#!/bin/bash

jeus_join_lines() {
    local IFS=$'\n'
    printf '%s' "$*"
}

jeus_set_result() {
    diagnosis_result="$1"
    status="$2"
    inspection_summary="$3"
    command_result="$4"
    command_executed="$5"
}

jeus_status_for_result() {
    case "$1" in
        GOOD) printf '%s' "양호" ;;
        VULNERABLE) printf '%s' "취약" ;;
        N/A) printf '%s' "N/A" ;;
        *) printf '%s' "수동진단" ;;
    esac
}

jeus_add_unique() {
    local value="$1"
    local existing
    [ -n "${value}" ] || return 0
    for existing in "${JEUS_UNIQUE_TMP[@]:-}"; do
        [ "${existing}" = "${value}" ] && return 0
    done
    JEUS_UNIQUE_TMP+=("${value}")
}

jeus_find_home() {
    if [ -n "${JEUS_HOME:-}" ] && [ -d "${JEUS_HOME}" ]; then
        printf '%s\n' "${JEUS_HOME}"
        return 0
    fi
    for candidate in /home/*/jeus /home/*/JEUS /opt/jeus /opt/JEUS /usr/local/jeus /usr/local/JEUS /TmaxSoft/JEUS /TmaxSoft/jeus /jeus /JEUS; do
        [ -d "${candidate}" ] && printf '%s\n' "${candidate}" && return 0
    done
    return 1
}

jeus_process_evidence() {
    ps -eo user=,pid=,comm=,args= 2>/dev/null |
        awk 'BEGIN { IGNORECASE = 1 } {
            comm = $3
            if (comm ~ /^(java|jeus|jeusadmin|webadmin)$/ && $0 ~ /(jeus|webadmin|-Djeus\.home|startDomainAdminServer|startManagedServer)/) {
                print $0
            }
        }' || true
}

jeus_is_installed() {
    [ -n "${JEUS_HOME_FOUND:-}" ] && return 0
    [ -n "${JEUS_PROCESS_EVIDENCE:-}" ] && return 0
    return 1
}

jeus_collect_state() {
    JEUS_HOME_FOUND="$(jeus_find_home || true)"
    JEUS_CONFIGS=()
    JEUS_LOG_DIRS=()
    JEUS_PROCESS_EVIDENCE="$(jeus_process_evidence)"
    JEUS_ADMIN="$(command -v jeusadmin 2>/dev/null || true)"

    if [ -z "${JEUS_ADMIN}" ] && [ -n "${JEUS_HOME_FOUND}" ] && [ -x "${JEUS_HOME_FOUND}/bin/jeusadmin" ]; then
        JEUS_ADMIN="${JEUS_HOME_FOUND}/bin/jeusadmin"
    fi

    if [ -n "${JEUS_HOME_FOUND}" ]; then
        JEUS_UNIQUE_TMP=()
        for dir in "${JEUS_HOME_FOUND}/domains" "${JEUS_HOME_FOUND}/config" "${JEUS_HOME_FOUND}/conf" "${JEUS_HOME_FOUND}/webhome"; do
            [ -d "${dir}" ] || continue
            while IFS= read -r file; do
                jeus_add_unique "${file}"
            done < <(find "${dir}" -type f \( -name 'domain.xml' -o -name 'web.xml' -o -name 'webcommon.xml' -o -name 'jeus-web-dd.xml' -o -name 'accounts.xml' -o -name 'policies.xml' \) 2>/dev/null | head -500)
        done
        if [ "${#JEUS_UNIQUE_TMP[@]}" -gt 0 ]; then
            JEUS_CONFIGS=("${JEUS_UNIQUE_TMP[@]}")
        fi

        JEUS_UNIQUE_TMP=()
        for dir in "${JEUS_HOME_FOUND}/logs" "${JEUS_HOME_FOUND}/domains"; do
            [ -d "${dir}" ] || continue
            jeus_add_unique "${dir}"
            while IFS= read -r log_dir; do
                jeus_add_unique "${log_dir}"
            done < <(find "${dir}" -type d -name 'logs' 2>/dev/null | head -100)
        done
        if [ "${#JEUS_UNIQUE_TMP[@]}" -gt 0 ]; then
            JEUS_LOG_DIRS=("${JEUS_UNIQUE_TMP[@]}")
        fi
        unset JEUS_UNIQUE_TMP
    fi
}

jeus_evidence() {
    {
        [ -n "${JEUS_HOME_FOUND:-}" ] && printf 'JEUS_HOME: %s\n' "${JEUS_HOME_FOUND}"
        [ "${#JEUS_CONFIGS[@]}" -gt 0 ] && printf 'ConfigFiles: %s\n' "${JEUS_CONFIGS[*]}"
        [ "${#JEUS_LOG_DIRS[@]}" -gt 0 ] && printf 'LogDirs: %s\n' "${JEUS_LOG_DIRS[*]}"
        [ -n "${JEUS_ADMIN:-}" ] && printf 'JeusAdminPath: %s\n' "${JEUS_ADMIN}"
        [ -n "${JEUS_PROCESS_EVIDENCE:-}" ] && printf 'Processes:\n%s\n' "${JEUS_PROCESS_EVIDENCE}"
    } | sed '/^$/d'
}

jeus_config_grep() {
    local pattern="$1"
    local found=1
    local file
    for file in "${JEUS_CONFIGS[@]}"; do
        if grep -Ein "${pattern}" "${file}" 2>/dev/null; then
            found=0
        fi
    done
    return "${found}"
}

jeus_acl_check() {
    local role="$1"
    shift
    local targets=("$@")
    local bad=""
    local checked=""
    local mode
    local target
    for target in "${targets[@]}"; do
        [ -e "${target}" ] || continue
        checked+="${target}"$'\n'
        if command -v stat >/dev/null 2>&1; then
            mode="$(stat -c '%a %U:%G %n' "${target}" 2>/dev/null || true)"
            case "${mode%% *}" in
                *2|*3|*6|*7) bad+="${mode}"$'\n' ;;
            esac
        fi
    done
    if [ -n "${bad}" ]; then
        jeus_set_result "VULNERABLE" "$(jeus_status_for_result VULNERABLE)" "Broad write permission evidence was found on JEUS ${role} paths." "${bad}" "stat JEUS ${role} paths"
    elif [ -n "${checked}" ]; then
        jeus_set_result "GOOD" "$(jeus_status_for_result GOOD)" "No broad write permission evidence was found on assessed JEUS ${role} paths." "${checked}" "stat JEUS ${role} paths"
    else
        jeus_set_result "MANUAL" "$(jeus_status_for_result MANUAL)" "JEUS ${role} paths were not found for permission assessment." "$(jeus_evidence)" "stat JEUS ${role} paths"
    fi
}

invoke_jeus_linux_check() {
    local item_id="$1"
    jeus_collect_state
    if ! jeus_is_installed; then
        jeus_set_result "N/A" "N/A" "JEUS service/process/home evidence was not found." "No JEUS process or JEUS_HOME evidence found." "ps -eo user,pid,args; inspect JEUS_HOME"
        return 0
    fi

    local lines
    local sample_paths
    case "${item_id}" in
        WEB-01)
            lines="$(jeus_config_grep '<user|<account|administrator|Administrators' || true)"
            if printf '%s' "${lines}" | grep -Eiq 'administrator'; then
                jeus_set_result "VULNERABLE" "$(jeus_status_for_result VULNERABLE)" "Default JEUS administrator account name evidence was found." "${lines}" "Inspect JEUS accounts.xml/security domain users"
            elif [ -n "${lines}" ]; then
                jeus_set_result "MANUAL" "$(jeus_status_for_result MANUAL)" "JEUS account evidence was found; confirm administrator account naming policy." "${lines}" "Inspect JEUS accounts.xml/security domain users"
            else
                jeus_set_result "MANUAL" "$(jeus_status_for_result MANUAL)" "JEUS account configuration was not found; confirm administrator account name manually." "$(jeus_evidence)" "Inspect JEUS accounts.xml/security domain users"
            fi
            ;;
        WEB-02)
            jeus_set_result "MANUAL" "$(jeus_status_for_result MANUAL)" "JEUS administrator password complexity depends on security-domain policy and password store state. Confirm policy and password age manually." "$(jeus_evidence)" "Inspect JEUS password policy/accounts.xml"
            ;;
        WEB-03)
            jeus_acl_check "security account/policy" "${JEUS_CONFIGS[@]}"
            ;;
        WEB-04)
            lines="$(jeus_config_grep '<allow-indexing>[[:space:]]*true|<allow-indexing>[[:space:]]*false|listings' || true)"
            if printf '%s' "${lines}" | grep -Eiq '<allow-indexing>[[:space:]]*true|listings[[:space:]]*=[[:space:]]*true'; then
                jeus_set_result "VULNERABLE" "$(jeus_status_for_result VULNERABLE)" "JEUS directory listing appears enabled." "${lines}" "Inspect jeus-web-dd.xml/web.xml directory listing settings"
            elif printf '%s' "${lines}" | grep -Eiq '<allow-indexing>[[:space:]]*false|listings[[:space:]]*=[[:space:]]*false'; then
                jeus_set_result "GOOD" "$(jeus_status_for_result GOOD)" "JEUS directory listing disable evidence was found." "${lines}" "Inspect jeus-web-dd.xml/web.xml directory listing settings"
            else
                jeus_set_result "MANUAL" "$(jeus_status_for_result MANUAL)" "JEUS directory listing evidence was not conclusive." "$(jeus_evidence)" "Inspect jeus-web-dd.xml/web.xml directory listing settings"
            fi
            ;;
        WEB-05)
            jeus_set_result "N/A" "N/A" "CGI/ISAPI execution restriction item is not targeted to JEUS in the guideline metadata." "WEB-05 target excludes JEUS." "Map web service CGI/ISAPI guideline applicability"
            ;;
        WEB-06)
            jeus_set_result "N/A" "N/A" "Upper-directory access restriction item is not targeted to JEUS in the guideline metadata." "WEB-06 target excludes JEUS." "Map web service upper-directory guideline applicability"
            ;;
        WEB-07)
            sample_paths=""
            if [ -n "${JEUS_HOME_FOUND}" ]; then
                sample_paths="$(find "${JEUS_HOME_FOUND}" -maxdepth 6 -type d \( -iname '*sample*' -o -iname '*example*' -o -path '*/docs/manuals*' -o -iname 'web-manager' \) 2>/dev/null | head -50 || true)"
            fi
            [ -n "${sample_paths}" ] && jeus_set_result "VULNERABLE" "$(jeus_status_for_result VULNERABLE)" "JEUS sample/manual/default management directories were found." "${sample_paths}" "Search JEUS samples/docs/manuals" || jeus_set_result "GOOD" "$(jeus_status_for_result GOOD)" "No JEUS sample/manual/default management directories were found in inspected homes." "$(jeus_evidence)" "Search JEUS samples/docs/manuals"
            ;;
        WEB-08)
            lines="$(jeus_config_grep 'max-file-size|max-request-size|maxPostSize|multipart-config' || true)"
            [ -n "${lines}" ] && jeus_set_result "GOOD" "$(jeus_status_for_result GOOD)" "JEUS upload/request size limit evidence was found." "${lines}" "Inspect web.xml multipart upload limits" || jeus_set_result "VULNERABLE" "$(jeus_status_for_result VULNERABLE)" "JEUS upload/request size limit evidence was not found." "$(jeus_evidence)" "Inspect web.xml multipart upload limits"
            ;;
        WEB-09)
            lines="${JEUS_PROCESS_EVIDENCE}"
            if printf '%s' "${lines}" | grep -Eiq '^[[:space:]]*root[[:space:]]'; then
                jeus_set_result "VULNERABLE" "$(jeus_status_for_result VULNERABLE)" "JEUS processes appear to run as root." "${lines}" "Inspect JEUS process owner"
            elif [ -n "${lines}" ]; then
                jeus_set_result "GOOD" "$(jeus_status_for_result GOOD)" "JEUS processes are not obviously running as root." "${lines}" "Inspect JEUS process owner"
            else
                jeus_set_result "MANUAL" "$(jeus_status_for_result MANUAL)" "JEUS process owner could not be determined." "$(jeus_evidence)" "Inspect JEUS process owner"
            fi
            ;;
        WEB-10)
            lines="$(jeus_config_grep 'ReverseProxy|proxy|PathPrefix|ServerAddress' || true)"
            [ -n "${lines}" ] && jeus_set_result "MANUAL" "$(jeus_status_for_result MANUAL)" "JEUS proxy/reverse-proxy evidence was found; confirm only required proxy mappings remain." "${lines}" "Inspect JEUS proxy mappings" || jeus_set_result "GOOD" "$(jeus_status_for_result GOOD)" "No JEUS proxy/reverse-proxy evidence was found in inspected configs." "$(jeus_evidence)" "Inspect JEUS proxy mappings"
            ;;
        WEB-11)
            lines="$(jeus_config_grep 'docBase|appBase|webhome|context-root' || true)"
            [ -n "${lines}" ] && jeus_set_result "MANUAL" "$(jeus_status_for_result MANUAL)" "JEUS web root/path evidence was found; confirm service path is separated from install/system directories." "${lines}" "Inspect JEUS web path settings" || jeus_set_result "MANUAL" "$(jeus_status_for_result MANUAL)" "JEUS web service path evidence was not conclusive." "$(jeus_evidence)" "Inspect JEUS web path settings"
            ;;
        WEB-12)
            lines="$(jeus_config_grep '<aliasing>|<alias>|<alias-name>|<real-path>' || true)"
            [ -n "${lines}" ] && jeus_set_result "VULNERABLE" "$(jeus_status_for_result VULNERABLE)" "JEUS alias/link mapping evidence was found." "${lines}" "Inspect JEUS aliasing settings" || jeus_set_result "GOOD" "$(jeus_status_for_result GOOD)" "No JEUS alias/link mapping evidence was found in inspected configs." "$(jeus_evidence)" "Inspect JEUS aliasing settings"
            ;;
        WEB-13)
            lines="$(jeus_config_grep 'DataSource|db|jdbc|password' || true)"
            [ -n "${lines}" ] && jeus_set_result "MANUAL" "$(jeus_status_for_result MANUAL)" "JEUS DB/resource configuration evidence was found; confirm unnecessary DB connection resources and exposed secrets are removed." "${lines}" "Inspect JEUS domain.xml/resource configs" || jeus_set_result "GOOD" "$(jeus_status_for_result GOOD)" "No JEUS DB/resource configuration evidence was found in inspected configs." "$(jeus_evidence)" "Inspect JEUS domain.xml/resource configs"
            ;;
        WEB-14)
            jeus_acl_check "config/root" "${JEUS_CONFIGS[@]}" "${JEUS_HOME_FOUND}"
            ;;
        WEB-15)
            lines="$(jeus_config_grep '<servlet-mapping>|<url-pattern>|cgi|admin|manager|invoker' || true)"
            if printf '%s' "${lines}" | grep -Eiq 'cgi|invoker|manager|admin'; then
                jeus_set_result "MANUAL" "$(jeus_status_for_result MANUAL)" "JEUS servlet mapping evidence was found; confirm unnecessary mappings are removed." "${lines}" "Inspect JEUS servlet mappings"
            else
                jeus_set_result "GOOD" "$(jeus_status_for_result GOOD)" "No obvious unnecessary JEUS servlet mapping evidence was found." "$(jeus_evidence)" "Inspect JEUS servlet mappings"
            fi
            ;;
        WEB-16)
            lines="$(jeus_config_grep 'serverInfo=false|server-header|ServerTokens' || true)"
            printf '%s' "${lines}" | grep -Eiq 'serverInfo=false' && jeus_set_result "GOOD" "$(jeus_status_for_result GOOD)" "JEUS server header suppression evidence was found." "${lines}" "Inspect JEUS serverInfo/header settings" || jeus_set_result "MANUAL" "$(jeus_status_for_result MANUAL)" "JEUS server header suppression evidence was not conclusive." "$(jeus_join_lines "${lines}" "$(jeus_evidence)")" "Inspect JEUS serverInfo/header settings"
            ;;
        WEB-17)
            jeus_set_result "N/A" "N/A" "Virtual directory cleanup item is not targeted to JEUS in the guideline metadata." "WEB-17 target excludes JEUS." "Map web service virtual-directory guideline applicability"
            ;;
        WEB-18)
            jeus_set_result "N/A" "N/A" "WebDAV disablement item is not targeted to JEUS in the guideline metadata." "WEB-18 target excludes JEUS." "Map WebDAV guideline applicability"
            ;;
        WEB-19)
            jeus_set_result "N/A" "N/A" "SSI restriction item is not targeted to JEUS in the guideline metadata." "WEB-19 target excludes JEUS." "Map SSI guideline applicability"
            ;;
        WEB-20)
            jeus_set_result "N/A" "N/A" "SSL/TLS activation item is not targeted to JEUS in the guideline metadata." "WEB-20 target excludes JEUS." "Map SSL/TLS guideline applicability"
            ;;
        WEB-21)
            jeus_set_result "N/A" "N/A" "HTTP-to-HTTPS redirection item is not targeted to JEUS in the guideline metadata." "WEB-21 target excludes JEUS." "Map HTTP redirection guideline applicability"
            ;;
        WEB-22)
            lines="$(jeus_config_grep '<error-page>|<error-code>|<location>' || true)"
            printf '%s' "${lines}" | grep -Eiq '<error-page>' && jeus_set_result "GOOD" "$(jeus_status_for_result GOOD)" "JEUS custom error-page evidence was found." "${lines}" "Inspect JEUS error-page settings" || jeus_set_result "VULNERABLE" "$(jeus_status_for_result VULNERABLE)" "JEUS custom error-page evidence was not found." "$(jeus_evidence)" "Inspect JEUS error-page settings"
            ;;
        WEB-23)
            lines="$(jeus_config_grep 'LDAP|digest|SHA-256|SHA256|SSHA|MD5|SHA-1' || true)"
            if printf '%s' "${lines}" | grep -Eiq 'SHA-256|SHA256|SSHA512|SSHA-512'; then
                jeus_set_result "GOOD" "$(jeus_status_for_result GOOD)" "JEUS LDAP strong digest evidence was found." "${lines}" "Inspect JEUS LDAP digest settings"
            elif printf '%s' "${lines}" | grep -Eiq 'LDAP|MD5|SHA-1'; then
                jeus_set_result "MANUAL" "$(jeus_status_for_result MANUAL)" "JEUS LDAP evidence was found; confirm digest algorithm is SHA-256 or stronger." "${lines}" "Inspect JEUS LDAP digest settings"
            else
                jeus_set_result "MANUAL" "$(jeus_status_for_result MANUAL)" "JEUS LDAP configuration evidence was not found; confirm LDAP is unused or securely configured." "$(jeus_evidence)" "Inspect JEUS LDAP digest settings"
            fi
            ;;
        WEB-24)
            lines="$(jeus_config_grep 'uploadDir|multipart-config|file-upload|tempdir' || true)"
            [ -n "${lines}" ] && jeus_set_result "MANUAL" "$(jeus_status_for_result MANUAL)" "JEUS upload path evidence was found; confirm upload path is separated and ACL-restricted." "${lines}" "Inspect JEUS upload path settings" || jeus_set_result "MANUAL" "$(jeus_status_for_result MANUAL)" "JEUS upload path evidence was not conclusive." "$(jeus_evidence)" "Inspect JEUS upload path settings"
            ;;
        WEB-25)
            if [ -n "${JEUS_ADMIN}" ]; then
                lines="$("${JEUS_ADMIN}" -version 2>&1 || true)"
                jeus_set_result "MANUAL" "$(jeus_status_for_result MANUAL)" "JEUS was found. Compare detected version against current TmaxSoft security/patch guidance." "${lines}" "${JEUS_ADMIN} -version"
            else
                jeus_set_result "MANUAL" "$(jeus_status_for_result MANUAL)" "JEUS was found, but jeusadmin was not found. Confirm version and patch level manually." "$(jeus_evidence)" "jeusadmin -version discovery"
            fi
            ;;
        WEB-26)
            jeus_acl_check "log" "${JEUS_LOG_DIRS[@]}"
            ;;
        *)
            jeus_set_result "MANUAL" "$(jeus_status_for_result MANUAL)" "No JEUS Linux diagnostic rule is defined for ${item_id}." "$(jeus_evidence)" "JEUS Linux generic discovery"
            ;;
    esac
}
