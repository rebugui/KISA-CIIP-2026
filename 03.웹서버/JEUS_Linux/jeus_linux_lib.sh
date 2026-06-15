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
    local octal
    local group_digit
    local other_digit
    local target
    for target in "${targets[@]}"; do
        [ -e "${target}" ] || continue
        checked+="${target}"$'\n'
        if command -v stat >/dev/null 2>&1; then
            mode="$(stat -c '%a %U:%G %n' "${target}" 2>/dev/null || true)"
            octal="${mode%% *}"
            # Normalize to last 3 octal digits (drop setuid/setgid/sticky leading digit).
            # Index 0 = owner, 1 = group, 2 = other.
            octal="${octal: -3}"
            group_digit="${octal:1:1}"
            other_digit="${octal:2:1}"
            # criteria_bad: any general-user access (read/write/exec) on password,
            # config or log paths. "Other" digit non-zero => world-accessible (read=4,
            # exec=1, write=2 all flagged). Group-WRITE (2/3/6/7) is also broad access per
            # guideline remediation (chmod 600 / chmod -R 750 -> group r-x is acceptable,
            # group write is not). Group read/exec only (4,5) stays clean per 750/640.
            case "${other_digit}" in
                1|2|3|4|5|6|7) bad+="${mode}"$'\n' ;;
            esac
            if [ -z "${other_digit}" ] || [ "${other_digit}" = "0" ]; then
                case "${group_digit}" in
                    2|3|6|7) bad+="${mode}"$'\n' ;;
                esac
            fi
        fi
    done
    if [ -n "${bad}" ]; then
        jeus_set_result "VULNERABLE" "$(jeus_status_for_result VULNERABLE)" "Broad general-user access (read/write/exec) permission evidence was found on JEUS ${role} paths." "${bad}" "stat JEUS ${role} paths"
    elif [ -n "${checked}" ]; then
        jeus_set_result "GOOD" "$(jeus_status_for_result GOOD)" "No broad general-user access permission evidence was found on assessed JEUS ${role} paths." "${checked}" "stat JEUS ${role} paths"
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
            if [ -z "${JEUS_HOME_FOUND}" ]; then
                jeus_set_result "MANUAL" "$(jeus_status_for_result MANUAL)" "JEUS is installed (process evidence) but JEUS_HOME could not be resolved, so the unnecessary-file search space is empty. Confirm sample/manual/default files manually." "$(jeus_evidence)" "Search JEUS samples/docs/manuals"
            else
                sample_paths="$(find "${JEUS_HOME_FOUND}" -maxdepth 6 -type d \( -iname '*sample*' -o -iname '*example*' -o -path '*/docs/manuals*' -o -iname 'web-manager' \) 2>/dev/null | head -50 || true)"
                [ -n "${sample_paths}" ] && jeus_set_result "VULNERABLE" "$(jeus_status_for_result VULNERABLE)" "JEUS sample/manual/default management directories were found." "${sample_paths}" "Search JEUS samples/docs/manuals" || jeus_set_result "GOOD" "$(jeus_status_for_result GOOD)" "No JEUS sample/manual/default management directories were found in inspected homes." "$(jeus_evidence)" "Search JEUS samples/docs/manuals"
            fi
            ;;
        WEB-08)
            lines="$(jeus_config_grep 'max-file-size|max-request-size|maxPostSize|multipart-config' || true)"
            # Strip XML/inline comments so commented-out directives do not count, then
            # require a real positive numeric limit (a size directive followed by a
            # non-zero integer). A lone <multipart-config> tag or <...>0<...> is not a limit.
            local web08_effective
            web08_effective="$(printf '%s\n' "${lines}" | sed -e 's/<!--.*-->//g' | grep -Ev '<!--|-->' || true)"
            if printf '%s\n' "${web08_effective}" | grep -Eiq '(max-file-size|max-request-size|maxPostSize)[^0-9]*[1-9][0-9]*'; then
                jeus_set_result "GOOD" "$(jeus_status_for_result GOOD)" "JEUS upload/request size limit evidence (non-zero numeric value) was found." "${web08_effective}" "Inspect web.xml multipart upload limits"
            elif [ -n "${lines}" ]; then
                jeus_set_result "VULNERABLE" "$(jeus_status_for_result VULNERABLE)" "JEUS multipart/upload configuration was present but had no real non-zero size limit (commented out, empty, or zero value)." "${lines}" "Inspect web.xml multipart upload limits"
            else
                jeus_set_result "VULNERABLE" "$(jeus_status_for_result VULNERABLE)" "JEUS upload/request size limit evidence was not found." "$(jeus_evidence)" "Inspect web.xml multipart upload limits"
            fi
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
            if [ -n "${lines}" ]; then
                jeus_set_result "MANUAL" "$(jeus_status_for_result MANUAL)" "JEUS DB/resource configuration evidence was found; confirm unnecessary DB connection resources and exposed secrets are removed, and that the config file ACL is restricted (chmod 600)." "${lines}" "Inspect JEUS domain.xml/resource configs"
            else
                # Keyword miss does NOT imply GOOD: a DB datasource may use non-standard
                # naming and escape the grep. The criteria_bad also covers the config-file
                # ACL (chmod 600). Verify ACL of inspected config files; if any config is
                # readable beyond owner -> VULNERABLE, otherwise undecidable -> MANUAL.
                local web13_bad=""
                local web13_mode
                local web13_octal
                local web13_file
                for web13_file in "${JEUS_CONFIGS[@]}"; do
                    [ -e "${web13_file}" ] || continue
                    command -v stat >/dev/null 2>&1 || continue
                    web13_mode="$(stat -c '%a %U:%G %n' "${web13_file}" 2>/dev/null || true)"
                    web13_octal="${web13_mode%% *}"
                    web13_octal="${web13_octal: -3}"
                    # Index 1 = group, 2 = other. Flag any "other" access (1-7) or
                    # group-write (2/3/6/7); group read/exec only (4/5) stays clean.
                    case "${web13_octal:2:1}" in
                        1|2|3|4|5|6|7) web13_bad+="${web13_mode}"$'\n' ;;
                    esac
                    case "${web13_octal:1:1}" in
                        2|3|6|7) web13_bad+="${web13_mode}"$'\n' ;;
                    esac
                done
                if [ -n "${web13_bad}" ]; then
                    jeus_set_result "VULNERABLE" "$(jeus_status_for_result VULNERABLE)" "No DB keyword matched, but JEUS configuration files carry general-user access permissions; DB connection files must be restricted (chmod 600)." "${web13_bad}" "stat JEUS config files for DB-file ACL"
                else
                    jeus_set_result "MANUAL" "$(jeus_status_for_result MANUAL)" "No DB/resource keyword matched inspected configs; DB usage may rely on non-standard naming. Confirm no unnecessary DB connection file exists and that any DB config file ACL is restricted to owner (chmod 600)." "$(jeus_evidence)" "Inspect JEUS domain.xml/resource configs"
                fi
            fi
            ;;
        WEB-14)
            jeus_acl_check "config/root" "${JEUS_CONFIGS[@]}" "${JEUS_HOME_FOUND}"
            ;;
        WEB-15)
            lines="$(jeus_config_grep '<servlet-mapping>|<url-pattern>|cgi|admin|manager|invoker' || true)"
            if printf '%s' "${lines}" | grep -Eiq 'cgi|invoker|manager|admin'; then
                jeus_set_result "MANUAL" "$(jeus_status_for_result MANUAL)" "JEUS servlet mapping evidence (high-risk keyword) was found; confirm unnecessary mappings are removed." "${lines}" "Inspect JEUS servlet mappings"
            elif [ -n "${lines}" ]; then
                # Servlet mappings exist but match no high-risk keyword. Necessity of a
                # mapping (e.g. /welcome -> jsp) cannot be decided automatically per the
                # guideline, so report MANUAL and list the mappings rather than GOOD.
                jeus_set_result "MANUAL" "$(jeus_status_for_result MANUAL)" "JEUS servlet mappings were found; necessity cannot be determined automatically. Review the listed mappings and remove unnecessary ones." "${lines}" "Inspect JEUS servlet mappings"
            else
                jeus_set_result "GOOD" "$(jeus_status_for_result GOOD)" "No JEUS servlet mapping evidence was found in inspected configs." "$(jeus_evidence)" "Inspect JEUS servlet mappings"
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
            # Strip XML comments so commented-out <!-- <error-page> --> blocks do not count,
            # and require a real <location> with a non-empty value to treat as configured.
            local web22_effective
            web22_effective="$(printf '%s\n' "${lines}" | sed -e 's/<!--.*-->//g' | grep -Ev '<!--|-->' || true)"
            if printf '%s\n' "${web22_effective}" | grep -Eiq '<location>[[:space:]]*[^<[:space:]][^<]*</location>'; then
                jeus_set_result "GOOD" "$(jeus_status_for_result GOOD)" "JEUS custom error-page with a designated location value was found." "${web22_effective}" "Inspect JEUS error-page settings"
            elif printf '%s\n' "${web22_effective}" | grep -Eiq '<error-page>'; then
                jeus_set_result "MANUAL" "$(jeus_status_for_result MANUAL)" "JEUS error-page element was found but no functional <location> value was confirmed. Verify the error page is designated and functional." "${web22_effective}" "Inspect JEUS error-page settings"
            else
                jeus_set_result "VULNERABLE" "$(jeus_status_for_result VULNERABLE)" "JEUS custom error-page evidence was not found (only commented-out or empty definitions)." "$(jeus_evidence)" "Inspect JEUS error-page settings"
            fi
            ;;
        WEB-23)
            # WEB-23 target is Tomcat only (oracle metadata). JEUS is out of scope, so the
            # previous SHA-256-substring heuristic produced spurious GOOD results from
            # accounts.xml password digests. Emit N/A for the JEUS branch.
            jeus_set_result "N/A" "N/A" "LDAP digest algorithm item targets Tomcat only in the guideline metadata; JEUS is out of scope." "WEB-23 target excludes JEUS." "Map LDAP digest guideline applicability"
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
