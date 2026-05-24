#!/bin/bash

webtob_join_lines() {
    local IFS=$'\n'
    printf '%s' "$*"
}

webtob_set_result() {
    diagnosis_result="$1"
    status="$2"
    inspection_summary="$3"
    command_result="$4"
    command_executed="$5"
}

webtob_status_for_result() {
    case "$1" in
        GOOD) printf '%s' "양호" ;;
        VULNERABLE) printf '%s' "취약" ;;
        N/A) printf '%s' "N/A" ;;
        *) printf '%s' "수동진단" ;;
    esac
}

webtob_find_home() {
    if [ -n "${WEBTOB:-}" ] && [ -d "${WEBTOB}" ]; then
        printf '%s\n' "${WEBTOB}"
        return 0
    fi
    for candidate in /home/*/webtob /opt/webtob /usr/local/webtob /webtob /TmaxSoft/WebtoB; do
        [ -d "${candidate}" ] && printf '%s\n' "${candidate}" && return 0
    done
    return 1
}

webtob_process_evidence() {
    ps -eo user=,pid=,args= 2>/dev/null | grep -Ei 'hth|wsm|wsboot|webtob' | grep -v grep || true
}

webtob_is_installed() {
    [ -n "${WEBTOB_HOME:-}" ] && return 0
    [ -n "$(webtob_process_evidence)" ] && return 0
    return 1
}

webtob_collect_state() {
    WEBTOB_HOME="$(webtob_find_home || true)"
    WEBTOB_CONFIGS=()
    WEBTOB_LOG_DIRS=()
    if [ -n "${WEBTOB_HOME}" ]; then
        for file in "${WEBTOB_HOME}/config/http.m" "${WEBTOB_HOME}/conf/http.m" "${WEBTOB_HOME}/config/rewrite_ssl.conf"; do
            [ -f "${file}" ] && WEBTOB_CONFIGS+=("${file}")
        done
        for dir in "${WEBTOB_HOME}/log" "${WEBTOB_HOME}/logs"; do
            [ -d "${dir}" ] && WEBTOB_LOG_DIRS+=("${dir}")
        done
    fi
    WEBTOB_PROCESS_EVIDENCE="$(webtob_process_evidence)"
    WEBTOB_WSCFL="$(command -v wscfl 2>/dev/null || true)"
    if [ -z "${WEBTOB_WSCFL}" ] && [ -n "${WEBTOB_HOME}" ] && [ -x "${WEBTOB_HOME}/bin/wscfl" ]; then
        WEBTOB_WSCFL="${WEBTOB_HOME}/bin/wscfl"
    fi
}

webtob_evidence() {
    {
        [ -n "${WEBTOB_HOME:-}" ] && printf 'WEBTOB_HOME: %s\n' "${WEBTOB_HOME}"
        [ "${#WEBTOB_CONFIGS[@]}" -gt 0 ] && printf 'ConfigFiles: %s\n' "${WEBTOB_CONFIGS[*]}"
        [ "${#WEBTOB_LOG_DIRS[@]}" -gt 0 ] && printf 'LogDirs: %s\n' "${WEBTOB_LOG_DIRS[*]}"
        [ -n "${WEBTOB_WSCFL:-}" ] && printf 'WscflPath: %s\n' "${WEBTOB_WSCFL}"
        [ -n "${WEBTOB_PROCESS_EVIDENCE:-}" ] && printf 'Processes:\n%s\n' "${WEBTOB_PROCESS_EVIDENCE}"
    } | sed '/^$/d'
}

webtob_config_grep() {
    local pattern="$1"
    local found=1
    for file in "${WEBTOB_CONFIGS[@]}"; do
        if grep -Ein "${pattern}" "${file}" 2>/dev/null; then
            found=0
        fi
    done
    return "${found}"
}

webtob_acl_check() {
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
        webtob_set_result "VULNERABLE" "$(webtob_status_for_result VULNERABLE)" "Broad write permission evidence was found on WebtoB ${role} paths." "${bad}" "stat WebtoB ${role} paths"
    elif [ -n "${checked}" ]; then
        webtob_set_result "GOOD" "$(webtob_status_for_result GOOD)" "No broad write permission evidence was found on assessed WebtoB ${role} paths." "${checked}" "stat WebtoB ${role} paths"
    else
        webtob_set_result "MANUAL" "$(webtob_status_for_result MANUAL)" "WebtoB ${role} paths were not found for permission assessment." "$(webtob_evidence)" "stat WebtoB ${role} paths"
    fi
}

invoke_webtob_linux_check() {
    local item_id="$1"
    webtob_collect_state
    if ! webtob_is_installed; then
        webtob_set_result "N/A" "N/A" "WebtoB service/process/home evidence was not found." "No WebtoB process or WEBTOB home evidence found." "pgrep -af 'hth|wsm|wsboot|webtob'; inspect WEBTOB"
        return 0
    fi

    local lines
    case "${item_id}" in
        WEB-01|WEB-02|WEB-03)
            webtob_set_result "N/A" "N/A" "This administrator account/password item is not targeted to WebtoB in the guideline metadata." "${item_id} target excludes WebtoB." "Map WebtoB account guideline applicability"
            ;;
        WEB-04)
            lines="$(webtob_config_grep 'Options[[:space:]]*=.*Indexes|-Indexes' || true)"
            if printf '%s' "${lines}" | grep -Eiq 'Options[[:space:]]*=.*(^|[^-])Indexes'; then
                webtob_set_result "VULNERABLE" "$(webtob_status_for_result VULNERABLE)" "WebtoB directory indexing appears enabled." "${lines}" "grep Options/Indexes http.m"
            elif printf '%s' "${lines}" | grep -Eiq -- '-Indexes'; then
                webtob_set_result "GOOD" "$(webtob_status_for_result GOOD)" "WebtoB directory indexing disable evidence was found." "${lines}" "grep Options/Indexes http.m"
            else
                webtob_set_result "MANUAL" "$(webtob_status_for_result MANUAL)" "WebtoB directory indexing evidence was not conclusive." "$(webtob_evidence)" "grep Options/Indexes http.m"
            fi
            ;;
        WEB-05)
            lines="$(webtob_config_grep 'SVRTYPE[[:space:]]*=[[:space:]]*CGI|SvrType[[:space:]]*=[[:space:]]*CGI|/cgi-bin|CGI' || true)"
            [ -n "${lines}" ] && webtob_set_result "VULNERABLE" "$(webtob_status_for_result VULNERABLE)" "WebtoB CGI execution mapping evidence was found." "${lines}" "grep CGI http.m" || webtob_set_result "GOOD" "$(webtob_status_for_result GOOD)" "No WebtoB CGI execution mapping evidence was found." "$(webtob_evidence)" "grep CGI http.m"
            ;;
        WEB-06)
            lines="$(webtob_config_grep 'UpperDirRestrict[[:space:]]*=[[:space:]]*[NY]' || true)"
            if printf '%s' "${lines}" | grep -Eiq 'UpperDirRestrict[[:space:]]*=[[:space:]]*N'; then
                webtob_set_result "VULNERABLE" "$(webtob_status_for_result VULNERABLE)" "WebtoB upper-directory restriction appears disabled." "${lines}" "grep UpperDirRestrict http.m"
            elif printf '%s' "${lines}" | grep -Eiq 'UpperDirRestrict[[:space:]]*=[[:space:]]*Y'; then
                webtob_set_result "GOOD" "$(webtob_status_for_result GOOD)" "WebtoB upper-directory restriction evidence was found." "${lines}" "grep UpperDirRestrict http.m"
            else
                webtob_set_result "MANUAL" "$(webtob_status_for_result MANUAL)" "WebtoB upper-directory restriction evidence was not conclusive." "$(webtob_evidence)" "grep UpperDirRestrict http.m"
            fi
            ;;
        WEB-07)
            lines=""
            [ -n "${WEBTOB_HOME}" ] && lines="$(find "${WEBTOB_HOME}" -maxdepth 4 -type d \( -iname '*sample*' -o -iname '*example*' -o -path '*/docs/manuals*' \) 2>/dev/null | head -50 || true)"
            [ -n "${lines}" ] && webtob_set_result "VULNERABLE" "$(webtob_status_for_result VULNERABLE)" "WebtoB sample/manual directories were found." "${lines}" "find WebtoB samples/docs/manuals" || webtob_set_result "GOOD" "$(webtob_status_for_result GOOD)" "No WebtoB sample/manual directories were found in inspected homes." "$(webtob_evidence)" "find WebtoB samples/docs/manuals"
            ;;
        WEB-08)
            lines="$(webtob_config_grep 'LimitRequestBody' || true)"
            [ -n "${lines}" ] && webtob_set_result "GOOD" "$(webtob_status_for_result GOOD)" "WebtoB upload/download size limit evidence was found." "${lines}" "grep LimitRequestBody http.m" || webtob_set_result "VULNERABLE" "$(webtob_status_for_result VULNERABLE)" "WebtoB upload/download size limit evidence was not found." "$(webtob_evidence)" "grep LimitRequestBody http.m"
            ;;
        WEB-09)
            lines="${WEBTOB_PROCESS_EVIDENCE}"
            if printf '%s' "${lines}" | grep -Eiq '^[[:space:]]*root[[:space:]]'; then
                webtob_set_result "VULNERABLE" "$(webtob_status_for_result VULNERABLE)" "WebtoB processes appear to run as root." "${lines}" "pgrep/ps WebtoB processes"
            elif [ -n "${lines}" ]; then
                webtob_set_result "GOOD" "$(webtob_status_for_result GOOD)" "WebtoB processes are not obviously running as root." "${lines}" "pgrep/ps WebtoB processes"
            else
                webtob_set_result "MANUAL" "$(webtob_status_for_result MANUAL)" "WebtoB process owner could not be determined." "$(webtob_evidence)" "pgrep/ps WebtoB processes"
            fi
            ;;
        WEB-10)
            lines="$(webtob_config_grep 'REVERSE_PROXY|PathPrefix|ServerAddress|Proxy' || true)"
            [ -n "${lines}" ] && webtob_set_result "MANUAL" "$(webtob_status_for_result MANUAL)" "WebtoB reverse proxy evidence was found; confirm only required proxy mappings remain." "${lines}" "grep proxy http.m" || webtob_set_result "GOOD" "$(webtob_status_for_result GOOD)" "No WebtoB reverse proxy evidence was found." "$(webtob_evidence)" "grep proxy http.m"
            ;;
        WEB-11)
            lines="$(webtob_config_grep 'DOCROOT|WEBTOBDIR' || true)"
            [ -n "${lines}" ] && webtob_set_result "MANUAL" "$(webtob_status_for_result MANUAL)" "WebtoB service path evidence was found; confirm DOCROOT is separated from install/system directories." "${lines}" "grep DOCROOT/WEBTOBDIR http.m" || webtob_set_result "MANUAL" "$(webtob_status_for_result MANUAL)" "WebtoB service path evidence was not conclusive." "$(webtob_evidence)" "grep DOCROOT/WEBTOBDIR http.m"
            ;;
        WEB-12|WEB-17)
            lines="$(webtob_config_grep '^[[:space:]]*\\*ALIAS|RealPath|ALIAS' || true)"
            [ -n "${lines}" ] && webtob_set_result "VULNERABLE" "$(webtob_status_for_result VULNERABLE)" "WebtoB alias/link mapping evidence was found." "${lines}" "grep ALIAS http.m" || webtob_set_result "GOOD" "$(webtob_status_for_result GOOD)" "No WebtoB alias/link mapping evidence was found." "$(webtob_evidence)" "grep ALIAS http.m"
            ;;
        WEB-13|WEB-15)
            webtob_set_result "N/A" "N/A" "This item is not targeted to WebtoB in the guideline metadata." "${item_id} target excludes WebtoB." "Map WebtoB guideline applicability"
            ;;
        WEB-14)
            webtob_acl_check "config/root" "${WEBTOB_CONFIGS[@]}" "${WEBTOB_HOME}"
            ;;
        WEB-16)
            lines="$(webtob_config_grep 'ServerTokens|ServerSignature' || true)"
            if printf '%s' "${lines}" | grep -Eiq 'ServerTokens[[:space:]]+(Prod|ProductOnly)|ServerSignature[[:space:]]+off'; then
                webtob_set_result "GOOD" "$(webtob_status_for_result GOOD)" "WebtoB server header minimization evidence was found." "${lines}" "grep ServerTokens/ServerSignature http.m"
            else
                webtob_set_result "MANUAL" "$(webtob_status_for_result MANUAL)" "WebtoB server header minimization evidence was not conclusive." "$(webtob_join_lines "${lines}" "$(webtob_evidence)")" "grep ServerTokens/ServerSignature http.m"
            fi
            ;;
        WEB-18)
            lines="$(webtob_config_grep 'Method[[:space:]]*=.*(PROPFIND|PUT|DELETE|MKCOL|COPY|MOVE)|WebDAV|dav' || true)"
            [ -n "${lines}" ] && webtob_set_result "VULNERABLE" "$(webtob_status_for_result VULNERABLE)" "WebtoB WebDAV-like methods/settings evidence was found." "${lines}" "grep WebDAV methods http.m" || webtob_set_result "GOOD" "$(webtob_status_for_result GOOD)" "No WebtoB WebDAV-like method evidence was found." "$(webtob_evidence)" "grep WebDAV methods http.m"
            ;;
        WEB-19)
            lines="$(webtob_config_grep 'SVRTYPE[[:space:]]*=[[:space:]]*SSI|SvrType[[:space:]]*=[[:space:]]*SSI|SSI' || true)"
            [ -n "${lines}" ] && webtob_set_result "VULNERABLE" "$(webtob_status_for_result VULNERABLE)" "WebtoB SSI server mapping evidence was found." "${lines}" "grep SSI http.m" || webtob_set_result "GOOD" "$(webtob_status_for_result GOOD)" "No WebtoB SSI mapping evidence was found." "$(webtob_evidence)" "grep SSI http.m"
            ;;
        WEB-20)
            lines="$(webtob_config_grep 'SSLFLAG[[:space:]]*=[[:space:]]*Y|SSLNAME|CertificateFile|Protocols' || true)"
            [ -n "${lines}" ] && webtob_set_result "GOOD" "$(webtob_status_for_result GOOD)" "WebtoB SSL/TLS configuration evidence was found." "${lines}" "grep SSL http.m" || webtob_set_result "VULNERABLE" "$(webtob_status_for_result VULNERABLE)" "WebtoB SSL/TLS configuration evidence was not found." "$(webtob_evidence)" "grep SSL http.m"
            ;;
        WEB-21)
            lines="$(webtob_config_grep 'URLRewrite[[:space:]]*=[[:space:]]*Y|URLRewriteConfig|https://|RewriteRule' || true)"
            [ -n "${lines}" ] && webtob_set_result "GOOD" "$(webtob_status_for_result GOOD)" "WebtoB HTTP-to-HTTPS redirection evidence was found." "${lines}" "grep rewrite http.m" || webtob_set_result "VULNERABLE" "$(webtob_status_for_result VULNERABLE)" "WebtoB HTTP-to-HTTPS redirection evidence was not found." "$(webtob_evidence)" "grep rewrite http.m"
            ;;
        WEB-22)
            lines="$(webtob_config_grep 'ERRORDOCUMENT|ErrorDocument|40[134]|50[034]' || true)"
            [ -n "${lines}" ] && webtob_set_result "GOOD" "$(webtob_status_for_result GOOD)" "WebtoB custom error document evidence was found." "${lines}" "grep ERRORDOCUMENT http.m" || webtob_set_result "VULNERABLE" "$(webtob_status_for_result VULNERABLE)" "WebtoB custom error document evidence was not found." "$(webtob_evidence)" "grep ERRORDOCUMENT http.m"
            ;;
        WEB-23|WEB-24)
            webtob_set_result "MANUAL" "$(webtob_status_for_result MANUAL)" "This WebtoB item requires application or site-specific policy review." "$(webtob_evidence)" "Review WebtoB application/site policy"
            ;;
        WEB-25)
            if [ -n "${WEBTOB_WSCFL}" ]; then
                lines="$("${WEBTOB_WSCFL}" -version 2>&1 || true)"
                webtob_set_result "MANUAL" "$(webtob_status_for_result MANUAL)" "WebtoB was found. Compare detected version against current TmaxSoft security/patch guidance." "${lines}" "${WEBTOB_WSCFL} -version"
            else
                webtob_set_result "MANUAL" "$(webtob_status_for_result MANUAL)" "WebtoB was found, but wscfl was not found. Confirm version and patch level manually." "$(webtob_evidence)" "wscfl -version discovery"
            fi
            ;;
        WEB-26)
            webtob_acl_check "log" "${WEBTOB_LOG_DIRS[@]}"
            ;;
        *)
            webtob_set_result "MANUAL" "$(webtob_status_for_result MANUAL)" "No WebtoB Linux diagnostic rule is defined for ${item_id}." "$(webtob_evidence)" "WebtoB Linux generic discovery"
            ;;
    esac
}
