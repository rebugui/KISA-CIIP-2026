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

# Comment-aware variant of webtob_config_grep.
# Drops lines whose first non-whitespace character is '#' (WebtoB http.m
# comment syntax) before matching, so commented-out directives do not produce
# false evidence. Emits "file:lineno:text" (lineno from the original file) for
# traceability. Returns 0 if at least one active line matched.
webtob_config_grep_active() {
    local pattern="$1"
    local found=1
    local file
    local match
    for file in "${WEBTOB_CONFIGS[@]}"; do
        [ -f "${file}" ] || continue
        # grep -vn keeps original line numbers; drop comment lines, then match.
        match="$(grep -vn '^[[:space:]]*#' "${file}" 2>/dev/null | grep -Ei -- "${pattern}" || true)"
        if [ -n "${match}" ]; then
            printf '%s\n' "${match}" | sed "s|^|${file}:|"
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
            # criteria_bad: ANY general-user (other) access incl. read.
            # The fix is chmod 750 / o-rwx, so the trailing (other) octal digit
            # must be 0. Any non-zero other digit (read=4, exec=1, write=2 and
            # their combinations 3/5/6/7) is a broad-access finding.
            local other_digit="${mode%% *}"
            other_digit="${other_digit: -1}"
            case "${other_digit}" in
                ''|0) : ;;
                *) bad+="${mode}"$'\n' ;;
            esac
        fi
    done
    if [ -n "${bad}" ]; then
        webtob_set_result "VULNERABLE" "$(webtob_status_for_result VULNERABLE)" "Broad general-user (other) access permission evidence was found on WebtoB ${role} paths." "${bad}" "stat WebtoB ${role} paths"
    elif [ -n "${checked}" ]; then
        webtob_set_result "GOOD" "$(webtob_status_for_result GOOD)" "No broad general-user (other) access permission evidence was found on assessed WebtoB ${role} paths." "${checked}" "stat WebtoB ${role} paths"
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
            if [ -n "${lines}" ]; then
                webtob_set_result "VULNERABLE" "$(webtob_status_for_result VULNERABLE)" "WebtoB CGI execution mapping evidence was found." "${lines}" "grep CGI http.m"
            elif [ -z "${WEBTOB_HOME}" ] || [ "${#WEBTOB_CONFIGS[@]}" -eq 0 ]; then
                # Installed (per webtob_is_installed) but no http.m config was
                # actually inspected (home not derivable or config files absent):
                # GOOD cannot be asserted from zero evidence -> MANUAL.
                webtob_set_result "MANUAL" "$(webtob_status_for_result MANUAL)" "WebtoB appears installed but its configuration (http.m) could not be inspected; manually verify CGI execution is unused or restricted to a designated directory." "$(webtob_evidence)" "grep CGI http.m"
            else
                webtob_set_result "GOOD" "$(webtob_status_for_result GOOD)" "No WebtoB CGI execution mapping evidence was found." "$(webtob_evidence)" "grep CGI http.m"
            fi
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
            if [ -z "${WEBTOB_HOME}" ]; then
                # Installed (per webtob_is_installed) but home not derivable:
                # no path can be inspected, so GOOD cannot be asserted -> MANUAL.
                webtob_set_result "MANUAL" "$(webtob_status_for_result MANUAL)" "WebtoB appears installed but its home directory could not be derived; manually inspect for sample/manual files." "$(webtob_evidence)" "find WebtoB samples/docs/manuals"
            else
                lines="$(find "${WEBTOB_HOME}" -maxdepth 4 -type d \( -iname '*sample*' -o -iname '*example*' -o -path '*/docs/manuals*' \) 2>/dev/null | head -50 || true)"
                [ -n "${lines}" ] && webtob_set_result "VULNERABLE" "$(webtob_status_for_result VULNERABLE)" "WebtoB sample/manual directories were found." "${lines}" "find WebtoB samples/docs/manuals" || webtob_set_result "GOOD" "$(webtob_status_for_result GOOD)" "No WebtoB sample/manual directories were found in inspected homes." "$(webtob_evidence)" "find WebtoB samples/docs/manuals"
            fi
            ;;
        WEB-08)
            # Oracle: a non-zero upload/download size limit must be configured.
            # Use the comment-aware grep so commented-out directives do not count,
            # and require LimitRequestBody to carry a positive (non-zero) value.
            # A value of 0 means "unlimited" -> not a real limit -> VULNERABLE.
            lines="$(webtob_config_grep_active 'LimitRequestBody' || true)"
            if printf '%s' "${lines}" | grep -Eiq 'LimitRequestBody[[:space:]]*=?[[:space:]]*0+([[:space:]]|$)'; then
                webtob_set_result "VULNERABLE" "$(webtob_status_for_result VULNERABLE)" "WebtoB LimitRequestBody is set to 0 (unlimited); upload/download size is not effectively limited." "${lines}" "grep LimitRequestBody http.m"
            elif printf '%s' "${lines}" | grep -Eiq 'LimitRequestBody[[:space:]]*=?[[:space:]]*[1-9][0-9]*'; then
                webtob_set_result "GOOD" "$(webtob_status_for_result GOOD)" "WebtoB upload/download size limit (non-zero LimitRequestBody) evidence was found." "${lines}" "grep LimitRequestBody http.m"
            elif [ -n "${lines}" ]; then
                # Directive present (active) but value not parseable as a number.
                webtob_set_result "MANUAL" "$(webtob_status_for_result MANUAL)" "WebtoB LimitRequestBody directive was found but its value could not be confirmed as a non-zero limit; verify the configured size." "$(webtob_join_lines "${lines}" "$(webtob_evidence)")" "grep LimitRequestBody http.m"
            else
                webtob_set_result "VULNERABLE" "$(webtob_status_for_result VULNERABLE)" "WebtoB upload/download size limit evidence was not found." "$(webtob_evidence)" "grep LimitRequestBody http.m"
            fi
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
            if [ -n "${lines}" ]; then
                webtob_set_result "VULNERABLE" "$(webtob_status_for_result VULNERABLE)" "WebtoB alias/link mapping evidence was found." "${lines}" "grep ALIAS http.m"
            elif [ -z "${WEBTOB_HOME}" ] || [ "${#WEBTOB_CONFIGS[@]}" -eq 0 ]; then
                # Installed (per webtob_is_installed) but no http.m config was
                # actually inspected (home not derivable or config files absent):
                # GOOD cannot be asserted from zero evidence -> MANUAL.
                webtob_set_result "MANUAL" "$(webtob_status_for_result MANUAL)" "WebtoB appears installed but its configuration (http.m) could not be inspected; manually verify symbolic-link/alias and virtual-directory usage." "$(webtob_evidence)" "grep ALIAS http.m"
            else
                webtob_set_result "GOOD" "$(webtob_status_for_result GOOD)" "No WebtoB alias/link mapping evidence was found." "$(webtob_evidence)" "grep ALIAS http.m"
            fi
            ;;
        WEB-13|WEB-15)
            webtob_set_result "N/A" "N/A" "This item is not targeted to WebtoB in the guideline metadata." "${item_id} target excludes WebtoB." "Map WebtoB guideline applicability"
            ;;
        WEB-14)
            webtob_acl_check "config/root" "${WEBTOB_CONFIGS[@]}" "${WEBTOB_HOME}"
            ;;
        WEB-16)
            lines="$(webtob_config_grep_active 'ServerTokens|ServerSignature' || true)"
            if printf '%s' "${lines}" | grep -Eiq 'ServerTokens[[:space:]]+(Prod|ProductOnly)|ServerSignature[[:space:]]+off'; then
                webtob_set_result "GOOD" "$(webtob_status_for_result GOOD)" "WebtoB server header minimization evidence was found." "${lines}" "grep ServerTokens/ServerSignature http.m"
            else
                webtob_set_result "MANUAL" "$(webtob_status_for_result MANUAL)" "WebtoB server header minimization evidence was not conclusive." "$(webtob_join_lines "${lines}" "$(webtob_evidence)")" "grep ServerTokens/ServerSignature http.m"
            fi
            ;;
        WEB-18)
            lines="$(webtob_config_grep 'Method[[:space:]]*=.*(PROPFIND|PUT|DELETE|MKCOL|COPY|MOVE)|WebDAV|dav' || true)"
            if [ -n "${lines}" ]; then
                webtob_set_result "VULNERABLE" "$(webtob_status_for_result VULNERABLE)" "WebtoB WebDAV-like methods/settings evidence was found." "${lines}" "grep WebDAV methods http.m"
            elif [ -z "${WEBTOB_HOME}" ] || [ "${#WEBTOB_CONFIGS[@]}" -eq 0 ]; then
                # Installed (per webtob_is_installed) but no http.m config was
                # actually inspected (home not derivable or config files absent):
                # GOOD cannot be asserted from zero evidence -> MANUAL.
                webtob_set_result "MANUAL" "$(webtob_status_for_result MANUAL)" "WebtoB appears installed but its configuration (http.m) could not be inspected; manually verify WebDAV is disabled." "$(webtob_evidence)" "grep WebDAV methods http.m"
            else
                webtob_set_result "GOOD" "$(webtob_status_for_result GOOD)" "No WebtoB WebDAV-like method evidence was found." "$(webtob_evidence)" "grep WebDAV methods http.m"
            fi
            ;;
        WEB-19)
            lines="$(webtob_config_grep 'SVRTYPE[[:space:]]*=[[:space:]]*SSI|SvrType[[:space:]]*=[[:space:]]*SSI|SSI' || true)"
            if [ -n "${lines}" ]; then
                webtob_set_result "VULNERABLE" "$(webtob_status_for_result VULNERABLE)" "WebtoB SSI server mapping evidence was found." "${lines}" "grep SSI http.m"
            elif [ -z "${WEBTOB_HOME}" ] || [ "${#WEBTOB_CONFIGS[@]}" -eq 0 ]; then
                # Installed (per webtob_is_installed) but no http.m config was
                # actually inspected (home not derivable or config files absent):
                # GOOD cannot be asserted from zero evidence -> MANUAL.
                webtob_set_result "MANUAL" "$(webtob_status_for_result MANUAL)" "WebtoB appears installed but its configuration (http.m) could not be inspected; manually verify SSI is disabled." "$(webtob_evidence)" "grep SSI http.m"
            else
                webtob_set_result "GOOD" "$(webtob_status_for_result GOOD)" "No WebtoB SSI mapping evidence was found." "$(webtob_evidence)" "grep SSI http.m"
            fi
            ;;
        WEB-20)
            # Oracle: GOOD only when SSL/TLS is actually ENABLED (SSLFLAG=Y).
            # A defined *SSL block (SSLNAME/CertificateFile) with SSLFLAG=N means
            # SSL is configured but disabled -> not GOOD.
            lines="$(webtob_config_grep_active 'SSLFLAG[[:space:]]*=[[:space:]]*[NY]|SSLNAME|CertificateFile|Protocols' || true)"
            if printf '%s' "${lines}" | grep -Eiq 'SSLFLAG[[:space:]]*=[[:space:]]*Y'; then
                webtob_set_result "GOOD" "$(webtob_status_for_result GOOD)" "WebtoB SSL/TLS is enabled (SSLFLAG=Y)." "${lines}" "grep SSL http.m"
            elif printf '%s' "${lines}" | grep -Eiq 'SSLFLAG[[:space:]]*=[[:space:]]*N'; then
                webtob_set_result "VULNERABLE" "$(webtob_status_for_result VULNERABLE)" "WebtoB SSL/TLS is disabled (SSLFLAG=N) despite SSL configuration being present." "${lines}" "grep SSL http.m"
            elif [ -n "${lines}" ]; then
                webtob_set_result "MANUAL" "$(webtob_status_for_result MANUAL)" "WebtoB SSL configuration directives were found but the SSLFLAG activation state could not be determined." "$(webtob_join_lines "${lines}" "$(webtob_evidence)")" "grep SSL http.m"
            else
                webtob_set_result "VULNERABLE" "$(webtob_status_for_result VULNERABLE)" "WebtoB SSL/TLS activation evidence was not found." "$(webtob_evidence)" "grep SSL http.m"
            fi
            ;;
        WEB-21)
            # Oracle: GOOD only when HTTPS redirection is ACTIVE: URLRewrite=Y
            # must be enabled AND an actual redirect to https must be present in
            # the scanned config (RewriteRule -> https:// or a literal https://
            # redirect target). A bare URLRewriteConfig directive only NAMES an
            # external rewrite file that is not content-scanned, so it cannot by
            # itself prove a redirect -> that case falls through to MANUAL below.
            lines="$(webtob_config_grep_active 'URLRewrite[[:space:]]*=[[:space:]]*[NY]|URLRewriteConfig|RewriteRule|https://' || true)"
            if printf '%s' "${lines}" | grep -Eiq 'URLRewrite[[:space:]]*=[[:space:]]*Y' \
                && printf '%s' "${lines}" | grep -Eiq 'RewriteRule.*https://|https://'; then
                webtob_set_result "GOOD" "$(webtob_status_for_result GOOD)" "WebtoB HTTP-to-HTTPS redirection is enabled (URLRewrite=Y with an https redirect rule)." "${lines}" "grep rewrite http.m"
            elif printf '%s' "${lines}" | grep -Eiq 'URLRewrite[[:space:]]*=[[:space:]]*N'; then
                webtob_set_result "VULNERABLE" "$(webtob_status_for_result VULNERABLE)" "WebtoB URL rewrite is disabled (URLRewrite=N); HTTPS redirection is not active." "${lines}" "grep rewrite http.m"
            elif printf '%s' "${lines}" | grep -Eiq 'URLRewrite[[:space:]]*=[[:space:]]*Y'; then
                webtob_set_result "MANUAL" "$(webtob_status_for_result MANUAL)" "WebtoB URLRewrite=Y is set but an explicit HTTPS redirect rule could not be confirmed; verify the rewrite config." "$(webtob_join_lines "${lines}" "$(webtob_evidence)")" "grep rewrite http.m"
            else
                webtob_set_result "VULNERABLE" "$(webtob_status_for_result VULNERABLE)" "WebtoB HTTP-to-HTTPS redirection activation evidence was not found." "$(webtob_evidence)" "grep rewrite http.m"
            fi
            ;;
        WEB-22)
            # Oracle: a custom error page must be SEPARATELY DESIGNATED, i.e. an
            # active ERRORDOCUMENT directive that assigns a url= to a custom
            # page (e.g. `503  status = 503, url = "/503.html"`). A bare numeric
            # match on 401/403/404/500/503/504 (ports, paths, comments) or an
            # ERRORDOCUMENT line without a url= value is NOT sufficient.
            lines="$(webtob_config_grep_active 'ERRORDOCUMENT|[[:space:]]url[[:space:]]*=' || true)"
            if printf '%s' "${lines}" | grep -Eiq 'url[[:space:]]*=[[:space:]]*"?[^",[:space:]]+'; then
                webtob_set_result "GOOD" "$(webtob_status_for_result GOOD)" "WebtoB custom error page is designated (ERRORDOCUMENT with a url= assignment)." "${lines}" "grep ERRORDOCUMENT http.m"
            elif printf '%s' "${lines}" | grep -Eiq 'ERRORDOCUMENT'; then
                webtob_set_result "VULNERABLE" "$(webtob_status_for_result VULNERABLE)" "WebtoB ERRORDOCUMENT section was found but no custom error page (url=) was designated." "$(webtob_join_lines "${lines}" "$(webtob_evidence)")" "grep ERRORDOCUMENT http.m"
            else
                webtob_set_result "VULNERABLE" "$(webtob_status_for_result VULNERABLE)" "WebtoB custom error page designation evidence was not found." "$(webtob_evidence)" "grep ERRORDOCUMENT http.m"
            fi
            ;;
        WEB-23)
            # Oracle target = Tomcat only; WebtoB is out of scope for the LDAP
            # digest-algorithm item -> N/A (not MANUAL).
            webtob_set_result "N/A" "N/A" "LDAP digest algorithm item (WEB-23) targets Tomcat only; WebtoB is out of scope." "WEB-23 target excludes WebtoB." "Map WebtoB guideline applicability"
            ;;
        WEB-24)
            # WebtoB IS in target for the separate upload-path item; retain the
            # manual upload-path/permission review.
            webtob_set_result "MANUAL" "$(webtob_status_for_result MANUAL)" "WebtoB separate upload path and permission settings require site-specific policy review." "$(webtob_evidence)" "Review WebtoB upload path/permission policy"
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
            # criteria_bad: '로그 디렉터리 및 파일에 일반 사용자의 접근 권한이 있는 경우'
            # — files are explicitly in scope. The default WebtoB log-file mode is
            # 644 (world/other-readable), so a 750 log dir containing a 644
            # access.log is still vulnerable. Enumerate the regular files inside
            # each log dir (maxdepth 1) and assess them alongside the dirs so a
            # world-readable log FILE under a tight dir is reported VULNERABLE.
            local webtob_log_targets=()
            local log_dir
            local log_file
            for log_dir in "${WEBTOB_LOG_DIRS[@]}"; do
                webtob_log_targets+=("${log_dir}")
                while IFS= read -r log_file; do
                    [ -n "${log_file}" ] && webtob_log_targets+=("${log_file}")
                done < <(find "${log_dir}" -maxdepth 1 -type f 2>/dev/null || true)
            done
            webtob_acl_check "log" "${webtob_log_targets[@]}"
            ;;
        *)
            webtob_set_result "MANUAL" "$(webtob_status_for_result MANUAL)" "No WebtoB Linux diagnostic rule is defined for ${item_id}." "$(webtob_evidence)" "WebtoB Linux generic discovery"
            ;;
    esac
}
