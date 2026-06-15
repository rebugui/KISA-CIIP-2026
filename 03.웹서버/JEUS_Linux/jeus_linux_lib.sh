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

# Strip XML comments (including MULTI-LINE <!-- ... --> blocks that span several
# lines) from each config file, then grep the comment-free text. A per-line sed
# cannot remove a block comment whose delimiters sit on separate lines, so the awk
# state machine below carries the in-comment state across newlines. Output lines are
# prefixed "file:" to keep evidence parity with jeus_config_grep. Returns 0 if the
# pattern matched any uncommented line.
jeus_config_grep_stripped() {
    local pattern="$1"
    local found=1
    local file
    for file in "${JEUS_CONFIGS[@]}"; do
        [ -f "${file}" ] || continue
        if awk -v fname="${file}" '
            {
                line = $0
                out = ""
                while (length(line) > 0) {
                    if (in_comment) {
                        idx = index(line, "-->")
                        if (idx == 0) { line = ""; break }
                        line = substr(line, idx + 3)
                        in_comment = 0
                    } else {
                        idx = index(line, "<!--")
                        if (idx == 0) { out = out line; line = ""; break }
                        out = out substr(line, 1, idx - 1)
                        line = substr(line, idx + 4)
                        in_comment = 1
                    }
                }
                if (out != "") print fname ":" out
            }
        ' "${file}" 2>/dev/null | grep -Ei "${pattern}"; then
            found=0
        fi
    done
    return "${found}"
}

jeus_acl_check() {
    local role="$1"
    local acl_mode="$2"
    shift 2
    [ -n "${acl_mode}" ] || acl_mode="lenient"
    local targets=("$@")
    local bad=""
    local checked=""
    local stat_failed=""
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
            if ! printf '%s' "${octal}" | grep -Eq '^[0-7]{3}$'; then
                # stat existed but the permission triplet could not be read/parsed.
                stat_failed=1
                continue
            fi
            group_digit="${octal:1:1}"
            other_digit="${octal:2:1}"
            if [ "${acl_mode}" = "strict" ]; then
                # criteria_bad (e.g. WEB-03 password file, <=600): ANY group OR other
                # access bit (read/write/exec) is a violation. Mask 0177 (=group rwx +
                # other rwx + owner-exec) -> non-zero means mode > 600. Group read (640)
                # and group/other exec are all flagged.
                if [ "$(( 8#${octal} & 8#177 ))" -ne 0 ]; then
                    bad+="${mode}"$'\n'
                fi
            else
                # Lenient (config/log hardening): "Other" digit non-zero => world-accessible
                # (read=4, exec=1, write=2 all flagged). Group-WRITE (2/3/6/7) is also broad
                # access per guideline remediation (chmod -R 750 -> group r-x acceptable,
                # group write is not). Group read/exec only (4,5) stays clean per 750/640.
                case "${other_digit}" in
                    1|2|3|4|5|6|7) bad+="${mode}"$'\n' ;;
                esac
                if [ "${other_digit}" = "0" ]; then
                    case "${group_digit}" in
                        2|3|6|7) bad+="${mode}"$'\n' ;;
                    esac
                fi
            fi
        else
            stat_failed=1
        fi
    done
    if [ -n "${bad}" ]; then
        jeus_set_result "VULNERABLE" "$(jeus_status_for_result VULNERABLE)" "Broad general-user access (read/write/exec) permission evidence was found on JEUS ${role} paths." "${bad}" "stat JEUS ${role} paths"
    elif [ "${acl_mode}" = "strict" ] && [ -n "${stat_failed}" ]; then
        jeus_set_result "MANUAL" "$(jeus_status_for_result MANUAL)" "JEUS ${role} paths exist but their permissions could not be read; verify the password-file mode (must be 600 or less) manually." "${checked}$(jeus_evidence)" "stat JEUS ${role} paths"
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
            # criteria_bad is the account NAME equalling the default 'administrator'. The
            # default 'Administrators' group / 'AdministratorsRole' role is functional and a
            # compliant (renamed) admin is still a member of it, so matching the bare
            # 'administrator' substring (which also hits 'Administrators'/'AdministratorsRole')
            # over-reports. Trigger VULNERABLE only on the username FIELD holding
            # 'administrator' (<name>administrator</name> or name="administrator"); the
            # trailing boundary [^[:alnum:]_] / value-close excludes the 'Administrators' group.
            if printf '%s' "${lines}" | grep -Eiq '<name>[[:space:]]*administrator[[:space:]]*</name>|name[[:space:]]*=[[:space:]]*["'"'"']administrator["'"'"']'; then
                jeus_set_result "VULNERABLE" "$(jeus_status_for_result VULNERABLE)" "Default JEUS administrator account name evidence was found." "${lines}" "Inspect JEUS accounts.xml/security domain users"
            elif [ -n "${lines}" ]; then
                jeus_set_result "MANUAL" "$(jeus_status_for_result MANUAL)" "JEUS account/group evidence was found (e.g. the default Administrators group/role) but no default 'administrator' account NAME was confirmed; verify the administrator account name is not a default/guessable value." "${lines}" "Inspect JEUS accounts.xml/security domain users"
            else
                jeus_set_result "MANUAL" "$(jeus_status_for_result MANUAL)" "JEUS account configuration was not found; confirm administrator account name manually." "$(jeus_evidence)" "Inspect JEUS accounts.xml/security domain users"
            fi
            ;;
        WEB-02)
            jeus_set_result "MANUAL" "$(jeus_status_for_result MANUAL)" "JEUS administrator password complexity depends on security-domain policy and password store state. Confirm policy and password age manually." "$(jeus_evidence)" "Inspect JEUS password policy/accounts.xml"
            ;;
        WEB-03)
            # WEB-03 is the STRICT password-file rule (criteria_bad: mode > 600). Only the
            # credential stores (accounts.xml/policies.xml) are in scope here; general config
            # files (domain.xml/web.xml/...) are covered by WEB-14 with its 750/640 leniency.
            # Restrict to the password files and enforce mode <= 600 (any group/other bit = bad).
            local web03_pwfiles=()
            local web03_file
            for web03_file in "${JEUS_CONFIGS[@]}"; do
                case "${web03_file}" in
                    */accounts.xml|*/policies.xml) web03_pwfiles+=("${web03_file}") ;;
                esac
            done
            jeus_acl_check "security account/policy" "strict" "${web03_pwfiles[@]:-}"
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
            # Use the comment-stripped grep so a multipart/upload limit disabled via a
            # MULTI-LINE <!-- ... --> comment (delimiters on their own lines) is not counted
            # as a real limit. jeus_config_grep alone returns only the inner matching lines,
            # so the standalone <!-- / --> lines never enter its set and the single-line sed
            # below cannot remove them (same multi-line blind spot fixed for WEB-22).
            lines="$(jeus_config_grep_stripped 'max-file-size|max-request-size|maxPostSize|multipart-config' || true)"
            # Strip XML/inline comments so commented-out directives do not count, then
            # require a real positive numeric limit (a size directive followed by a
            # non-zero integer). A lone <multipart-config> tag or <...>0<...> is not a limit.
            # The gap class [^0-9-]* forbids a leading '-' between the directive and the
            # digit, so -1 / maxPostSize="-1" (servlet-spec "no limit" = unlimited = bad)
            # is NOT treated as a valid limit.
            local web08_effective
            web08_effective="$(printf '%s\n' "${lines}" | sed -e 's/<!--.*-->//g' | grep -Ev '<!--|-->' || true)"
            if printf '%s\n' "${web08_effective}" | grep -Eiq '(max-file-size|max-request-size|maxPostSize)[^0-9-]*[1-9][0-9]*'; then
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
            # Use the comment-stripped grep so an aliasing/link block disabled via a
            # MULTI-LINE <!-- ... --> comment (delimiters on their own lines) is not counted.
            # GOOD per the guideline = links not allowed; a commented-out (inactive) alias
            # block means aliasing is NOT in effect and must NOT drive VULNERABLE. Only an
            # active aliasing element should flag (same multi-line fix used for WEB-22).
            lines="$(jeus_config_grep_stripped '<aliasing>|<alias>|<alias-name>|<real-path>' || true)"
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
            jeus_acl_check "config/root" "lenient" "${JEUS_CONFIGS[@]}" "${JEUS_HOME_FOUND}"
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
            elif [ "${#JEUS_CONFIGS[@]}" -eq 0 ]; then
                # No config files were collected (e.g. JEUS detected by process only,
                # JEUS_HOME unresolved). "No mapping found" here means "nothing inspected",
                # not "genuinely no mappings"; do not emit GOOD. (Mirrors the WEB-07 guard.)
                jeus_set_result "MANUAL" "$(jeus_status_for_result MANUAL)" "JEUS is installed but no web.xml/config files were available to inspect for servlet mappings; review unnecessary script mappings manually." "$(jeus_evidence)" "Inspect JEUS servlet mappings"
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
            # Use the comment-stripped grep so that error-page blocks disabled via a
            # MULTI-LINE <!-- ... --> comment (delimiters on their own lines) are not
            # counted. jeus_config_grep alone would keep the inner <location> line because
            # the standalone <!-- / --> lines never enter its match set.
            local web22_effective
            web22_effective="$(jeus_config_grep_stripped '<error-page>|<error-code>|<location>' || true)"
            # Require a real <location> with a non-empty value to treat as configured.
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
            # criteria_bad covers log DIRECTORIES *and* FILES (remediation: log files 640;
            # default 644 is world-readable = vulnerable). JEUS_LOG_DIRS holds directories
            # only, so enumerate the regular files inside each and assess them too.
            local web26_targets=()
            local web26_dir
            local web26_file
            for web26_dir in "${JEUS_LOG_DIRS[@]:-}"; do
                [ -n "${web26_dir}" ] || continue
                web26_targets+=("${web26_dir}")
                [ -d "${web26_dir}" ] || continue
                while IFS= read -r web26_file; do
                    [ -n "${web26_file}" ] && web26_targets+=("${web26_file}")
                done < <(find "${web26_dir}" -type f 2>/dev/null | head -500)
            done
            jeus_acl_check "log" "lenient" "${web26_targets[@]:-}"
            ;;
        *)
            jeus_set_result "MANUAL" "$(jeus_status_for_result MANUAL)" "No JEUS Linux diagnostic rule is defined for ${item_id}." "$(jeus_evidence)" "JEUS Linux generic discovery"
            ;;
    esac
}
