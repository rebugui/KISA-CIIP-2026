#!/bin/bash

tibero_set_result() {
    diagnosis_result="$1"
    status="$2"
    inspection_summary="$3"
    command_result="$4"
    command_executed="$5"
}

tibero_status_for_result() {
    case "$1" in
        GOOD) printf '%s' "양호" ;;
        VULNERABLE) printf '%s' "취약" ;;
        N/A) printf '%s' "N/A" ;;
        *) printf '%s' "수동진단" ;;
    esac
}

tibero_add_unique() {
    local value="$1"
    local existing
    [ -n "${value}" ] || return 0
    for existing in "${TIBERO_UNIQUE_TMP[@]:-}"; do
        [ "${existing}" = "${value}" ] && return 0
    done
    TIBERO_UNIQUE_TMP+=("${value}")
}

tibero_find_home() {
    if [ -n "${TB_HOME:-}" ] && [ -d "${TB_HOME}" ]; then
        printf '%s\n' "${TB_HOME}"
        return 0
    fi
    for candidate in /home/*/tibero /home/*/Tibero /opt/tibero /usr/local/tibero /TmaxData/tibero /Tibero /tibero; do
        [ -d "${candidate}" ] && printf '%s\n' "${candidate}" && return 0
    done
    return 1
}

tibero_process_evidence() {
    ps -eo user=,pid=,comm=,args= 2>/dev/null |
        awk 'BEGIN { IGNORECASE = 1 } {
            comm = $3
            if (comm ~ /^(tbsvr|tblistener|tbsql|tbboot|tbdown)$/ && $0 ~ /(tibero|TB_HOME|tbsvr|tblistener)/) {
                print $0
            }
        }' || true
}

tibero_collect_state() {
    TIBERO_HOME_FOUND="$(tibero_find_home || true)"
    TIBERO_PROCESS_EVIDENCE="$(tibero_process_evidence)"
    TIBERO_CLI="$(command -v tbsql 2>/dev/null || true)"
    TIBERO_CONFIGS=()

    if [ -z "${TIBERO_CLI}" ] && [ -n "${TIBERO_HOME_FOUND}" ] && [ -x "${TIBERO_HOME_FOUND}/bin/tbsql" ]; then
        TIBERO_CLI="${TIBERO_HOME_FOUND}/bin/tbsql"
    fi

    if [ -n "${TIBERO_HOME_FOUND}" ]; then
        TIBERO_UNIQUE_TMP=()
        for file in "${TIBERO_HOME_FOUND}/client/config/tbdsn.tbr" "${TIBERO_HOME_FOUND}/config/tbdsn.tbr"; do
            [ -f "${file}" ] && tibero_add_unique "${file}"
        done
        if [ -d "${TIBERO_HOME_FOUND}/config" ]; then
            while IFS= read -r file; do
                tibero_add_unique "${file}"
            done < <(find "${TIBERO_HOME_FOUND}/config" -maxdepth 2 -type f \( -name '*.tip' -o -name 'tbdsn.tbr' \) 2>/dev/null | head -80)
        fi
        if [ "${#TIBERO_UNIQUE_TMP[@]}" -gt 0 ]; then
            TIBERO_CONFIGS=("${TIBERO_UNIQUE_TMP[@]}")
        fi
        unset TIBERO_UNIQUE_TMP
    fi
}

tibero_is_installed() {
    [ -n "${TIBERO_HOME_FOUND:-}" ] && return 0
    [ -n "${TIBERO_PROCESS_EVIDENCE:-}" ] && return 0
    return 1
}

tibero_evidence() {
    {
        [ -n "${TIBERO_HOME_FOUND:-}" ] && printf 'TB_HOME: %s\n' "${TIBERO_HOME_FOUND}"
        [ "${#TIBERO_CONFIGS[@]}" -gt 0 ] && printf 'ConfigFiles: %s\n' "${TIBERO_CONFIGS[*]}"
        [ -n "${TIBERO_CLI:-}" ] && printf 'CliPath: %s\n' "${TIBERO_CLI}"
        [ -n "${TIBERO_PROCESS_EVIDENCE:-}" ] && printf 'Processes:\n%s\n' "${TIBERO_PROCESS_EVIDENCE}"
    } | sed '/^$/d'
}

tibero_config_grep() {
    local pattern="$1"
    local found=1
    local file
    for file in "${TIBERO_CONFIGS[@]}"; do
        if grep -Ein "${pattern}" "${file}" 2>/dev/null; then
            found=0
        fi
    done
    return "${found}"
}

tibero_acl_check() {
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
        tibero_set_result "VULNERABLE" "$(tibero_status_for_result VULNERABLE)" "Broad write permission evidence was found on Tibero ${role} paths." "${bad}" "stat Tibero ${role} paths"
    elif [ -n "${checked}" ]; then
        tibero_set_result "GOOD" "$(tibero_status_for_result GOOD)" "No broad write permission evidence was found on assessed Tibero ${role} paths." "${checked}" "stat Tibero ${role} paths"
    else
        tibero_set_result "MANUAL" "$(tibero_status_for_result MANUAL)" "Tibero ${role} paths were not found for permission assessment." "$(tibero_evidence)" "stat Tibero ${role} paths"
    fi
}

tibero_query() {
    local query="$1"
    if [ -z "${TIBERO_CLI:-}" ]; then
        printf '%s\n' "tbsql client was not found."
        return 127
    fi
    local conn
    local display
    if [ -n "${TIBERO_CONNECT_STRING:-}" ]; then
        conn="${TIBERO_CONNECT_STRING}"
        display="TIBERO_CONNECT_STRING"
    else
        local user="${TIBERO_USER:-${DB_USER:-sys}}"
        local password="${TIBERO_PASSWORD:-${DB_PASSWORD:-tibero}}"
        local host="${TIBERO_HOST:-${DB_HOST:-localhost}}"
        local port="${TIBERO_PORT:-${DB_PORT:-8629}}"
        local service="${TB_SID:-${DB_NAME:-tibero}}"
        conn="${user}/${password}@${host}:${port}/${service}"
        display="${user}/***@${host}:${port}/${service}"
    fi
    TIBERO_LAST_COMMAND="${TIBERO_CLI} ${display}"
    printf 'set heading off feedback off pagesize 500 linesize 32767\n%s\nexit\n' "${query}" |
        "${TIBERO_CLI}" "${conn}" 2>&1
}

tibero_sql_check() {
    local query="$1"
    local description="$2"
    local output
    local code
    output="$(tibero_query "${query}")"
    code=$?
    if [ "${code}" -ne 0 ] || printf '%s' "${output}" | grep -Eiq 'TBR-[0-9]+|ERROR|failed|not found'; then
        tibero_set_result "MANUAL" "$(tibero_status_for_result MANUAL)" "Tibero was found, but SQL evidence for ${description} could not be collected automatically." "$(printf 'Discovery evidence:\n%s\n\nSQL output:\n%s' "$(tibero_evidence)" "${output}")" "${TIBERO_LAST_COMMAND:-tbsql client discovery}"
        return 1
    fi
    TIBERO_SQL_OUTPUT="${output}"
    return 0
}

invoke_tibero_linux_check() {
    local item_id="$1"
    tibero_collect_state
    if ! tibero_is_installed; then
        tibero_set_result "N/A" "N/A" "Tibero service/process/home evidence was not found." "No Tibero process or TB_HOME evidence found." "ps -eo user,pid,args; inspect TB_HOME"
        return 0
    fi

    local lines
    case "${item_id}" in
        D-01)
            tibero_sql_check "SELECT username||' '||account_status FROM dba_users WHERE username IN ('SYS','SYSCAT','SYSGIS','OUTLN','TIBERO','TBSAMPLE');" "default account password policy" || return 0
            if printf '%s' "${TIBERO_SQL_OUTPUT}" | grep -Eiq '[[:space:]]OPEN'; then
                tibero_set_result "MANUAL" "$(tibero_status_for_result MANUAL)" "Default Tibero accounts are open; confirm password change, lock policy, and approved use." "${TIBERO_SQL_OUTPUT}" "${TIBERO_LAST_COMMAND}"
            else
                tibero_set_result "GOOD" "$(tibero_status_for_result GOOD)" "Default Tibero account evidence was collected without obvious open-account risk." "${TIBERO_SQL_OUTPUT}" "${TIBERO_LAST_COMMAND}"
            fi
            ;;
        D-02)
            tibero_sql_check "SELECT username||' '||account_status FROM dba_users WHERE username IN ('TBSAMPLE','SAMPLE','TEST','DEMO') OR username LIKE 'TEST%';" "unnecessary account removal" || return 0
            if printf '%s' "${TIBERO_SQL_OUTPUT}" | grep -Eiq '[[:space:]]OPEN'; then
                tibero_set_result "VULNERABLE" "$(tibero_status_for_result VULNERABLE)" "Unnecessary Tibero sample/test accounts are open." "${TIBERO_SQL_OUTPUT}" "${TIBERO_LAST_COMMAND}"
            elif printf '%s' "${TIBERO_SQL_OUTPUT}" | grep -Eq '[[:alnum:]]'; then
                tibero_set_result "MANUAL" "$(tibero_status_for_result MANUAL)" "Sample/test Tibero accounts exist; confirm they are locked or approved." "${TIBERO_SQL_OUTPUT}" "${TIBERO_LAST_COMMAND}"
            else
                tibero_set_result "GOOD" "$(tibero_status_for_result GOOD)" "No obvious sample/test Tibero accounts were returned." "No rows returned." "${TIBERO_LAST_COMMAND}"
            fi
            ;;
        D-03)
            tibero_sql_check "SELECT resource_name||'='||limit FROM dba_profiles WHERE profile='DEFAULT' AND resource_name IN ('PASSWORD_LIFE_TIME','PASSWORD_VERIFY_FUNCTION','FAILED_LOGIN_ATTEMPTS','PASSWORD_LOCK_TIME');" "password lifetime and complexity" || return 0
            if ! printf '%s' "${TIBERO_SQL_OUTPUT}" | grep -Eq '[^[:space:]]'; then
                tibero_set_result "VULNERABLE" "$(tibero_status_for_result VULNERABLE)" "Tibero DEFAULT profile returned no password lifetime/complexity/lockout policy rows; the control is not configured." "No rows returned (no DEFAULT profile password policy configured)." "${TIBERO_LAST_COMMAND}"
            elif printf '%s' "${TIBERO_SQL_OUTPUT}" | grep -Eiq 'PASSWORD_VERIFY_FUNCTION=$|PASSWORD_VERIFY_FUNCTION=NULL|PASSWORD_LIFE_TIME=UNLIMITED|FAILED_LOGIN_ATTEMPTS=UNLIMITED'; then
                tibero_set_result "VULNERABLE" "$(tibero_status_for_result VULNERABLE)" "Tibero DEFAULT profile password lifetime/complexity/lockout controls are weak." "${TIBERO_SQL_OUTPUT}" "${TIBERO_LAST_COMMAND}"
            elif ! printf '%s' "${TIBERO_SQL_OUTPUT}" | grep -Eq 'PASSWORD_VERIFY_FUNCTION='; then
                tibero_set_result "VULNERABLE" "$(tibero_status_for_result VULNERABLE)" "Tibero DEFAULT profile is missing a PASSWORD_VERIFY_FUNCTION row; no password complexity verification is configured." "${TIBERO_SQL_OUTPUT}" "${TIBERO_LAST_COMMAND}"
            else
                tibero_set_result "GOOD" "$(tibero_status_for_result GOOD)" "Tibero DEFAULT profile password controls appear configured." "${TIBERO_SQL_OUTPUT}" "${TIBERO_LAST_COMMAND}"
            fi
            ;;
        D-04)
            tibero_sql_check "SELECT grantee FROM dba_role_privs WHERE granted_role='DBA' ORDER BY grantee;" "administrator privilege restriction" || return 0
            tibero_set_result "MANUAL" "$(tibero_status_for_result MANUAL)" "Tibero DBA role grantees were collected; confirm only approved administrators are included." "${TIBERO_SQL_OUTPUT}" "${TIBERO_LAST_COMMAND}"
            ;;
        D-05)
            tibero_sql_check "SELECT resource_name||'='||limit FROM dba_profiles WHERE resource_name IN ('PASSWORD_REUSE_TIME','PASSWORD_REUSE_MAX') ORDER BY profile,resource_name;" "password reuse policy" || return 0
            if ! printf '%s' "${TIBERO_SQL_OUTPUT}" | grep -Eq '[^[:space:]]'; then
                tibero_set_result "VULNERABLE" "$(tibero_status_for_result VULNERABLE)" "Tibero returned no PASSWORD_REUSE_TIME/PASSWORD_REUSE_MAX policy rows; the password-reuse control is not configured." "No rows returned (no password-reuse policy configured)." "${TIBERO_LAST_COMMAND}"
            elif printf '%s' "${TIBERO_SQL_OUTPUT}" | grep -Eiq '=UNLIMITED|=DEFAULT'; then
                tibero_set_result "MANUAL" "$(tibero_status_for_result MANUAL)" "Tibero password reuse controls require profile-by-profile review." "${TIBERO_SQL_OUTPUT}" "${TIBERO_LAST_COMMAND}"
            else
                tibero_set_result "GOOD" "$(tibero_status_for_result GOOD)" "Tibero password reuse profile limits were collected without obvious unlimited evidence." "${TIBERO_SQL_OUTPUT}" "${TIBERO_LAST_COMMAND}"
            fi
            ;;
        D-06)
            tibero_sql_check "SELECT username FROM dba_users WHERE username IN ('DBA','ADMIN','OPER','SHARED') OR username LIKE 'APP_%' ORDER BY username;" "individual DB account assignment" || return 0
            if printf '%s' "${TIBERO_SQL_OUTPUT}" | grep -Eiq 'DBA|ADMIN|OPER|SHARED|APP_'; then
                tibero_set_result "MANUAL" "$(tibero_status_for_result MANUAL)" "Shared or privileged-looking Tibero accounts were found; confirm individual account assignment policy." "${TIBERO_SQL_OUTPUT}" "${TIBERO_LAST_COMMAND}"
            else
                tibero_set_result "GOOD" "$(tibero_status_for_result GOOD)" "No obvious shared Tibero account names were returned." "${TIBERO_SQL_OUTPUT}" "${TIBERO_LAST_COMMAND}"
            fi
            ;;
        D-07)
            tibero_set_result "N/A" "N/A" "root-privilege service-execution control (D-07) does not target Tibero." "D-07 target scope is Oracle DB, MySQL, Altibase, Cubrid; Tibero is out of scope for this item." "Map DBMS root-execution guideline applicability"
            ;;
        D-08)
            lines="$(tibero_config_grep 'ENCRYPT|SSL|WALLET|CERT' || true)"
            [ -n "${lines}" ] && tibero_set_result "MANUAL" "$(tibero_status_for_result MANUAL)" "Tibero encryption-related configuration evidence was found; confirm approved transport encryption policy." "${lines}" "grep Tibero encryption settings" || tibero_set_result "MANUAL" "$(tibero_status_for_result MANUAL)" "Tibero network encryption evidence was not found; confirm transport encryption policy manually." "$(tibero_evidence)" "grep Tibero encryption settings"
            ;;
        D-09)
            tibero_sql_check "SELECT resource_name||'='||limit FROM dba_profiles WHERE resource_name IN ('FAILED_LOGIN_ATTEMPTS','PASSWORD_LOCK_TIME') ORDER BY profile,resource_name;" "failed login lockout policy" || return 0
            if ! printf '%s' "${TIBERO_SQL_OUTPUT}" | grep -Eq '[^[:space:]]'; then
                tibero_set_result "VULNERABLE" "$(tibero_status_for_result VULNERABLE)" "Tibero returned no FAILED_LOGIN_ATTEMPTS/PASSWORD_LOCK_TIME policy rows; the login-failure lockout control is not configured." "No rows returned (no failed-login lockout policy configured)." "${TIBERO_LAST_COMMAND}"
            elif printf '%s' "${TIBERO_SQL_OUTPUT}" | grep -Eiq 'FAILED_LOGIN_ATTEMPTS[[:space:]]*=[[:space:]]*UNLIMITED'; then
                tibero_set_result "VULNERABLE" "$(tibero_status_for_result VULNERABLE)" "Tibero failed-login lockout profile controls are weak (FAILED_LOGIN_ATTEMPTS=UNLIMITED; no login-attempt limit). PASSWORD_LOCK_TIME=UNLIMITED alone is an accepted lock policy per KISA D-09 and is not treated as a vulnerability." "${TIBERO_SQL_OUTPUT}" "${TIBERO_LAST_COMMAND}"
            elif printf '%s' "${TIBERO_SQL_OUTPUT}" | grep -Eiq 'FAILED_LOGIN_ATTEMPTS[[:space:]]*=[[:space:]]*[0-9]+'; then
                tibero_set_result "GOOD" "$(tibero_status_for_result GOOD)" "Tibero failed-login lockout profile evidence shows a concrete numeric FAILED_LOGIN_ATTEMPTS limit." "${TIBERO_SQL_OUTPUT}" "${TIBERO_LAST_COMMAND}"
            else
                tibero_set_result "MANUAL" "$(tibero_status_for_result MANUAL)" "Tibero failed-login lockout evidence does not show a concrete numeric FAILED_LOGIN_ATTEMPTS limit (value is unset, DEFAULT, blank, or only PASSWORD_LOCK_TIME was returned). Resolve the effective per-profile FAILED_LOGIN_ATTEMPTS (expand DEFAULT/blank to the inherited DEFAULT-profile value) and confirm a login-attempt limit is set; treat unset/DEFAULT/UNLIMITED as a finding." "${TIBERO_SQL_OUTPUT}" "${TIBERO_LAST_COMMAND}"
            fi
            ;;
        D-10)
            lines="$(tibero_config_grep '(LSNR_INVITED_IP|LSNR_DENIED_IP)[[:space:]]*=[[:space:]]*[^[:space:]]' || true)"
            # Drop commented-out directives. tibero_config_grep runs grep -Ein on ONE file at a time, so output is single-file form 'NNN:content' (line number at column 0, no filename and no leading colon); anchor on the leading line number to skip lines whose content starts with #, ;, or -- so an inert commented LSNR_*_IP does not yield GOOD.
            lines="$(printf '%s\n' "${lines}" | grep -Ev '^[0-9]+:[[:space:]]*(#|;|--)' || true)"
            if printf '%s\n' "${lines}" | grep -Eq 'LSNR_INVITED_IP[[:space:]]*=[[:space:]]*[^[:space:]]'; then
                tibero_set_result "GOOD" "$(tibero_status_for_result GOOD)" "Tibero listener IP restriction evidence (active LSNR_INVITED_IP with a value) was found." "${lines}" "grep Tibero listener IP access controls"
            elif [ -n "${lines}" ]; then
                tibero_set_result "MANUAL" "$(tibero_status_for_result MANUAL)" "Only LSNR_DENIED_IP (denylist) was found without LSNR_INVITED_IP (allowlist); a denylist alone does not restrict to only specified IPs. Confirm the actual IP-access restriction policy (firewall, listener, or host-based)." "${lines}" "grep Tibero listener IP access controls"
            else
                tibero_set_result "MANUAL" "$(tibero_status_for_result MANUAL)" "No active Tibero listener IP restriction (LSNR_INVITED_IP/LSNR_DENIED_IP) was found; confirm firewall/listener source-IP policy." "$(tibero_evidence)" "grep Tibero listener IP access controls"
            fi
            ;;
        D-11)
            tibero_sql_check "SELECT grantee||' '||owner||'.'||table_name||' '||privilege FROM dba_tab_privs WHERE owner IN ('SYS','SYSCAT') AND grantee NOT IN ('SYS','SYSCAT','DBA') AND ROWNUM <= 100;" "system table access restriction" || return 0
            if printf '%s' "${TIBERO_SQL_OUTPUT}" | grep -Eq '[[:alnum:]]'; then
                tibero_set_result "VULNERABLE" "$(tibero_status_for_result VULNERABLE)" "Non-DBA Tibero system object privileges were found." "${TIBERO_SQL_OUTPUT}" "${TIBERO_LAST_COMMAND}"
            else
                tibero_set_result "GOOD" "$(tibero_status_for_result GOOD)" "No non-DBA Tibero system object privilege evidence was returned." "No rows returned." "${TIBERO_LAST_COMMAND}"
            fi
            ;;
        D-12)
            tibero_set_result "N/A" "N/A" "Oracle listener password control is not directly applicable to Tibero." "Tibero listener access is handled through Tibero listener configuration such as LSNR_INVITED_IP/LSNR_DENIED_IP and OS/service controls." "Map DBMS listener-password guideline applicability"
            ;;
        D-13)
            tibero_set_result "N/A" "N/A" "D-13 (unnecessary ODBC/OLE-DB data source/driver removal) targets Windows OS only per the KISA CIIP 2026 guideline metadata; Tibero_Linux is out of scope." "D-13 target: Windows OS. Linux Tibero uses tbdsn.tbr rather than Windows ODBC DSN entries." "Map DBMS ODBC/OLE-DB guideline applicability"
            ;;
        D-14)
            tibero_set_result "N/A" "N/A" "D-14 (main configuration/password file access-permission restriction) does not target Tibero per the KISA CIIP 2026 guideline metadata (target: Oracle DB, PostgreSQL, Cubrid)." "Tibero is out of scope for D-14; no file-ACL judgment is rendered." "Map DBMS file-permission guideline applicability"
            ;;
        D-15)
            tibero_set_result "N/A" "N/A" "D-15 (Oracle Listener log/trace change restriction) targets Oracle DB only per the KISA CIIP 2026 guideline metadata; Tibero is out of scope." "D-15 target: Oracle DB; Tibero out of scope." "Map Oracle Listener log/trace guideline applicability"
            ;;
        D-16)
            tibero_set_result "N/A" "N/A" "SQL Server Windows authentication mode control is not applicable to Tibero." "Tibero authentication is controlled by Tibero users, profiles, and DB/OS configuration." "Map DBMS authentication-mode guideline applicability"
            ;;
        D-17)
            tibero_sql_check "SELECT grantee||' '||owner||'.'||table_name||' '||privilege FROM dba_tab_privs WHERE table_name LIKE '%AUDIT%' AND grantee NOT IN ('SYS','SYSCAT','DBA') AND ROWNUM <= 100;" "audit table DBA-only access" || return 0
            if printf '%s' "${TIBERO_SQL_OUTPUT}" | grep -Eq '[[:alnum:]]'; then
                tibero_set_result "VULNERABLE" "$(tibero_status_for_result VULNERABLE)" "Tibero audit table privileges granted to non-administrative principals were found." "${TIBERO_SQL_OUTPUT}" "${TIBERO_LAST_COMMAND}"
            else
                tibero_set_result "GOOD" "$(tibero_status_for_result GOOD)" "No non-administrative Tibero audit table privilege evidence was returned." "No rows returned." "${TIBERO_LAST_COMMAND}"
            fi
            ;;
        D-18)
            tibero_sql_check "SELECT granted_role FROM dba_role_privs WHERE grantee='PUBLIC';" "DBA role granted to PUBLIC" || return 0
            if printf '%s' "${TIBERO_SQL_OUTPUT}" | grep -Eq '^[[:space:]]*DBA[[:space:]]*$'; then
                tibero_set_result "VULNERABLE" "$(tibero_status_for_result VULNERABLE)" "Tibero DBA role granted to PUBLIC was found." "${TIBERO_SQL_OUTPUT}" "${TIBERO_LAST_COMMAND}"
            elif printf '%s' "${TIBERO_SQL_OUTPUT}" | grep -Eq '[[:alnum:]]'; then
                tibero_set_result "MANUAL" "$(tibero_status_for_result MANUAL)" "Non-DBA Tibero roles granted to PUBLIC were found; confirm whether any role conveys DBA-level access." "${TIBERO_SQL_OUTPUT}" "${TIBERO_LAST_COMMAND}"
            else
                tibero_set_result "GOOD" "$(tibero_status_for_result GOOD)" "No Tibero roles granted to PUBLIC were returned." "No rows returned." "${TIBERO_LAST_COMMAND}"
            fi
            ;;
        D-19)
            tibero_set_result "N/A" "N/A" "Oracle OS_ROLES/REMOTE_OS_AUTHENTICATION/REMOTE_OS_ROLES controls are not directly applicable to Tibero." "Tibero does not expose Oracle OS role parameters with the same semantics." "Map Oracle OS role guideline applicability"
            ;;
        D-20)
            tibero_sql_check "SELECT owner||'.'||object_name FROM dba_objects WHERE owner NOT IN ('SYS','SYSCAT','OUTLN') AND ROWNUM <= 100;" "unauthorized object owner restriction" || return 0
            if printf '%s' "${TIBERO_SQL_OUTPUT}" | grep -Eq '[[:alnum:]]'; then
                tibero_set_result "MANUAL" "$(tibero_status_for_result MANUAL)" "Application-owned Tibero objects were found or queried; confirm owners are authorized." "${TIBERO_SQL_OUTPUT}" "${TIBERO_LAST_COMMAND}"
            else
                tibero_set_result "GOOD" "$(tibero_status_for_result GOOD)" "No non-system Tibero object owner evidence was returned." "No rows returned." "${TIBERO_LAST_COMMAND}"
            fi
            ;;
        D-21)
            tibero_sql_check "SELECT grantee||' '||owner||'.'||table_name||' '||privilege FROM dba_tab_privs WHERE grantable='YES' AND grantee NOT IN (SELECT grantee FROM dba_role_privs WHERE granted_role = 'DBA') AND ROWNUM <= 100;" "GRANT OPTION restriction" || return 0
            if printf '%s' "${TIBERO_SQL_OUTPUT}" | grep -Eq '[[:alnum:]]'; then
                tibero_set_result "VULNERABLE" "$(tibero_status_for_result VULNERABLE)" "Tibero object privileges with grant option were found." "${TIBERO_SQL_OUTPUT}" "${TIBERO_LAST_COMMAND}"
            else
                tibero_set_result "GOOD" "$(tibero_status_for_result GOOD)" "No Tibero object privileges with grant option were returned." "No rows returned." "${TIBERO_LAST_COMMAND}"
            fi
            ;;
        D-22)
            tibero_set_result "N/A" "$(tibero_status_for_result N/A)" "D-22 (RESOURCE_LIMIT) targets Oracle DB only per KISA CIIP 2026 metadata; Tibero is out of scope." "D-22 target: Oracle DB." "Map DBMS resource-limit guideline applicability"
            ;;
        D-23)
            tibero_set_result "N/A" "N/A" "SQL Server xp_cmdshell control is not applicable to Tibero." "Tibero has no xp_cmdshell feature." "Map DBMS command-shell guideline applicability"
            ;;
        D-24)
            tibero_set_result "N/A" "N/A" "SQL Server registry extended procedure control is not applicable to Tibero." "Tibero does not expose SQL Server registry extended procedures." "Map DBMS registry-procedure guideline applicability"
            ;;
        D-25)
            tibero_sql_check "SELECT * FROM v\$version;" "vendor patch status" || return 0
            tibero_set_result "MANUAL" "$(tibero_status_for_result MANUAL)" "Tibero was found. Compare detected version and patch level against current TmaxTibero patch guidance." "${TIBERO_SQL_OUTPUT}" "${TIBERO_LAST_COMMAND}"
            ;;
        D-26)
            lines="$(tibero_config_grep 'AUDIT_TRAIL|AUDIT_SYS_OPERATIONS|AUDIT_FILE_DEST|AUDIT_FILE_SIZE' || true)"
            if printf '%s' "${lines}" | grep -Eiq 'AUDIT_TRAIL[[:space:]]*=[[:space:]]*(OS|DB|YES)|AUDIT_SYS_OPERATIONS[[:space:]]*=[[:space:]]*Y'; then
                tibero_set_result "MANUAL" "$(tibero_status_for_result MANUAL)" "Tibero audit configuration evidence was found; confirm retention and audited events satisfy policy." "${lines}" "grep Tibero audit configuration"
            else
                tibero_set_result "MANUAL" "$(tibero_status_for_result MANUAL)" "Tibero audit policy is not derivable from .tip configuration; Tibero audit options reside in the data dictionary. Review DBA_OBJ_AUDIT_OPTS/DBA_PRIV_AUDIT_OPTS/DBA_STMT_AUDIT_OPTS (and AUDIT_SYS_OPERATIONS) to confirm an approved audit logging policy is applied." "$(tibero_evidence)" "grep Tibero audit configuration; review DBA_*_AUDIT_OPTS"
            fi
            ;;
        *)
            tibero_set_result "MANUAL" "$(tibero_status_for_result MANUAL)" "No Tibero Linux diagnostic rule is defined for ${item_id}." "$(tibero_evidence)" "Tibero Linux generic discovery"
            ;;
    esac
}
