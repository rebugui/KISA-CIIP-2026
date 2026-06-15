#!/bin/bash

altibase_set_result() {
    diagnosis_result="$1"
    status="$2"
    inspection_summary="$3"
    command_result="$4"
    command_executed="$5"
}

altibase_status_for_result() {
    case "$1" in
        GOOD) printf '%s' "양호" ;;
        VULNERABLE) printf '%s' "취약" ;;
        N/A) printf '%s' "N/A" ;;
        *) printf '%s' "수동진단" ;;
    esac
}

altibase_add_unique() {
    local value="$1"
    local existing
    [ -n "${value}" ] || return 0
    for existing in "${ALTIBASE_UNIQUE_TMP[@]:-}"; do
        [ "${existing}" = "${value}" ] && return 0
    done
    ALTIBASE_UNIQUE_TMP+=("${value}")
}

altibase_find_home() {
    local env_home="${ALTIBASE_HOME:-${ALTI_HOME:-}}"
    if [ -n "${env_home}" ] && [ -d "${env_home}" ]; then
        printf '%s\n' "${env_home}"
        return 0
    fi
    for candidate in /home/*/altibase /home/*/Altibase /opt/altibase /usr/local/altibase /Altibase /altibase; do
        [ -d "${candidate}" ] && printf '%s\n' "${candidate}" && return 0
    done
    return 1
}

altibase_process_evidence() {
    ps -eo user=,pid=,comm=,args= 2>/dev/null |
        awk 'BEGIN { IGNORECASE = 1 } {
            comm = $3
            if (comm ~ /^(altibase|altibase_m|isql|alti)$/ && $0 ~ /(altibase|ALTIBASE_HOME|ALTI_HOME)/) {
                print $0
            }
        }' || true
}

altibase_collect_state() {
    ALTIBASE_HOME_FOUND="$(altibase_find_home || true)"
    ALTIBASE_PROCESS_EVIDENCE="$(altibase_process_evidence)"
    ALTIBASE_CLI="$(command -v isql 2>/dev/null || true)"
    ALTIBASE_CONFIGS=()
    ALTIBASE_LOG_DIRS=()

    if [ -z "${ALTIBASE_CLI}" ] && [ -n "${ALTIBASE_HOME_FOUND}" ] && [ -x "${ALTIBASE_HOME_FOUND}/bin/isql" ]; then
        ALTIBASE_CLI="${ALTIBASE_HOME_FOUND}/bin/isql"
    fi

    if [ -n "${ALTIBASE_HOME_FOUND}" ]; then
        ALTIBASE_UNIQUE_TMP=()
        for file in "${ALTIBASE_HOME_FOUND}/conf/altibase.properties" "${ALTIBASE_HOME_FOUND}/conf/altibase_user.env"; do
            [ -f "${file}" ] && altibase_add_unique "${file}"
        done
        if [ "${#ALTIBASE_UNIQUE_TMP[@]}" -gt 0 ]; then
            ALTIBASE_CONFIGS=("${ALTIBASE_UNIQUE_TMP[@]}")
        fi

        ALTIBASE_UNIQUE_TMP=()
        for dir in "${ALTIBASE_HOME_FOUND}/trc" "${ALTIBASE_HOME_FOUND}/logs" "${ALTIBASE_HOME_FOUND}/log"; do
            [ -d "${dir}" ] && altibase_add_unique "${dir}"
        done
        if [ "${#ALTIBASE_UNIQUE_TMP[@]}" -gt 0 ]; then
            ALTIBASE_LOG_DIRS=("${ALTIBASE_UNIQUE_TMP[@]}")
        fi
        unset ALTIBASE_UNIQUE_TMP
    fi
}

altibase_is_installed() {
    [ -n "${ALTIBASE_HOME_FOUND:-}" ] && return 0
    [ -n "${ALTIBASE_PROCESS_EVIDENCE:-}" ] && return 0
    return 1
}

altibase_evidence() {
    {
        [ -n "${ALTIBASE_HOME_FOUND:-}" ] && printf 'ALTIBASE_HOME: %s\n' "${ALTIBASE_HOME_FOUND}"
        [ "${#ALTIBASE_CONFIGS[@]}" -gt 0 ] && printf 'ConfigFiles: %s\n' "${ALTIBASE_CONFIGS[*]}"
        [ "${#ALTIBASE_LOG_DIRS[@]}" -gt 0 ] && printf 'LogDirs: %s\n' "${ALTIBASE_LOG_DIRS[*]}"
        [ -n "${ALTIBASE_CLI:-}" ] && printf 'CliPath: %s\n' "${ALTIBASE_CLI}"
        [ -n "${ALTIBASE_PROCESS_EVIDENCE:-}" ] && printf 'Processes:\n%s\n' "${ALTIBASE_PROCESS_EVIDENCE}"
    } | sed '/^$/d'
}

altibase_config_grep() {
    local pattern="$1"
    local found=1
    local file
    for file in "${ALTIBASE_CONFIGS[@]}"; do
        if grep -Ein "${pattern}" "${file}" 2>/dev/null; then
            found=0
        fi
    done
    return "${found}"
}

altibase_acl_check() {
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
        altibase_set_result "VULNERABLE" "$(altibase_status_for_result VULNERABLE)" "Broad write permission evidence was found on Altibase ${role} paths." "${bad}" "stat Altibase ${role} paths"
    elif [ -n "${checked}" ]; then
        altibase_set_result "GOOD" "$(altibase_status_for_result GOOD)" "No broad write permission evidence was found on assessed Altibase ${role} paths." "${checked}" "stat Altibase ${role} paths"
    else
        altibase_set_result "MANUAL" "$(altibase_status_for_result MANUAL)" "Altibase ${role} paths were not found for permission assessment." "$(altibase_evidence)" "stat Altibase ${role} paths"
    fi
}

altibase_query() {
    local query="$1"
    if [ -z "${ALTIBASE_CLI:-}" ]; then
        printf '%s\n' "isql client was not found."
        return 127
    fi

    local user="${ALTIBASE_USER:-${DB_USER:-SYS}}"
    local password="${ALTIBASE_PASSWORD:-${DB_PASSWORD:-MANAGER}}"
    local host="${ALTIBASE_HOST:-${DB_HOST:-127.0.0.1}}"
    local port="${ALTIBASE_PORT:-${DB_PORT:-20300}}"

    printf '%s\n%s\n' "${query}" "quit;" |
        "${ALTIBASE_CLI}" -u "${user}" -p "${password}" -s "${host}" -port "${port}" 2>&1
}

altibase_sql_check() {
    local query="$1"
    local description="$2"
    local output
    local code
    output="$(altibase_query "${query}")"
    code=$?
    if [ "${code}" -ne 0 ] || printf '%s' "${output}" | grep -Eiq 'error|fail|not found|invalid|ERR-|SQLSTATE'; then
        altibase_set_result "MANUAL" "$(altibase_status_for_result MANUAL)" "Altibase was found, but SQL evidence for ${description} could not be collected automatically." "$(printf 'Discovery evidence:\n%s\n\nSQL output:\n%s' "$(altibase_evidence)" "${output}")" "isql -u *** -p *** -s host -port port"
        return 1
    fi
    ALTIBASE_SQL_OUTPUT="${output}"
    return 0
}

invoke_altibase_linux_check() {
    local item_id="$1"
    altibase_collect_state
    if ! altibase_is_installed; then
        altibase_set_result "N/A" "N/A" "Altibase service/process/home evidence was not found." "No Altibase process, ALTIBASE_HOME, or ALTI_HOME evidence found." "ps -eo user,pid,args; inspect ALTIBASE_HOME/ALTI_HOME"
        return 0
    fi

    local lines
    case "${item_id}" in
        D-01)
            altibase_sql_check "SELECT USER_NAME, ACCOUNT_LOCK FROM system_.sys_users_ WHERE USER_NAME IN ('SYS','SYSTEM_','OUTLN','ALTITEST');" "default account password policy" || return 0
            if printf '%s' "${ALTIBASE_SQL_OUTPUT}" | grep -Eiq 'SYS|SYSTEM_|ALTITEST'; then
                altibase_set_result "MANUAL" "$(altibase_status_for_result MANUAL)" "Altibase default account evidence was collected; confirm default passwords are changed or accounts are locked." "${ALTIBASE_SQL_OUTPUT}" "SELECT USER_NAME, ACCOUNT_LOCK FROM system_.sys_users_"
            else
                altibase_set_result "GOOD" "$(altibase_status_for_result GOOD)" "No obvious Altibase default account evidence was returned." "${ALTIBASE_SQL_OUTPUT}" "SELECT USER_NAME FROM system_.sys_users_"
            fi
            ;;
        D-02)
            altibase_sql_check "SELECT USER_NAME FROM system_.sys_users_ WHERE USER_NAME IN ('SCOTT','PM','ADAMS','CLARK','TEST','DEMO','ALTITEST') OR USER_NAME LIKE 'TEST%';" "unnecessary account removal" || return 0
            if printf '%s' "${ALTIBASE_SQL_OUTPUT}" | grep -Eiq 'SCOTT|PM|ADAMS|CLARK|TEST|DEMO|ALTITEST'; then
                altibase_set_result "VULNERABLE" "$(altibase_status_for_result VULNERABLE)" "Unnecessary Altibase sample/test accounts were found." "${ALTIBASE_SQL_OUTPUT}" "SELECT USER_NAME FROM system_.sys_users_"
            else
                altibase_set_result "GOOD" "$(altibase_status_for_result GOOD)" "No obvious sample/test Altibase accounts were returned." "${ALTIBASE_SQL_OUTPUT}" "SELECT USER_NAME FROM system_.sys_users_"
            fi
            ;;
        D-03|D-05|D-09)
            altibase_sql_check "SELECT USER_NAME, PASSWORD_LIFE_TIME, PASSWORD_GRACE_TIME, PASSWORD_REUSE_TIME, PASSWORD_REUSE_MAX, FAILED_LOGIN_ATTEMPTS FROM system_.sys_users_;" "password and login policy" || return 0
            if printf '%s' "${ALTIBASE_SQL_OUTPUT}" | grep -Eiq 'UNLIMITED|NULL|(^|[[:space:]])0([[:space:]]|$)'; then
                altibase_set_result "MANUAL" "$(altibase_status_for_result MANUAL)" "Altibase password/login policy evidence contains weak-looking values; confirm institutional policy thresholds." "${ALTIBASE_SQL_OUTPUT}" "SELECT password policy columns FROM system_.sys_users_"
            else
                altibase_set_result "GOOD" "$(altibase_status_for_result GOOD)" "Altibase password/login policy evidence was collected without obvious unlimited values." "${ALTIBASE_SQL_OUTPUT}" "SELECT password policy columns FROM system_.sys_users_"
            fi
            ;;
        D-04)
            altibase_sql_check "SELECT GRANTEE_ID, PRIV_ID FROM system_.sys_grant_system_;" "administrator privilege restriction" || return 0
            altibase_set_result "MANUAL" "$(altibase_status_for_result MANUAL)" "Altibase system privilege grantees were collected; confirm only approved administrators have DBA-equivalent privileges." "${ALTIBASE_SQL_OUTPUT}" "SELECT GRANTEE_ID, PRIV_ID FROM system_.sys_grant_system_"
            ;;
        D-06)
            altibase_sql_check "SELECT USER_NAME FROM system_.sys_users_ WHERE USER_NAME IN ('DBA','ADMIN','OPER','SHARED') OR USER_NAME LIKE 'APP_%';" "individual DB account assignment" || return 0
            if printf '%s' "${ALTIBASE_SQL_OUTPUT}" | grep -Eiq 'DBA|ADMIN|OPER|SHARED|APP_'; then
                altibase_set_result "MANUAL" "$(altibase_status_for_result MANUAL)" "Shared or privileged-looking Altibase accounts were found; confirm individual account assignment policy." "${ALTIBASE_SQL_OUTPUT}" "SELECT USER_NAME FROM system_.sys_users_"
            else
                altibase_set_result "GOOD" "$(altibase_status_for_result GOOD)" "No obvious shared Altibase account names were returned." "${ALTIBASE_SQL_OUTPUT}" "SELECT USER_NAME FROM system_.sys_users_"
            fi
            ;;
        D-07)
            lines="${ALTIBASE_PROCESS_EVIDENCE}"
            if printf '%s' "${lines}" | grep -Eiq '^[[:space:]]*root[[:space:]]'; then
                altibase_set_result "VULNERABLE" "$(altibase_status_for_result VULNERABLE)" "Altibase processes appear to run as root." "${lines}" "Inspect Altibase process owner"
            elif [ -n "${lines}" ]; then
                altibase_set_result "GOOD" "$(altibase_status_for_result GOOD)" "Altibase processes are not obviously running as root." "${lines}" "Inspect Altibase process owner"
            else
                altibase_set_result "MANUAL" "$(altibase_status_for_result MANUAL)" "Altibase process owner could not be determined." "$(altibase_evidence)" "Inspect Altibase process owner"
            fi
            ;;
        D-08)
            lines="$(altibase_config_grep 'SSL|TLS|ENCRYPT|CERT|KEY' || true)"
            [ -n "${lines}" ] && altibase_set_result "MANUAL" "$(altibase_status_for_result MANUAL)" "Altibase encryption-related configuration evidence was found; confirm approved transport encryption policy." "${lines}" "grep Altibase encryption settings" || altibase_set_result "MANUAL" "$(altibase_status_for_result MANUAL)" "Altibase network encryption evidence was not found; confirm transport encryption policy manually." "$(altibase_evidence)" "grep Altibase encryption settings"
            ;;
        D-10)
            lines="$(altibase_config_grep 'ACCESS_CONTROL|TCP.*PERMIT|TCP.*DENY|IP_ACCESS|IPC_CHANNEL' || true)"
            if [ -n "${lines}" ]; then
                altibase_set_result "GOOD" "$(altibase_status_for_result GOOD)" "Altibase access-control configuration evidence was found." "${lines}" "grep ACCESS_CONTROL altibase.properties"
            else
                altibase_sql_check "SELECT NAME, VALUE1 FROM v\$property WHERE NAME LIKE 'ACCESS_CONTROL_%';" "access control by source IP" || return 0
                if [ -n "${ALTIBASE_SQL_OUTPUT}" ]; then
                    altibase_set_result "MANUAL" "$(altibase_status_for_result MANUAL)" "Altibase access-control property evidence was collected; confirm it matches approved source IP policy." "${ALTIBASE_SQL_OUTPUT}" "SELECT ACCESS_CONTROL properties FROM v\$property"
                else
                    altibase_set_result "MANUAL" "$(altibase_status_for_result MANUAL)" "Altibase access-control configuration/property evidence was not found; confirm approved source IP restriction policy manually." "$(altibase_evidence)" "SELECT ACCESS_CONTROL properties FROM v\$property"
                fi
            fi
            ;;
        D-11)
            altibase_sql_check "SELECT * FROM system_.sys_tables_ WHERE USER_ID NOT IN (SELECT USER_ID FROM system_.sys_users_ WHERE USER_NAME IN ('SYS','SYSTEM_'));" "system table access restriction" || return 0
            altibase_set_result "MANUAL" "$(altibase_status_for_result MANUAL)" "Altibase system table ownership/access evidence was collected; confirm non-admin access is not allowed." "${ALTIBASE_SQL_OUTPUT}" "SELECT * FROM system_.sys_tables_"
            ;;
        D-12)
            altibase_set_result "N/A" "N/A" "Oracle listener password control is not directly applicable to Altibase." "Altibase listener access is handled through Altibase properties, IP ACLs, and OS/service controls." "Map DBMS listener-password guideline applicability"
            ;;
        D-13)
            lines="$(find /etc "${ALTIBASE_HOME_FOUND:-/nonexistent}" -maxdepth 4 \( -iname '*odbc*.ini' -o -iname '*altibase*odbc*' \) 2>/dev/null | head -50 || true)"
            [ -n "${lines}" ] && altibase_set_result "MANUAL" "$(altibase_status_for_result MANUAL)" "Altibase ODBC configuration evidence was found; confirm only required DSNs/drivers remain." "${lines}" "find Altibase ODBC config" || altibase_set_result "GOOD" "$(altibase_status_for_result GOOD)" "No Altibase ODBC configuration evidence was found in inspected paths." "$(altibase_evidence)" "find Altibase ODBC config"
            ;;
        D-14)
            altibase_acl_check "home/config" "${ALTIBASE_HOME_FOUND}" "${ALTIBASE_CONFIGS[@]}"
            ;;
        D-15)
            altibase_set_result "N/A" "N/A" "Oracle Listener log/trace change-restriction control is not applicable to Altibase." "D-15 targets Oracle DB listener (LSNRCTL) parameter/trace protection; Altibase has no equivalent Oracle Listener." "Map Oracle Listener log/trace guideline applicability"
            ;;
        D-16)
            altibase_set_result "N/A" "N/A" "SQL Server Windows authentication mode control is not applicable to Altibase." "Altibase authentication is controlled by Altibase users, password policy, and DB/OS configuration." "Map DBMS authentication-mode guideline applicability"
            ;;
        D-17)
            altibase_sql_check "SELECT * FROM system_.sys_grant_object_ WHERE OBJ_ID IN (SELECT TABLE_ID FROM system_.sys_tables_ WHERE TABLE_NAME LIKE '%AUDIT%');" "audit table DBA-only access" || return 0
            altibase_set_result "MANUAL" "$(altibase_status_for_result MANUAL)" "Altibase audit table privilege evidence was collected; confirm only administrators can access audit tables." "${ALTIBASE_SQL_OUTPUT}" "SELECT audit table grants FROM system_.sys_grant_object_"
            ;;
        D-18)
            altibase_sql_check "SELECT * FROM system_.sys_grant_object_ WHERE GRANTEE_ID IN (SELECT USER_ID FROM system_.sys_users_ WHERE USER_NAME IN ('PUBLIC','GUEST'));" "public role restriction" || return 0
            if printf '%s' "${ALTIBASE_SQL_OUTPUT}" | grep -Eiq 'PUBLIC|GUEST|[0-9]'; then
                altibase_set_result "VULNERABLE" "$(altibase_status_for_result VULNERABLE)" "Altibase object permissions granted to PUBLIC/GUEST-like principals may exist." "${ALTIBASE_SQL_OUTPUT}" "SELECT PUBLIC/GUEST grants FROM system_.sys_grant_object_"
            else
                altibase_set_result "GOOD" "$(altibase_status_for_result GOOD)" "No Altibase PUBLIC/GUEST object permission evidence was returned." "${ALTIBASE_SQL_OUTPUT}" "SELECT PUBLIC/GUEST grants FROM system_.sys_grant_object_"
            fi
            ;;
        D-19)
            altibase_set_result "N/A" "N/A" "Oracle OS_ROLES/REMOTE_OS_AUTHENTICATION/REMOTE_OS_ROLES controls are not directly applicable to Altibase." "Altibase does not expose Oracle OS role parameters with the same semantics." "Map Oracle OS role guideline applicability"
            ;;
        D-20)
            altibase_sql_check "SELECT USER_ID, TABLE_NAME FROM system_.sys_tables_ WHERE USER_ID NOT IN (SELECT USER_ID FROM system_.sys_users_ WHERE USER_NAME IN ('SYS','SYSTEM_'));" "unauthorized object owner restriction" || return 0
            altibase_set_result "MANUAL" "$(altibase_status_for_result MANUAL)" "Application-owned Altibase objects were found or queried; confirm owners are authorized." "${ALTIBASE_SQL_OUTPUT}" "SELECT USER_ID, TABLE_NAME FROM system_.sys_tables_"
            ;;
        D-21)
            altibase_sql_check "SELECT * FROM system_.sys_grant_object_ WHERE WITH_GRANT_OPTION = 1;" "GRANT OPTION restriction" || return 0
            if printf '%s' "${ALTIBASE_SQL_OUTPUT}" | grep -Eiq '1|WITH_GRANT'; then
                altibase_set_result "VULNERABLE" "$(altibase_status_for_result VULNERABLE)" "Altibase object privileges with grant option were found." "${ALTIBASE_SQL_OUTPUT}" "SELECT WITH_GRANT_OPTION FROM system_.sys_grant_object_"
            else
                altibase_set_result "GOOD" "$(altibase_status_for_result GOOD)" "No Altibase object privileges with grant option were returned." "${ALTIBASE_SQL_OUTPUT}" "SELECT WITH_GRANT_OPTION FROM system_.sys_grant_object_"
            fi
            ;;
        D-22)
            lines="$(altibase_config_grep 'RESOURCE|MAX_CLIENT|QUERY_TIMEOUT|IDLE_TIMEOUT|SESSION' || true)"
            [ -n "${lines}" ] && altibase_set_result "MANUAL" "$(altibase_status_for_result MANUAL)" "Altibase resource/session limit configuration evidence was found; confirm institutional threshold policy." "${lines}" "grep resource/session limits altibase.properties" || altibase_set_result "MANUAL" "$(altibase_status_for_result MANUAL)" "Altibase resource-limit evidence was not conclusive; confirm DB/session resource policy." "$(altibase_evidence)" "grep resource/session limits altibase.properties"
            ;;
        D-23)
            altibase_set_result "N/A" "N/A" "SQL Server xp_cmdshell control is not applicable to Altibase." "Altibase has no xp_cmdshell feature." "Map DBMS command-shell guideline applicability"
            ;;
        D-24)
            altibase_set_result "N/A" "N/A" "SQL Server registry extended procedure control is not applicable to Altibase." "Altibase does not expose SQL Server registry extended procedures." "Map DBMS registry-procedure guideline applicability"
            ;;
        D-25)
            if altibase_sql_check "SELECT PRODUCT_SIGNATURE FROM v\$database;" "vendor patch status"; then
                altibase_set_result "MANUAL" "$(altibase_status_for_result MANUAL)" "Altibase was found. Compare detected version and patch level against current Altibase patch guidance." "${ALTIBASE_SQL_OUTPUT}" "SELECT PRODUCT_SIGNATURE FROM v\$database"
            else
                lines="$("${ALTIBASE_HOME_FOUND}/bin/altibase" -v 2>&1 || true)"
                altibase_set_result "MANUAL" "$(altibase_status_for_result MANUAL)" "Altibase was found. Compare detected binary version against current Altibase patch guidance." "${lines}" "altibase -v"
            fi
            ;;
        D-26)
            lines="$(altibase_config_grep 'AUDIT|AUDIT_OUTPUT|AUDIT_LOG|AUDIT_FILE' || true)"
            if [ -n "${lines}" ]; then
                altibase_set_result "MANUAL" "$(altibase_status_for_result MANUAL)" "Altibase audit configuration evidence was found; confirm retention and audited events satisfy policy." "${lines}" "grep audit settings altibase.properties"
            else
                altibase_set_result "VULNERABLE" "$(altibase_status_for_result VULNERABLE)" "Altibase audit configuration evidence was not found." "$(altibase_evidence)" "grep audit settings altibase.properties"
            fi
            ;;
        *)
            altibase_set_result "MANUAL" "$(altibase_status_for_result MANUAL)" "No Altibase Linux diagnostic rule is defined for ${item_id}." "$(altibase_evidence)" "Altibase Linux generic discovery"
            ;;
    esac
}
