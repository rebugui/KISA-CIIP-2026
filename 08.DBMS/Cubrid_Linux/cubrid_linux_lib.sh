#!/bin/bash

cubrid_set_result() {
    diagnosis_result="$1"
    status="$2"
    inspection_summary="$3"
    command_result="$4"
    command_executed="$5"
}

cubrid_status_for_result() {
    case "$1" in
        GOOD) printf '%s' "양호" ;;
        VULNERABLE) printf '%s' "취약" ;;
        N/A) printf '%s' "N/A" ;;
        *) printf '%s' "수동진단" ;;
    esac
}

cubrid_add_unique() {
    local value="$1"
    local existing
    [ -n "${value}" ] || return 0
    for existing in "${CUBRID_UNIQUE_TMP[@]:-}"; do
        [ "${existing}" = "${value}" ] && return 0
    done
    CUBRID_UNIQUE_TMP+=("${value}")
}

cubrid_find_home() {
    if [ -n "${CUBRID:-}" ] && [ -d "${CUBRID}" ]; then
        printf '%s\n' "${CUBRID}"
        return 0
    fi
    for candidate in /home/*/cubrid /home/*/CUBRID /opt/cubrid /usr/local/cubrid /CUBRID /cubrid; do
        [ -d "${candidate}" ] && printf '%s\n' "${candidate}" && return 0
    done
    return 1
}

cubrid_process_evidence() {
    ps -eo user=,pid=,comm=,args= 2>/dev/null |
        awk 'BEGIN { IGNORECASE = 1 } {
            comm = $3
            if (comm ~ /^(cub_master|cub_broker|cub_server|cub_manager|csql|cubrid|cubrid_rel)$/ && $0 ~ /(cubrid|CUBRID|cub_master|cub_broker|cub_server)/) {
                print $0
            }
        }' || true
}

cubrid_collect_state() {
    CUBRID_HOME_FOUND="$(cubrid_find_home || true)"
    CUBRID_PROCESS_EVIDENCE="$(cubrid_process_evidence)"
    CUBRID_CSQL="$(command -v csql 2>/dev/null || true)"
    CUBRID_REL="$(command -v cubrid_rel 2>/dev/null || true)"
    CUBRID_CONFIGS=()

    if [ -z "${CUBRID_CSQL}" ] && [ -n "${CUBRID_HOME_FOUND}" ] && [ -x "${CUBRID_HOME_FOUND}/bin/csql" ]; then
        CUBRID_CSQL="${CUBRID_HOME_FOUND}/bin/csql"
    fi
    if [ -z "${CUBRID_REL}" ] && [ -n "${CUBRID_HOME_FOUND}" ] && [ -x "${CUBRID_HOME_FOUND}/bin/cubrid_rel" ]; then
        CUBRID_REL="${CUBRID_HOME_FOUND}/bin/cubrid_rel"
    fi

    if [ -n "${CUBRID_HOME_FOUND}" ]; then
        CUBRID_UNIQUE_TMP=()
        for file in "${CUBRID_HOME_FOUND}/conf/cubrid.conf" "${CUBRID_HOME_FOUND}/conf/cubrid_broker.conf" "${CUBRID_HOME_FOUND}/conf/databases.txt" "${CUBRID_HOME_FOUND}/databases/databases.txt"; do
            [ -f "${file}" ] && cubrid_add_unique "${file}"
        done
        if [ "${#CUBRID_UNIQUE_TMP[@]}" -gt 0 ]; then
            CUBRID_CONFIGS=("${CUBRID_UNIQUE_TMP[@]}")
        fi
        unset CUBRID_UNIQUE_TMP
    fi
}

cubrid_is_installed() {
    [ -n "${CUBRID_HOME_FOUND:-}" ] && return 0
    [ -n "${CUBRID_PROCESS_EVIDENCE:-}" ] && return 0
    return 1
}

cubrid_evidence() {
    {
        [ -n "${CUBRID_HOME_FOUND:-}" ] && printf 'CUBRID_HOME: %s\n' "${CUBRID_HOME_FOUND}"
        [ "${#CUBRID_CONFIGS[@]}" -gt 0 ] && printf 'ConfigFiles: %s\n' "${CUBRID_CONFIGS[*]}"
        [ -n "${CUBRID_CSQL:-}" ] && printf 'CsqlPath: %s\n' "${CUBRID_CSQL}"
        [ -n "${CUBRID_REL:-}" ] && printf 'RelPath: %s\n' "${CUBRID_REL}"
        [ -n "${CUBRID_PROCESS_EVIDENCE:-}" ] && printf 'Processes:\n%s\n' "${CUBRID_PROCESS_EVIDENCE}"
    } | sed '/^$/d'
}

cubrid_acl_check() {
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
            local octal="${mode%% *}"
            local group_digit="${octal: -2:1}"
            local other_digit="${octal: -1}"
            # guideline(docs/09_DBMS.md D-14, criteria_good): 디렉터리는 일반 사용자의
            # '수정(write) 권한 제거'만 양호 기준(예: $ORACLE_HOME/network, /lib 가 755 로 정상).
            # 디렉터리 대상은 group/other write 비트(2,3,6,7)만 취약 판정(r/x 노출은 허용).
            if [ -d "${target}" ]; then
                case "${group_digit}" in
                    2|3|6|7) bad+="${mode}"$'\n' ; continue ;;
                esac
                case "${other_digit}" in
                    2|3|6|7) bad+="${mode}"$'\n' ;;
                esac
                continue
            fi
            # 자격증명 포함 설정 파일은 일반 사용자(other)의 read 노출도 취약(640 초과).
            # other(마지막 자릿수)가 0 이외(read=4/exec=1/write=2 모두)면 취약.
            # other=0 일 때에만 group write(2,3,6,7) 추가 점검(640 기준 group r 까지 허용).
            case "${other_digit}" in
                1|2|3|4|5|6|7) bad+="${mode}"$'\n' ; continue ;;
            esac
            case "${group_digit}" in
                2|3|6|7) bad+="${mode}"$'\n' ;;
            esac
        fi
    done
    if [ -n "${bad}" ]; then
        cubrid_set_result "VULNERABLE" "$(cubrid_status_for_result VULNERABLE)" "Broad write permission evidence was found on CUBRID ${role} paths." "${bad}" "stat CUBRID ${role} paths"
    elif [ -n "${checked}" ]; then
        cubrid_set_result "GOOD" "$(cubrid_status_for_result GOOD)" "No broad write permission evidence was found on assessed CUBRID ${role} paths." "${checked}" "stat CUBRID ${role} paths"
    else
        cubrid_set_result "MANUAL" "$(cubrid_status_for_result MANUAL)" "CUBRID ${role} paths were not found for permission assessment." "$(cubrid_evidence)" "stat CUBRID ${role} paths"
    fi
}

cubrid_query() {
    local query="$1"
    if [ -z "${CUBRID_CSQL:-}" ]; then
        printf '%s\n' "csql client was not found."
        return 127
    fi
    local db="${CUBRID_DB:-${DB_NAME:-demodb}}"
    local user="${CUBRID_USER:-${DB_USER:-dba}}"
    local args=("-u" "${user}")
    if [ -n "${CUBRID_PASSWORD:-${DB_PASSWORD:-}}" ]; then
        args+=("-p" "${CUBRID_PASSWORD:-${DB_PASSWORD:-}}")
    fi
    args+=("-c" "${query}" "${db}")
    CUBRID_LAST_COMMAND="${CUBRID_CSQL} -u ${user} -c <query> ${db}"
    "${CUBRID_CSQL}" "${args[@]}" 2>&1
}

cubrid_sql_check() {
    local query="$1"
    local description="$2"
    local output
    local code
    output="$(cubrid_query "${query}")"
    code=$?
    if [ "${code}" -ne 0 ] || printf '%s' "${output}" | grep -Eiq 'ERROR|failed|Cannot connect|not found'; then
        cubrid_set_result "MANUAL" "$(cubrid_status_for_result MANUAL)" "CUBRID was found, but SQL evidence for ${description} could not be collected automatically." "$(printf 'Discovery evidence:\n%s\n\nSQL output:\n%s' "$(cubrid_evidence)" "${output}")" "${CUBRID_LAST_COMMAND:-csql client discovery}"
        return 1
    fi
    CUBRID_SQL_OUTPUT="${output}"
    return 0
}

cubrid_not_targeted() {
    local item_id="$1"
    local summary="$2"
    cubrid_set_result "N/A" "N/A" "${summary}" "${item_id} target excludes CUBRID or has no CUBRID-equivalent control." "Map DBMS guideline applicability"
}

invoke_cubrid_linux_check() {
    local item_id="$1"
    cubrid_collect_state
    if ! cubrid_is_installed; then
        cubrid_set_result "N/A" "N/A" "CUBRID service/process/home evidence was not found." "No CUBRID process or CUBRID home evidence found." "ps -eo user,pid,args; inspect CUBRID env"
        return 0
    fi

    local lines
    case "${item_id}" in
        D-01)
            cubrid_sql_check "SELECT name, password FROM db_user;" "default account password policy" || return 0
            if printf '%s' "${CUBRID_SQL_OUTPUT}" | grep -Eiq '^dba[[:space:]]+($|NULL|[[:space:]]*$)'; then
                cubrid_set_result "VULNERABLE" "$(cubrid_status_for_result VULNERABLE)" "CUBRID DBA/default account appears to have an empty password." "${CUBRID_SQL_OUTPUT}" "${CUBRID_LAST_COMMAND}"
            else
                cubrid_set_result "MANUAL" "$(cubrid_status_for_result MANUAL)" "CUBRID user password evidence was collected; confirm default account password policy." "${CUBRID_SQL_OUTPUT}" "${CUBRID_LAST_COMMAND}"
            fi
            ;;
        D-02)
            cubrid_sql_check "SELECT name FROM db_user WHERE name IN ('public','dba','test','demo') OR name LIKE 'test%';" "unnecessary account removal" || return 0
            if printf '%s' "${CUBRID_SQL_OUTPUT}" | grep -Eiq '^(test|demo)'; then
                cubrid_set_result "VULNERABLE" "$(cubrid_status_for_result VULNERABLE)" "Unnecessary CUBRID sample/test accounts were found." "${CUBRID_SQL_OUTPUT}" "${CUBRID_LAST_COMMAND}"
            else
                cubrid_set_result "MANUAL" "$(cubrid_status_for_result MANUAL)" "CUBRID default/public accounts exist; confirm only required accounts remain." "${CUBRID_SQL_OUTPUT}" "${CUBRID_LAST_COMMAND}"
            fi
            ;;
        D-04)
            cubrid_sql_check "SELECT g.name FROM db_authorization a, db_user g WHERE a.grantee = g.name;" "administrator privilege restriction" || return 0
            cubrid_set_result "MANUAL" "$(cubrid_status_for_result MANUAL)" "CUBRID authorization evidence was collected; confirm only approved administrators have privileged roles." "${CUBRID_SQL_OUTPUT}" "${CUBRID_LAST_COMMAND}"
            ;;
        D-07)
            lines="${CUBRID_PROCESS_EVIDENCE}"
            if printf '%s' "${lines}" | grep -Eiq '^[[:space:]]*root[[:space:]]'; then
                cubrid_set_result "VULNERABLE" "$(cubrid_status_for_result VULNERABLE)" "CUBRID processes appear to run as root." "${lines}" "Inspect CUBRID process owner"
            elif [ -n "${lines}" ]; then
                cubrid_set_result "GOOD" "$(cubrid_status_for_result GOOD)" "CUBRID processes are not obviously running as root." "${lines}" "Inspect CUBRID process owner"
            else
                cubrid_set_result "MANUAL" "$(cubrid_status_for_result MANUAL)" "CUBRID process owner could not be determined." "$(cubrid_evidence)" "Inspect CUBRID process owner"
            fi
            ;;
        D-14)
            cubrid_acl_check "home/config" "${CUBRID_HOME_FOUND}" "${CUBRID_CONFIGS[@]}"
            ;;
        D-18)
            cubrid_sql_check "SELECT name FROM db_user WHERE name='PUBLIC';" "public role restriction" || return 0
            if printf '%s' "${CUBRID_SQL_OUTPUT}" | grep -Eiq '^PUBLIC'; then
                cubrid_set_result "MANUAL" "$(cubrid_status_for_result MANUAL)" "CUBRID PUBLIC role/user evidence exists; confirm application/DBA roles are not assigned broadly." "${CUBRID_SQL_OUTPUT}" "${CUBRID_LAST_COMMAND}"
            else
                cubrid_set_result "GOOD" "$(cubrid_status_for_result GOOD)" "No CUBRID PUBLIC role/user evidence was returned." "${CUBRID_SQL_OUTPUT}" "${CUBRID_LAST_COMMAND}"
            fi
            ;;
        D-25)
            if [ -n "${CUBRID_REL}" ]; then
                lines="$("${CUBRID_REL}" 2>&1 || true)"
                cubrid_set_result "MANUAL" "$(cubrid_status_for_result MANUAL)" "CUBRID was found. Compare detected version and patch level against current CUBRID release notes." "${lines}" "${CUBRID_REL}"
            else
                cubrid_set_result "MANUAL" "$(cubrid_status_for_result MANUAL)" "CUBRID was found, but cubrid_rel was not found. Confirm version and patch level manually." "$(cubrid_evidence)" "cubrid_rel discovery"
            fi
            ;;
        D-03) cubrid_not_targeted "${item_id}" "Password lifetime and complexity item is not explicitly targeted to CUBRID in the guideline metadata." ;;
        D-05) cubrid_not_targeted "${item_id}" "Password reuse item is not explicitly targeted to CUBRID in the guideline metadata." ;;
        D-06) cubrid_not_targeted "${item_id}" "Individual DB account assignment item is not explicitly targeted to CUBRID in the guideline metadata." ;;
        D-08) cubrid_not_targeted "${item_id}" "Transport encryption item is not explicitly targeted to CUBRID in the guideline metadata." ;;
        D-09) cubrid_not_targeted "${item_id}" "Failed-login lockout item is not explicitly targeted to CUBRID in the guideline metadata." ;;
        D-10) cubrid_not_targeted "${item_id}" "Remote DB access restriction item is not explicitly targeted to CUBRID in the guideline metadata." ;;
        D-11) cubrid_not_targeted "${item_id}" "System table access restriction item is not explicitly targeted to CUBRID in the guideline metadata." ;;
        D-12) cubrid_not_targeted "${item_id}" "Oracle listener password control is not applicable to CUBRID." ;;
        D-13) cubrid_not_targeted "${item_id}" "Unnecessary ODBC/OLE-DB driver cleanup item is not explicitly targeted to CUBRID in the guideline metadata." ;;
        D-15) cubrid_not_targeted "${item_id}" "Oracle listener log/trace modification control is not applicable to CUBRID." ;;
        D-16) cubrid_not_targeted "${item_id}" "SQL Server Windows authentication mode control is not applicable to CUBRID." ;;
        D-17) cubrid_not_targeted "${item_id}" "AuditTable DBA-only access item is not explicitly targeted to CUBRID in the guideline metadata." ;;
        D-19) cubrid_not_targeted "${item_id}" "Oracle OS role parameters are not applicable to CUBRID." ;;
        D-20) cubrid_not_targeted "${item_id}" "Unauthorized object owner item is not explicitly targeted to CUBRID in the guideline metadata." ;;
        D-21) cubrid_not_targeted "${item_id}" "GRANT OPTION restriction item is not explicitly targeted to CUBRID in the guideline metadata." ;;
        D-22) cubrid_not_targeted "${item_id}" "Resource limit item is not explicitly targeted to CUBRID in the guideline metadata." ;;
        D-23) cubrid_not_targeted "${item_id}" "SQL Server xp_cmdshell control is not applicable to CUBRID." ;;
        D-24) cubrid_not_targeted "${item_id}" "SQL Server registry extended procedure control is not applicable to CUBRID." ;;
        D-26) cubrid_not_targeted "${item_id}" "Audit logging item is not explicitly targeted to CUBRID in the guideline metadata." ;;
        *)
            cubrid_set_result "MANUAL" "$(cubrid_status_for_result MANUAL)" "No CUBRID Linux diagnostic rule is defined for ${item_id}." "$(cubrid_evidence)" "CUBRID Linux generic discovery"
            ;;
    esac
}
