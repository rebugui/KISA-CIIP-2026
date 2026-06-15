#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : D-04
# @Category    : DBMS (Database Management System)
# @Platform    : Oracle_Linux
# @Severity    : 상
# @Title       : 데이터베이스 관리자 권한을 꼭 필요한 계정 및 그룹에 대해서만 허용
# @Description : DBMS 진단 항목 D-04 관련 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../../lib"

# Oracle 연결 정보 초기화 (fallback if library not loaded)
ORACLE_USER="${ORACLE_USER:-system}"
ORACLE_PASSWORD="${ORACLE_PASSWORD:-manager}"
ORACLE_HOST="${ORACLE_HOST:-localhost}"
ORACLE_PORT="${ORACLE_PORT:-1521}"
ORACLE_SID="${ORACLE_SID:-ORCL}"
ORACLE_SYSDBA="${ORACLE_SYSDBA:-sys as sysdba}"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/command_validator.sh"
source "${LIB_DIR}/timeout_handler.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/dbms_connector.sh"
source "${LIB_DIR}/db_connection_helpers.sh"

ITEM_ID="D-04"
ITEM_NAME="데이터베이스 관리자 권한을 꼭 필요한 계정 및 그룹에 대해서만 허용"
SEVERITY="상"

GUIDELINE_PURPOSE="관리자 권한이 필요한 계정과 그룹에만 관리자 권한을 부여하였는지 점검하여 관리자 권한의 남용을 방지하여 계정 유출로 인한 비인가자의 DB 접근 가능성을 최소화하고자함"
GUIDELINE_THREAT="관리자 권한이 필요한 계정 및 그룹에만 관리자 권한을 부여하지 않으면 관리자 권한이 부여된 계정이 비인가자에게 유출될 경우 DB에 접근할 수 있는 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="관리자 권한이 필요한 계정 및 그룹에만 관리자 권한이 부여된 경우"
GUIDELINE_CRITERIA_BAD="관리자 권한이 필요 없는 계정 및 그룹에 관리자 권한이 부여된 경우"
GUIDELINE_REMEDIATION="관리자 권한이 필요한 계정 및 그룹에만 관리자 권한 부여"

diagnose() {
    diagnosis_result="unknown"  # Global variable (not local)
    local status="수동진단"
    local inspection_summary=""
    local command_result=""
    local command_executed=""

    # Initialize Oracle connection variables (only if library function exists)
    if declare -f init_oracle_vars >/dev/null 2>&1; then
        init_oracle_vars
    fi

    # Oracle 서비스 확인 (서비스 미실행 시 자동 점검 불가 -> 수동진단)
    if ! pgrep -x "tnslsnr" &>/dev/null && ! pgrep -x "oracle" &>/dev/null; then
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="서비스 미실행으로 자동 점검 불가 (수동진단 필요). 서비스 시작 후 관리자 권한 부여 계정을 수동으로 확인하세요."
        command_result="Oracle process not found"
        command_executed="pgrep -x tnslsnr; pgrep -x oracle"
        if declare -f save_dual_result >/dev/null 2>&1; then
            save_dual_result "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" "${inspection_summary}" "${command_result}" "${command_executed}" "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
        fi
        if declare -f verify_result_saved >/dev/null 2>&1; then
            verify_result_saved "${ITEM_ID}"
        fi
        return 0
    fi

    # sqlplus check
    if ! command -v sqlplus &>/dev/null; then
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="Oracle SQL*Plus 클라이언트가 설치되지 않았습니다. 수동으로 확인이 필요합니다."
        command_result="sqlplus command not found"
        command_executed="command -v sqlplus"
        if declare -f save_dual_result >/dev/null 2>&1; then
            save_dual_result "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" "${inspection_summary}" "${command_result}" "${command_executed}" "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
        fi
        if declare -f verify_result_saved >/dev/null 2>&1; then
            verify_result_saved "${ITEM_ID}"
        fi
        return 0
    fi

    # FR-022: Check required tools (only if library function exists)
    if declare -f check_oracle_tools >/dev/null 2>&1; then
        if ! check_oracle_tools; then
            if declare -f handle_missing_tools >/dev/null 2>&1; then
                handle_missing_tools "oracle" "${ITEM_ID}" "${ITEM_NAME}" \
                    "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" \
                    "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
            fi
            return 0
        fi
    fi

    # Connection prompt if not already connected (FR-018)
    if [ -z "${DBMS_HOST:-}" ] || [ -z "${DBMS_USER:-}" ]; then
        echo "[INFO] Oracle 연결 정보 입력이 필요합니다."
        if declare -f prompt_dbms_connection >/dev/null 2>&1; then
            prompt_dbms_connection "oracle"
        fi
    else
        # Use environment variables for batch mode
        DBMS_HOST="${DBMS_HOST:-${ORACLE_HOST:-localhost}}"
        DBMS_USER="${DBMS_USER:-${ORACLE_USER:-system}}"
        DBMS_PASSWORD="${DBMS_PASSWORD:-${ORACLE_PASSWORD:-manager}}"
        DBMS_PORT="${DBMS_PORT:-${ORACLE_PORT:-1521}}"
        DBMS_SID="${DBMS_SID:-${ORACLE_SID:-ORCL}}"
        export DBMS_HOST DBMS_USER DBMS_PASSWORD DBMS_PORT DBMS_SID
    fi

    # Test connection
    if ! echo "SELECT 1 FROM DUAL;" | sqlplus -s "${DBMS_USER}/${DBMS_PASSWORD}@${DBMS_HOST}:${DBMS_PORT}/${DBMS_SID}" &>/dev/null; then
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="Oracle 연결에 실패했습니다. 연결 정보를 확인하고 다시 시도하세요."
        command_result="Connection failed"
        command_executed="sqlplus -s ${DBMS_USER}/***@${DBMS_HOST}:${DBMS_PORT}/${DBMS_SID}"
        if declare -f save_dual_result >/dev/null 2>&1; then
            save_dual_result "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" "${inspection_summary}" "${command_result}" "${command_executed}" "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
        fi
        if declare -f verify_result_saved >/dev/null 2>&1; then
            verify_result_saved "${ITEM_ID}"
        fi
        return 0
    fi

    echo "[INFO] Oracle 연결 성공"
    echo "진단 항목: ${ITEM_ID} - ${ITEM_NAME}"

    local vulnerabilities_found=0
    local query_error=0

    # Step 1) SYSDBA 권한 점검 - KISA 가이드: v$pwfile_users (dba_sys_privs 에는 SYSDBA 가 없음)
    #   DBA Role 미보유 + SYSDBA='TRUE' + INTERNAL 제외 계정이 나오면 취약
    local sysdba_query="SET HEADING OFF FEEDBACK OFF PAGESIZE 0 LINESIZE 200
SELECT username FROM v\$pwfile_users WHERE username NOT IN (SELECT grantee FROM dba_role_privs WHERE granted_role='DBA') AND username != 'INTERNAL' AND SYSDBA = 'TRUE';"
    local sysdba_result
    sysdba_result=$(echo "${sysdba_query}" | sqlplus -s "${DBMS_USER}/${DBMS_PASSWORD}@${DBMS_HOST}:${DBMS_PORT}/${DBMS_SID}" 2>&1 || true)

    if echo "${sysdba_result}" | grep -qiE 'ORA-[0-9]+|SP2-[0-9]+|ERROR|TNS-[0-9]+'; then
        query_error=1
    else
        local sysdba_list
        sysdba_list=$(echo "${sysdba_result}" | sed '/^[[:space:]]*$/d' | grep -viE 'no rows selected|SQL>' | sed 's/[[:space:]]//g' | grep -v '^$' || true)
        local sysdba_count
        sysdba_count=$(echo "${sysdba_list}" | grep -c '.' || true)
        if [ "${sysdba_count}" -gt 0 ]; then
            ((vulnerabilities_found++)) || true
            inspection_summary+="취약: 비인가 SYSDBA 권한 계정 ${sysdba_count}개 발견($(echo "${sysdba_list}" | head -5 | tr '\n' ',' )); "
        else
            inspection_summary+="SYSDBA 권한 인가 계정만 보유; "
        fi
    fi

    # Step 2) Admin 부적합 계정(admin_option='YES') 점검 - dba_sys_privs (비SYSDBA 시스템 권한)
    local admin_query="SET HEADING OFF FEEDBACK OFF PAGESIZE 0 LINESIZE 200
SELECT grantee FROM dba_sys_privs WHERE grantee NOT IN ('SYS','SYSTEM','AQ_ADMINISTRATOR_ROLE','DBA','DSYS','BACSYS','SCHEDULER_ADMIN','MSYS') AND admin_option='YES' AND grantee NOT IN (SELECT grantee FROM dba_role_privs WHERE granted_role='DBA');"
    local admin_result
    admin_result=$(echo "${admin_query}" | sqlplus -s "${DBMS_USER}/${DBMS_PASSWORD}@${DBMS_HOST}:${DBMS_PORT}/${DBMS_SID}" 2>&1 || true)
    command_executed="echo \"<v\$pwfile_users SYSDBA query; dba_sys_privs admin_option query>\" | sqlplus -s ${DBMS_USER}/***@${DBMS_HOST}:${DBMS_PORT}/${DBMS_SID}"
    command_result="${sysdba_result}"$'\n'"${admin_result}"

    if echo "${admin_result}" | grep -qiE 'ORA-[0-9]+|SP2-[0-9]+|ERROR|TNS-[0-9]+'; then
        query_error=1
    else
        local admin_list
        admin_list=$(echo "${admin_result}" | sed '/^[[:space:]]*$/d' | grep -viE 'no rows selected|SQL>' | sed 's/[[:space:]]//g' | grep -v '^$' || true)
        local admin_count
        admin_count=$(echo "${admin_list}" | grep -c '.' || true)
        if [ "${admin_count}" -gt 0 ]; then
            ((vulnerabilities_found++)) || true
            inspection_summary+="취약: 불필요 계정에 ADMIN_OPTION 시스템 권한 부여 ${admin_count}개($(echo "${admin_list}" | head -5 | tr '\n' ',' )); "
        else
            inspection_summary+="비인가 ADMIN_OPTION 시스템 권한 없음; "
        fi
    fi

    if [ "${query_error}" -eq 1 ]; then
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="Oracle 접속/쿼리 실행 실패로 자동 판단 불가 (수동진단 필요). 확인: v\$pwfile_users(SYSDBA), dba_sys_privs(admin_option='YES')."
    elif [ $vulnerabilities_found -gt 0 ]; then
        diagnosis_result="VULNERABLE"
        status="취약"
    else
        diagnosis_result="GOOD"
        status="양호"
        if [ -z "$inspection_summary" ]; then
            inspection_summary="관리자 권한이 인가된 계정 및 그룹에만 부여됨"
        fi
    fi

    if declare -f save_dual_result >/dev/null 2>&1; then
        save_dual_result "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" "${inspection_summary}" "${command_result}" "${command_executed}" "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
    fi
    if declare -f verify_result_saved >/dev/null 2>&1; then
        verify_result_saved "${ITEM_ID}"
    fi

    return 0
}

main() {
    diagnose
}

if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi
