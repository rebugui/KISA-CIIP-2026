#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : D-18
# @Category    : DBMS (Database Management System)
# @Platform    : Oracle_Linux
# @Severity    : 상
# @Title       : 응용 프로그램 또는 DBA 계정의 Role이 Public으로 설정되지 않도록 조정
# @Description : Public role에 부여된 불필요한 권한 확인 및 제거
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/command_validator.sh"
source "${LIB_DIR}/timeout_handler.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/dbms_connector.sh"
source "${LIB_DIR}/db_connection_helpers.sh"

# Oracle 연결 정보 초기화 (fallback if library not loaded)
ORACLE_USER="${ORACLE_USER:-system}"
ORACLE_PASSWORD="${ORACLE_PASSWORD:-manager}"
ORACLE_HOST="${ORACLE_HOST:-localhost}"
ORACLE_PORT="${ORACLE_PORT:-1521}"
ORACLE_SID="${ORACLE_SID:-ORCL}"
ORACLE_SYSDBA="${ORACLE_SYSDBA:-sys as sysdba}"

ITEM_ID="D-18"
ITEM_NAME="응용 프로그램 또는 DBA 계정의 Role이 Public으로 설정되지 않도록 조정"
SEVERITY="상"

GUIDELINE_PURPOSE="응용 프로그램 또는 DBA 계정의 Role을 점검하여 일반 계정으로 응용 프로그램 테이블이나 DBA 테이블의 접근을 차단하기 위함"
GUIDELINE_THREAT="응용 프로그램 또는 DBA 계정의 Role이 Public으로 설정된 경우 일반 계정에서도 응용 프로그램 테이블 및 DBA 테이블로 접근할 수 있으므로 중요 정보 유출의 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="DBA 계정의 Role이 Public으로 설정되지 않은 경우"
GUIDELINE_CRITERIA_BAD="DBA 계정의 Role이 Public으로 설정된 경우"
GUIDELINE_REMEDIATION="DBA 계정의 Role 설정에서 Public 그룹 권한 취소"

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

    echo "진단 항목: ${ITEM_ID} - ${ITEM_NAME}"

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

    local diagnosis_result="MANUAL" status="수동진단" inspection_summary="" command_result="" command_executed=""

    if ! systemctl is-active oracle &>/dev/null && ! pgrep -f "ora_pmon" &>/dev/null; then
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="서비스 미실행으로 자동 점검 불가 (수동진단 필요). 서비스 시작 후 PUBLIC 에 부여된 Role 을 수동으로 확인하세요."
        command_result="Oracle process not found"
        command_executed="systemctl is-active oracle; pgrep -f ora_pmon"
        if declare -f save_dual_result >/dev/null 2>&1; then
            save_dual_result "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" "${inspection_summary}" "${command_result}" "${command_executed}" "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
        fi
        if declare -f verify_result_saved >/dev/null 2>&1; then
            verify_result_saved "${ITEM_ID}"
        fi
        return 0
    fi

    # D-18 판단기준 (KISA 가이드 docs/09_DBMS.md / guideline_metadata.json):
    #   양호: DBA 계정의 Role이 Public으로 설정되지 않은 경우
    #   취약: DBA 계정의 Role이 Public으로 설정된 경우
    # 확인 쿼리: SELECT granted_role FROM dba_role_privs WHERE grantee = 'PUBLIC';
    #   -> 한 건이라도 반환되면 PUBLIC 에 Role 이 부여된 것이므로 취약
    command_executed="SELECT granted_role FROM dba_role_privs WHERE grantee = 'PUBLIC';"

    local query_output=""
    # set -euo pipefail 안전성 유지: 쿼리 실패 시에도 중단되지 않도록 || true
    query_output=$(echo "SET HEADING OFF FEEDBACK OFF PAGESIZE 0 LINESIZE 200
SELECT granted_role FROM dba_role_privs WHERE grantee = 'PUBLIC';" \
        | sqlplus -s "${ORACLE_USER}/${ORACLE_PASSWORD}@${ORACLE_HOST}:${ORACLE_PORT}/${ORACLE_SID}" 2>&1 || true)

    if echo "${query_output}" | grep -qiE 'ORA-[0-9]+|SP2-[0-9]+|ERROR|TNS-[0-9]+'; then
        # 쿼리 실행 실패(접속 오류 등): 자동 판단 불가 -> 수동진단
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="Oracle 접속/쿼리 실행 실패로 자동 판단 불가 (수동진단 필요). 확인 쿼리: SELECT granted_role FROM dba_role_privs WHERE grantee = 'PUBLIC';"
        command_result="${query_output}"
    else
        # 빈 줄/공백 제거 후 실제 role 행 존재 여부 판단
        local role_rows
        role_rows=$(echo "${query_output}" | sed 's/[[:space:]]//g' | grep -c '.' || true)
        command_result="${query_output}"
        if [ "${role_rows}" -gt 0 ]; then
            diagnosis_result="VULNERABLE"
            status="취약"
            inspection_summary="PUBLIC 에 부여된 Role 발견 (${role_rows}건). 조치: REVOKE [Role name] FROM PUBLIC;"
        else
            diagnosis_result="GOOD"
            status="양호"
            inspection_summary="PUBLIC 에 부여된 Role 없음 (DBA 계정 Role 이 Public 으로 설정되지 않음)"
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
