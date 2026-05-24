#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : D-26
# @Category    : DBMS (Database Management System)
# @Platform    : Oracle_Linux
# @Severity    : 상
# @Title       : 데이터베이스의 접근, 변경, 삭제 등의 감사 기록이 기관의 감사 기록 정책에 적합하도록 설정
# @Description : 감사 로깅 활성화로 보안 이벤트 추적 점검
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

ITEM_ID="D-26"
ITEM_NAME="데이터베이스의 접근, 변경, 삭제 등의 감사 기록이 기관의 감사 기록 정책에 적합하도록 설정"
SEVERITY="상"

GUIDELINE_PURPOSE="데이터, 로그, 응용 프로그램에 대한 감사 기록 정책을 수립하고 적용하여 데이터베이스에 문제 발생 시 원활하게 대응하기 위함"
GUIDELINE_THREAT="감사 기록 정책이 설정되어 있지 않을 경우, 데이터베이스에 문제 발생 시 원인을 규명할 수 있는 자료가 존재하지 않아 이에 대한 대처 및 개선 방안 수립이 어려워 장기적으로 심각한 보안 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="DBMS의 감사 로그 저장 정책이 수립되어 있으며, 정책 설정이 적용된 경우"
GUIDELINE_CRITERIA_BAD="DBMS에 대한 감사 로그 저장을 하지 않거나, 정책 설정이 적용되지 않은 경우"
GUIDELINE_REMEDIATION="DBMS에 대한 감사 로그 저장 정책 수립, 적용"

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

    # Oracle 서비스 확인
    if ! pgrep -x "tnslsnr" &>/dev/null && ! pgrep -x "oracle" &>/dev/null; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="Oracle 서비스 미실행"
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

    # 감사 로그 설정 확인
    local audit_query="SHOW PARAMETER audit_trail"
    command_executed="sqlplus -s "${DBMS_USER}/${DBMS_PASSWORD}@${DBMS_HOST}:${DBMS_PORT}/${DBMS_SID}" \"${audit_query}\""
    command_result=$(sqlplus -s "${DBMS_USER}/${DBMS_PASSWORD}@${DBMS_HOST}:${DBMS_PORT}/${DBMS_SID}" "${audit_query}" 2>/dev/null | grep -v "^$" | grep -v "SQL>" || echo "")

    # 결과 분석
    if echo "$command_result" | grep -qi "DB"; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="감사 로깅(audit_trail) 활성화됨 (양호)"
    elif echo "$command_result" | grep -qi "NONE"; then
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="감사 로깅 비활성화됨 (취약 - 감사 기능 활성화 권장)"
    else
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="감사 설정 확인 불가 - 수동 진단 필요: ${command_result}"
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
