#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : D-09
# @Category    : DBMS (Database Management System)
# @Platform    : Oracle_Linux
# @Severity    : 중
# @Title       : 일정 횟수의 로그인 실패 시 이에 대한 잠금 정책 설정
# @Description : DBMS 진단 항목 D-09 관련 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================


SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/command_validator.sh"
source "${LIB_DIR}/timeout_handler.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/dbms_connector.sh"
source "${LIB_DIR}/db_connection_helpers.sh"

ITEM_ID="D-09"
ITEM_NAME="일정 횟수의 로그인 실패 시 이에 대한 잠금 정책 설정"
SEVERITY="중"

GUIDELINE_PURPOSE="일정 횟수의 로그인 실패 시 계정 잠금 정책을 설정하여 비인가자의 자동화된 무차별 대입 공격, 사전 대입 공격 등을 통한 사용자 계정 비밀번호 유출을 방지하기 위함"
GUIDELINE_THREAT="일정한 횟수의 로그인 실패 횟수를 설정하여 제한하지 않으면 자동화된 방법으로 계정 및 비밀번호를 획득하여 데이터베이스에 접근하여 정보가 유출될 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="로그인 시도 횟수를 제한하는 값을 설정한 경우"
GUIDELINE_CRITERIA_BAD="로그인 시도 횟수를 제한하는 값을 설정하지 않은 경우"
GUIDELINE_REMEDIATION="로그인 시도 횟수 제한 값 설정"

diagnose() {
    echo "진단 항목: ${ITEM_ID} - ${ITEM_NAME}"

    # FR-022: Check required tools
    if ! check_oracle_tools; then
        handle_missing_tools "oracle" "${ITEM_ID}" "${ITEM_NAME}" \
            "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" \
            "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
        return 0
    fi


    local diagnosis_result="VULNERABLE"
    local status="취약"
    local inspection_summary=""
    local command_result=""
    local command_executed=""

    # Process check
    if command -v pgrep >/dev/null; then
        if ! pgrep -x "tnslsnr" > /dev/null && ! pgrep -x "oracle" > /dev/null; then
            diagnosis_result="N/A"
            status="N/A"
            inspection_summary="Oracle 서비스가 실행 중이 아닙니다."
            command_result="Oracle process not found"
            command_executed="pgrep -x tnslsnr; pgrep -x oracle"
            save_dual_result "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" "${inspection_summary}" "${command_result}" "${command_executed}" "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
            verify_result_saved "${ITEM_ID}"
            return 0
        fi
    else
        echo "[INFO] pgrep command missing, skipping process check."
    fi

    # sqlplus check
    if ! command -v sqlplus >/dev/null; then
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="Oracle SQL*Plus 클라이언트가 설치되지 않았습니다. 수동으로 확인이 필요합니다."
        command_result="sqlplus command not found"
        command_executed="command -v sqlplus"
        save_dual_result "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" "${inspection_summary}" "${command_result}" "${command_executed}" "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
        verify_result_saved "${ITEM_ID}"
        return 0
    fi

    # Connection prompt if not already connected
    if [ -z "${DBMS_HOST:-}" ] || [ -z "${DBMS_USER:-}" ]; then
        echo "[INFO] Oracle 연결 정보 입력이 필요합니다."
        prompt_dbms_connection "oracle"
    fi

    # Test connection
    if ! echo "SELECT 1 FROM DUAL;" | sqlplus -s "${DBMS_USER}/${DBMS_PASSWORD}@${DBMS_HOST}:${DBMS_PORT}/${DBMS_SID}" &>/dev/null; then
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="Oracle 연결에 실패했습니다. 연결 정보를 확인하고 다시 시도하세요."
        command_result="Connection failed"
        command_executed="sqlplus -s ${DBMS_USER}/***@${DBMS_HOST}:${DBMS_PORT}/${DBMS_SID}"
        save_dual_result "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" "${inspection_summary}" "${command_result}" "${command_executed}" "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
        verify_result_saved "${ITEM_ID}"
        return 0
    fi

    echo "[INFO] Oracle 연결 성공"

    # Query FAILED_LOGIN_ATTEMPTS from DBA_PROFILES
    # SET HEADING OFF FEEDBACK OFF PAGESIZE 0 suppresses column headers, the
    # dashed separator row, and the "n rows selected" trailer so awk parses
    # only the data row.
    local lockout_query="SET HEADING OFF
SET FEEDBACK OFF
SET PAGESIZE 0
SELECT PROFILE, LIMIT FROM DBA_PROFILES WHERE RESOURCE_NAME='FAILED_LOGIN_ATTEMPTS' AND PROFILE='DEFAULT';"
    command_executed="${lockout_query}"
    command_result=$(echo "${lockout_query}" | sqlplus -s "${DBMS_USER}/${DBMS_PASSWORD}@${DBMS_HOST}:${DBMS_PORT}/${DBMS_SID}" 2>/dev/null | grep -v "^$" | grep -v "SQL>" | grep -v '^-\{2,\}' || echo "")

    echo "[DEBUG] Query result:\n${command_result}"

    # Extract FAILED_LOGIN_ATTEMPTS value — take only the last non-empty data
    # line so any residual banner / separator line is ignored.
    local failed_attempts_line
    failed_attempts_line=$(echo "${command_result}" | grep -v '^[[:space:]]*$' | tail -n 1)
    local failed_attempts=$(echo "${failed_attempts_line}" | awk '{print $2}' | tr -d ' ')

    echo "[INFO] FAILED_LOGIN_ATTEMPTS: ${failed_attempts:-UNLIMITED}"

    # Determine result
    if [ -z "${failed_attempts}" ] || [ "${failed_attempts}" = "UNLIMITED" ] || [ "${failed_attempts}" = "DEFAULT" ]; then
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="FAILED_LOGIN_ATTEMPTS가 설정되지 않았거나 UNLIMITED입니다(현재값: ${failed_attempts:-UNLIMITED}). 로그인 실패 잠금 정책을 설정하세요."
    elif [[ "${failed_attempts}" =~ ^[0-9]+$ ]] && [ "${failed_attempts}" -gt 0 ] && [ "${failed_attempts}" -le 20 ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="로그인 실패 잠금 정책이 안전하게 설정되어 있습니다(FAILED_LOGIN_ATTEMPTS: ${failed_attempts}회)."

        # Add recommendation if value is > 10
        if [ "${failed_attempts}" -gt 10 ]; then
            inspection_summary+=" (권장: 3-10회, 현재: ${failed_attempts}회)"
        fi
    elif [[ "${failed_attempts}" =~ ^[0-9]+$ ]] && [ "${failed_attempts}" -eq 0 ]; then
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="FAILED_LOGIN_ATTEMPTS가 0으로 설정되어 있습니다. 로그인 실패 잠금 정책이 비활성화되어 있습니다."
    elif [[ "${failed_attempts}" =~ ^[0-9]+$ ]]; then
        # Numeric value > 20 (a finite limit IS set, so GOOD per the guideline)
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="로그인 실패 잠금 정책이 설정되어 있습니다(FAILED_LOGIN_ATTEMPTS: ${failed_attempts}회). (권장: 3-10회, 현재: ${failed_attempts}회)"
    else
        # Non-numeric, non-UNLIMITED, non-DEFAULT value (parse anomaly or
        # unexpected sqlplus output). Route to MANUAL — never silently GOOD.
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="FAILED_LOGIN_ATTEMPTS 값을 해석할 수 없습니다(현재값: ${failed_attempts}). sqlplus 출력 형식을 수동으로 확인하세요."
    fi

    save_dual_result "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" "${inspection_summary}" "${command_result}" "${command_executed}" "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
    verify_result_saved "${ITEM_ID}"
    return 0
}

main() {
    diagnose
}

if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi
