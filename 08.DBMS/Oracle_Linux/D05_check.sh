#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : D-05
# @Category    : DBMS (Database Management System)
# @Platform    : Oracle_Linux
# @Severity    : 중
# @Title       : 비밀번호 재사용에 대한 제약 설정
# @Description : DBMS 진단 항목 D-05 관련 점검
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

ITEM_ID="D-05"
ITEM_NAME="비밀번호 재사용에 대한 제약 설정"
SEVERITY="중"

GUIDELINE_PURPOSE="비밀번호 재사용 제약 설정 적용 여부를 점검하여 비밀번호 변경 시 이전 비밀번호 재사용을 제약하여 형식적인 비밀번호 변경을 원천적으로 차단하기 위함"
GUIDELINE_THREAT="비밀번호 재사용 제약 설정이 적용되어 있지 않을 경우 비밀번호 변경 전 사용했던 비밀번호를 재사용함으로써 비인가자의 계정 비밀번호 추측 공격에 대한 시간을 더 많이 허용하여 비밀번호 유출 위험이 증가함"
GUIDELINE_CRITERIA_GOOD="비밀번호 재사용 제한 설정을 적용한 경우"
GUIDELINE_CRITERIA_BAD="비밀번호 재사용 제한 설정을 적용하지 않은 경우"
GUIDELINE_REMEDIATION="PASSWORD _REUSE _TIME, PASSWORD _REUSE _MAX 파라미터 설정"

diagnose() {
    echo "진단 항목: ${ITEM_ID} - ${ITEM_NAME}"

    # FR-022: Check required tools
    if ! check_oracle_tools; then
        handle_missing_tools "oracle" "${ITEM_ID}" "${ITEM_NAME}" \
            "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" \
            "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
        return 0
    fi


    local diagnosis_result="MANUAL"
    local status="수동진단"
    local inspection_summary=""
    local command_result=""
    local command_executed=""

    # Process check
    if command -v pgrep >/dev/null; then
        if ! pgrep -x "tnslsnr" > /dev/null && ! pgrep -x "oracle" > /dev/null; then
            diagnosis_result="MANUAL"
            status="수동진단"
            inspection_summary="Oracle 서비스가 실행 중이지 않습니다. 서비스 시작 후 수동으로 확인이 필요합니다."
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

    # Connection prompt if not already connected (FR-018)
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

    # Query PASSWORD_REUSE_MAX and PASSWORD_REUSE_TIME from DBA_PROFILES
    local reuse_query="SELECT PROFILE, RESOURCE_NAME, LIMIT FROM DBA_PROFILES WHERE RESOURCE_NAME IN ('PASSWORD_REUSE_MAX', 'PASSWORD_REUSE_TIME') AND PROFILE='DEFAULT';"
    command_executed="${reuse_query}"
    command_result=$(echo "${reuse_query}" | sqlplus -s "${DBMS_USER}/${DBMS_PASSWORD}@${DBMS_HOST}:${DBMS_PORT}/${DBMS_SID}" 2>/dev/null | grep -v "^$" | grep -v "SQL>" | tail -n +2 || echo "")

    echo "[DEBUG] Query result:\n${command_result}"

    # Check PASSWORD_REUSE_MAX
    local reuse_max=$(echo "${command_result}" | grep "PASSWORD_REUSE_MAX" | awk '{print $3}' | tr -d ' ')
    local reuse_time=$(echo "${command_result}" | grep "PASSWORD_REUSE_TIME" | awk '{print $3}' | tr -d ' ')

    echo "[INFO] PASSWORD_REUSE_MAX: ${reuse_max:-UNLIMITED}"
    echo "[INFO] PASSWORD_REUSE_TIME: ${reuse_time:-UNLIMITED}"

    # Determine result based on KISA guideline
    # PASSWORD_REUSE_MAX와 PASSWORD_REUSE_TIME이 UNLIMITED이면 취약
    if [ -z "${reuse_max}" ] || [ "${reuse_max}" = "UNLIMITED" ] || [ "${reuse_max}" = "DEFAULT" ]; then
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="PASSWORD_REUSE_MAX가 설정되지 않았거나 UNLIMITED입니다(현재값: ${reuse_max:-UNLIMITED}). 비밀번호 재사용 제약을 설정하세요."
    elif [ -z "${reuse_time}" ] || [ "${reuse_time}" = "UNLIMITED" ] || [ "${reuse_time}" = "DEFAULT" ]; then
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="PASSWORD_REUSE_TIME이 설정되지 않았거나 UNLIMITED입니다(현재값: ${reuse_time:-UNLIMITED}). 비밀번호 재사용 제약을 설정하세요."
    else
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="비밀번호 재사용 제약이 안전하게 설정되어 있습니다(PASSWORD_REUSE_MAX: ${reuse_max}, PASSWORD_REUSE_TIME: ${reuse_time})."
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
