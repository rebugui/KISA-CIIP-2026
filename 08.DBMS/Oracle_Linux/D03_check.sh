#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : D-03
# @Category    : DBMS (Database Management System)
# @Platform    : Oracle
# @Severity    : 중
# @Title       : DBMS 진단 항목 D-03
# @Description : DBMS 진단 항목 D-03 관련 점검
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

ITEM_ID="D-03"
ITEM_NAME="비밀번호 사용 기간 및 복잡 도를 기관의 정책에 맞도록 설정"
SEVERITY="상"

GUIDELINE_PURPOSE="비밀번호 사용 기간 및 복잡 도 설정 유무를 점검하여 비인가자의 비밀번호 추측 공격(무차별 대입 공격, 사전 대입 공격 등)에 대한 대비가 되어 있는지 확인하기 위함"
GUIDELINE_THREAT="비밀번호 사용 기간 및 복잡 도 설정이 되어 있지 않으면 비인가자가 비밀번호 추측 공격을 통해 획득한 계정의 비밀번호를 이용하여 DB에 접근할 수 있는 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="기관 정책에 맞게 비밀번호 사용 기간 및 복잡 도 설정이 적용된 경우"
GUIDELINE_CRITERIA_BAD="기관 정책에 맞게 비밀번호 사용 기간 및 복잡 도 설정이 적용되지 않은 경우"
GUIDELINE_REMEDIATION="기관 정책에 맞게 비밀번호 사용 기간 및 복잡 도 정책 설정"

diagnose() {
    # Oracle 서비스 확인
    if ! pgrep -x "tnslsnr" &>/dev/null && ! pgrep -x "oracle" &>/dev/null; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="Oracle 서비스 미실행"
        save_dual_result "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" "${inspection_summary}" "${command_result}" "${command_executed}" "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
        verify_result_saved "${ITEM_ID}"
        return 0
    fi

    # sqlplus check
    if ! command -v sqlplus &>/dev/null; then
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

    # FR-022: Check required tools
    if ! check_oracle_tools; then
        handle_missing_tools "oracle" "${ITEM_ID}" "${ITEM_NAME}" \
            "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" \
            "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
        return 0
    fi

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
    echo "진단 항목: ${ITEM_ID} - ${ITEM_NAME}"

    local diagnosis_result="GOOD"
    local status="양호"
    local inspection_summary=""
    local command_result=""
    local command_executed=""
    local vulnerabilities_found=0

    if ! pgrep -x "tnslsnr" &>/dev/null && ! pgrep -x "oracle" &>/dev/null; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="Oracle 서비스 미실행"
        save_dual_result "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" "${inspection_summary}" "${command_result}" "${command_executed}" "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
        verify_result_saved "${ITEM_ID}"
        return 0
    fi

    # 비밀번호 Profile 확인
    local profile_check="SELECT profile FROM dba_profiles WHERE resource_name='PASSWORD_VERIFY_FUNCTION';"
    command_result=$(sqlplus -s "${DBMS_USER}/${DBMS_PASSWORD}@${DBMS_HOST}:${DBMS_PORT}/${DBMS_SID}" "${profile_check}" 2>/dev/null | grep -v "^$" | grep -v "SQL>" || echo "")

    if [ -z "$command_result" ] || echo "$command_result" | grep -q "NULL"; then
        ((vulnerabilities_found++)) || true
        inspection_summary+="취약: 비밀번호 검증 함수 미설정; "
    else
        inspection_summary+=" 비밀번호 검증 함수 설정됨; "
    fi

    # 비밀번호 정책 변수 확인
    local policy_vars="SELECT resource_name, limit FROM dba_profiles WHERE profile='DEFAULT' AND resource_type='PASSWORD' ORDER BY resource_name;"
    command_result=$(sqlplus -s "${DBMS_USER}/${DBMS_PASSWORD}@${DBMS_HOST}:${DBMS_PORT}/${DBMS_SID}" "${policy_vars}" 2>/dev/null | grep -v "^$" | grep -v "SQL>" || echo "")

    if [ -n "$command_result" ]; then
        local password_life=$(echo "$command_result" | grep "PASSWORD_LIFE_TIME" | awk '{print $2}' || echo "")
        local reuse_time=$(echo "$command_result" | grep "PASSWORD_REUSE_TIME" | awk '{print $2}' || echo "")

        if [ "${password_life:-UNLIMITED}" = "UNLIMITED" ]; then
            ((vulnerabilities_found++)) || true
            inspection_summary+="취약: 비밀번호 만료 기간 무제한; "
        fi

        if [ "${reuse_time:-UNLIMITED}" = "UNLIMITED" ]; then
            ((vulnerabilities_found++)) || true
            inspection_summary+="취약: 비밀번호 재사용 제한 없음; "
        fi
    fi

    if [ $vulnerabilities_found -gt 0 ]; then
        diagnosis_result="VULNERABLE"
        status="취약"
    else
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="비밀번호 정책이 적절히 설정됨"
    fi
    command_executed="sqlplus -s "${DBMS_USER}/${DBMS_PASSWORD}@${DBMS_HOST}:${DBMS_PORT}/${DBMS_SID}" \"${profile_check}; ${policy_vars}\""

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
