#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-28
# ============================================================================
# [점검 항목 상세]
# @ID          : U-65
# @Category    : UNIX > 5. 서비스 관리
# @Platform    : RedHat
# @Severity    : 중
# @Title       : NTP 및 시각 동기화 설정
# @Description : NTP 서비스 활성화 여부 및 시간 동기화 상태 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/metadata_parser.sh"

ITEM_ID="U-65"
ITEM_NAME="NTP 및 시각 동기화 설정"
SEVERITY="중"

GUIDELINE_PURPOSE="인증 및 감사 목적을 위한 시간 동기화는 필수적이며, 안전하고 승인된 NTP 서비스와 동기화하기 위함"
GUIDELINE_THREAT="시스템 간 시간 동기화 미흡으로 보안 사고 및 장애 발생 시 로그에 대한 신뢰도 확보 미흡 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="NTP 및 시각 동기화 설정이 기준에 따라 적용된 경우"
GUIDELINE_CRITERIA_BAD="NTP 및 시각 동기화 설정이 기준에 따라 적용되어 있지 않은 경우"
GUIDELINE_REMEDIATION="NTP 설정 및 동기화 주기 설정"

diagnose() {
    local status="양호"
    diagnosis_result="GOOD"
    local inspection_summary="NTP 서비스가 정상적으로 동작 중입니다."
    local command_result=""
    local command_executed="chronyc sources || ntpq -p"
    
    # 1. 실행 결과 저장
    local cmd_out
    cmd_out=$(chronyc sources 2>&1 || ntpq -p 2>&1 || echo "NTP_SERVICE_NOT_FOUND")

    # 2. 판정 로직 
    # - 에러 메시지(Cannot talk to daemon, Connection refused 등)가 포함된 경우
    # - 혹은 동기화 서버 리스트가 아예 없는 경우
    if [[ "$cmd_out" == "NTP_SERVICE_NOT_FOUND" ]]; then
        status="취약"
        diagnosis_result="VULNERABLE"
        inspection_summary="NTP 서비스가 설치되어 있지 않습니다."
    elif [[ "$cmd_out" =~ "Cannot talk to daemon" ]] || [[ "$cmd_out" =~ "Connection refused" ]]; then
        status="취약"
        diagnosis_result="VULNERABLE"
        inspection_summary="NTP 데몬이 응답하지 않습니다. 서비스 상태를 확인하십시오."
    elif ! echo "$cmd_out" | grep -qE '^\^[*+]|^[*o]'; then
        # 동기화 기호가 없는 경우 취약
        # - chronyc sources: 라인이 '^* '(동기화) 또는 '^+ '(결합) 로 시작 (첫 문자는 리터럴 '^')
        # - ntpq -p: 라인이 '*'(syspeer) 또는 'o'(PPS) 로 시작
        status="취약"
        diagnosis_result="VULNERABLE"
        inspection_summary="NTP 서버와 동기화가 이루어지지 않고 있습니다."
    fi

    command_result="[NTP Status]\n${cmd_out}"

    save_dual_result \
        "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" \
        "${inspection_summary}" "${command_result}" "${command_executed}" \
        "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" \
        "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"

    verify_result_saved "${ITEM_ID}"
}

main() {
    show_diagnosis_start "${ITEM_ID}" "${ITEM_NAME}"
    [ "$EUID" -ne 0 ] && { echo "root 권한이 필요합니다."; exit 1; }
    diagnose
    show_diagnosis_complete "${ITEM_ID}" "${diagnosis_result}"
    exit 0
}
main "$@"
