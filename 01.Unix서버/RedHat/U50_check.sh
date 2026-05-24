#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-28
# ============================================================================
# [점검 항목 상세]
# @ID          : U-50
# @Category    : UNIX > 3. 서비스 관리
# @Platform    : RedHat
# @Severity    : 상
# @Title       : DNS ZoneTransfer 설정
# @Description : DNS 존 전송(Zone Transfer)을 제한하여 불필요한 영역 정보 노출을 방지하는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/metadata_parser.sh"

ITEM_ID="U-50"
ITEM_NAME="DNS ZoneTransfer 설정"
SEVERITY="상"

GUIDELINE_PURPOSE="DNSZoneTransfer 설정을 통해 비인가자에 대한 무단 접근을 방지하기 위함"
GUIDELINE_THREAT="ZoneTransfer를 모든 사용자에게 허용할 경우, 비인가자에게 호스트 정보, 시스템 정보 등 중요 정보가 유출될 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="ZoneTransfer를 허가된 사용자에게만 허용한 경우"
GUIDELINE_CRITERIA_BAD="Zone Transfer를 모든 사용자에게 허용한 경우"
GUIDELINE_REMEDIATION="DNS 서비스를 사용하지 않는 경우 서비스 중지 및 비활성화 설정 DNS 서비스 사용 시 DNSZoneTransfer를 허가된 사용자에게만 전송 허용하도록 설정"

diagnose() {
    local status="양호"
    diagnosis_result="GOOD"
    local inspection_summary="DNS 존 전송 설정이 적절하게 제한되어 있습니다."
    local command_result=""
    local command_executed="grep 'allow-transfer' /etc/named.conf"

    if [ -f "/etc/named.conf" ]; then
        local transfer_opt=$(grep -i "allow-transfer" /etc/named.conf | tr -d '[:space:]' || echo "not-set")
        if [[ "$transfer_opt" == "not-set" ]] || [[ "$transfer_opt" =~ "any" ]]; then
            status="취약"
            diagnosis_result="VULNERABLE"
            inspection_summary="DNS 존 전송이 제한되지 않았거나 모든 호스트(any)에 허용되어 있습니다."
        fi
        command_result="allow-transfer 설정 현황: [ ${transfer_opt} ]"
    else
        command_result="DNS 설정 파일(/etc/named.conf)이 존재하지 않습니다."
    fi

    command_result=$(echo "$command_result" | tr -d '\n\r')

    save_dual_result \
        "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" \
        "${inspection_summary}" "${command_result}" "${command_executed}" \
        "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" \
        "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
    
    verify_result_saved "${ITEM_ID}"
    return 0
}

main() {
    show_diagnosis_start "${ITEM_ID}" "${ITEM_NAME}"
    [ "$EUID" -ne 0 ] && { echo "root 권한이 필요합니다."; exit 1; }
    diagnose
    show_diagnosis_complete "${ITEM_ID}" "${diagnosis_result}"
    exit 0
}

main "$@"
