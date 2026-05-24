#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-28
# ============================================================================
# [점검 항목 상세]
# @ID          : U-59
# @Category    : UNIX > 5. 서비스 관리
# @Platform    : RedHat
# @Severity    : 상
# @Title       : 안전한 SNMP 버전 사용
# @Description : 취약한 SNMP v1, v2c 버전 사용 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/metadata_parser.sh"

ITEM_ID="U-59"
ITEM_NAME="안전한 SNMP 버전 사용"
SEVERITY="상"

GUIDELINE_PURPOSE="안전한 SNMP 버전 사용으로 전송되는 데이터를 보호하기 위함"
GUIDELINE_THREAT="SNMP 버전이 기준보다 낮을 경우, 응답 패킷이 평문으로 전송되어 스니 핑 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="SNMP 서비스를 v3 이상으로 사용하는 경우"
GUIDELINE_CRITERIA_BAD="SNMP 서비스를 v2 이하로 사용하는 경우"
GUIDELINE_REMEDIATION="SNMP 서비스를 사용하지 않는 경우 서비스 중지 및 비활성화 설정 SNMP 서비스 사용 시 SNMP 버전을 v3 이상으로 적용하도록 설정"

diagnose() {
    local status="양호"
    diagnosis_result="GOOD"
    local inspection_summary="SNMPv1/v2c 등 취약한 버전 설정이 발견되지 않았습니다."
    local command_result=""
    local command_executed="grep -Ei 'com2sec|community' /etc/snmp/snmpd.conf"

    if [ -f "/etc/snmp/snmpd.conf" ]; then
        local v12_check=$(grep -Ei "com2sec|community" /etc/snmp/snmpd.conf | grep -v "^#" | xargs || echo "")
        if [ -n "$v12_check" ]; then
            status="취약"
            diagnosis_result="VULNERABLE"
            inspection_summary="취약한 SNMPv1/v2c 커뮤니티 설정이 발견되었습니다."
            command_result="발견된 설정: [ ${v12_check} ]"
        fi
    fi
    command_result=$(echo "${command_result:-SNMP 설정 이상 없음}" | tr -d '\n\r')

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
