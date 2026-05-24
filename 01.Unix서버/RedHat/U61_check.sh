#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-28
# ============================================================================
# [점검 항목 상세]
# @ID          : U-61
# @Category    : UNIX > 5. 서비스 관리
# @Platform    : SOLARIS, LINUX, AIX, HP-UX 등
# @Severity    : (중)
# @Title       : SNMP 서비스 접근 제어 설정
# @Description : SNMP 서비스에 대한 호스트/IP 기반 접근 제어 설정 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/metadata_parser.sh"

ITEM_ID="U-61"
ITEM_NAME="SNMP 서비스 접근 제어 설정"
SEVERITY="상"

GUIDELINE_PURPOSE="SNMP 접근 제어 설정을 통해 비인가자의 접근을 차단하기 위함"
GUIDELINE_THREAT="SNMP 서비스에 접근 제어가 설정되어 있지 않을 경우, 비인가자의 접근, 네트워크 정보 유출, 시스템 및 네트워크 설정 변경,DoS 공격 등의 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="SNMP 서비스에 접근 제어 설정이 되어 있는 경우"
GUIDELINE_CRITERIA_BAD="SNMP 서비스에 접근 제어 설정이 되어 있지 않은 경우"
GUIDELINE_REMEDIATION="SNMP 서비스를 사용하지 않는 경우 서비스 중지 및 비활성화 설정 SNMP 서비스 사용 시 SNMP 접근 제어 설정하도록 설정"

diagnose() {
    local status="양호"
    diagnosis_result="GOOD"
    local inspection_summary="SNMP 접근 제어 설정이 적절하게 구성되어 있습니다."
    local command_result=""
    local command_executed="grep -Ei 'com2sec|sec.name' /etc/snmp/snmpd.conf"

    if [ -f "/etc/snmp/snmpd.conf" ]; then
        # com2sec 기반 접근 제어 확인 (SNMPv1/v2c)
        local com2sec_check=$(grep -Ei "com2sec|sec.name" /etc/snmp/snmpd.conf | grep "default" | grep -v "^#" || echo "")
        # VACM 기반 접근 제어 확인 (SNMPv3 및 고급 설정)
        local vacm_check=$(grep -v "^#" /etc/snmp/snmpd.conf | grep -Ei "^[[:space:]]*access[[:space:]]" | grep -Ei "exact\s+all\s" || echo "")

        if [ -n "$com2sec_check" ]; then
            status="취약"
            diagnosis_result="VULNERABLE"
            inspection_summary="SNMP 서비스가 'default'(모든 호스트) 대역에 대해 허용되어 있습니다."
            command_result="취약한 설정: [ ${com2sec_check} ]"
        elif [ -n "$vacm_check" ]; then
            status="취약"
            diagnosis_result="VULNERABLE"
            inspection_summary="SNMP VACM 설정이 과도하게 허용되어 있습니다."
            command_result="취약한 VACM 설정: [ ${vacm_check} ]"
        fi
    fi
    command_result=$(echo "${command_result:-접근 제어 양호}" | tr -d '\n\r')

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
