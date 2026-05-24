#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-28
# ============================================================================
# [점검 항목 상세]
# @ID          : U-38
# @Category    : UNIX > 3. 서비스 관리
# @Platform    : SOLARIS, LINUX, AIX, HP-UX 등
# @Severity    : (상)
# @Title       : DoS 공격에 취약한 서비스 비활성화
# @Description : DoS 공격에 악용될 수 있는 echo, discard, daytime, chargen 등의 서비스 비활성화 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/metadata_parser.sh"

ITEM_ID="U-38"
ITEM_NAME="DoS 공격에 취약한 서비스 비활성화"
SEVERITY="상"

GUIDELINE_PURPOSE="많은 취약점을 가진 echo, discard, daytime, chargen, ntp, snmp 등의 서비스를 중지하여 시스템의 보안성을 높이기 위함"
GUIDELINE_THREAT="해당 서비스가 활성화된 경우, 시스템 정보 유출 및 DoS 공격의 대상이 될 수 있는 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="DoS 공격에"
GUIDELINE_CRITERIA_BAD="DoS 공격에 취약한 서비스가 활성화된 경우"
GUIDELINE_REMEDIATION="echo, discard, daytime, chargen, ntp, dns,snmp 등의 서비스 비활성화 설정"

diagnose() {
    local status="양호"
    diagnosis_result="GOOD"
    local inspection_summary="DoS 공격에 취약한 불필요 서비스들이 모두 비활성화되어 있습니다."
    local command_result=""
    local command_executed="grep -r 'disable' /etc/xinetd.d/"

    # 1. 실제 데이터 추출
    local dos_list=("echo" "discard" "daytime" "chargen")
    local active_services=""
    
    for svc in "${dos_list[@]}"; do
        if [ -f "/etc/xinetd.d/$svc" ]; then
            if grep -qi "disable" "/etc/xinetd.d/$svc" | grep -qi "no"; then
                active_services+="$svc "
            fi
        fi
    done

    # 2. 판정 로직
    if [ -n "$active_services" ]; then
        status="취약"
        diagnosis_result="VULNERABLE"
        inspection_summary="DoS 공격에 취약한 일부 서비스가 활성화되어 있습니다."
        command_result="활성 DoS 서비스: [ ${active_services} ]"
    else
        command_result="모든 취약한 DoS 서비스가 비활성화 상태입니다."
    fi

    save_dual_result \
        "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" \
        "${inspection_summary}" "${command_result}" "${command_executed}" \
        "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" \
        "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
    
    return 0
}

main() { [ "$EUID" -ne 0 ] && exit 1; diagnose; }
main "$@"
