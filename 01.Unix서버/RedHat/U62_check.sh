#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-28
# ============================================================================
# [점검 항목 상세]
# @ID          : U-62
# @Category    : UNIX > 6. 로그 관리
# @Platform    : RedHat
# @Severity    : 하
# @Title       : 로그인 시 경고 메시지 설정
# @Description : 서버 접속 시 법적 책임 및 경고 문구가 포함된 배너 출력 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/metadata_parser.sh"

ITEM_ID="U-62"
ITEM_NAME="로그인 시 경고 메시지 설정"
SEVERITY="하"

GUIDELINE_PURPOSE="비인가자들에게 서버에 대한 불필요한 정보를 제공하지 않고, 서버 접속 시 관계자만 접속해야한다는 경각심을 심어 주기 위함"
GUIDELINE_THREAT="로그온 시 경고 메시지가 설정되어 있지 않을 경우, 기본 설정 값엔 서버 OS 버전 및 서비스 버전이 비인가자에게 노출되어 해당 정보를 통해 서비스의 취약점을 이용하여 공격을 시도할 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="서버 및 Telnet,FTP,SMTP,DNS 서비스에 로그온 시 경고 메시지가 설정된 경우"
GUIDELINE_CRITERIA_BAD="서버 및 Telnet,FTP,SMTP,DNS 서비스에 로그 온 시 경고 메시지가 설정되어 있지 않은 경우"
GUIDELINE_REMEDIATION="Telnet,FTP,SMTP,DNS 서비스를 사용하는 경우 설정 파일을 통해 로그온 시 경고 메시지 설정"

diagnose() {
    local status="양호"
    diagnosis_result="GOOD"
    local inspection_summary="로그인 경고 메시지가 적절하게 설정되어 있습니다."
    local command_result=""
    local command_executed="ls -l /etc/motd /etc/issue.net"

    local motd_content=$(cat /etc/motd 2>/dev/null | xargs || echo "")
    local issue_content=$(cat /etc/issue.net 2>/dev/null | xargs || echo "")

    if [ -z "$motd_content" ] && [ -z "$issue_content" ]; then
        status="취약"
        diagnosis_result="VULNERABLE"
        inspection_summary="서버 접속 시 출력되는 경고 메시지(배너)가 비어 있거나 설정되지 않았습니다."
    fi
    command_result=$(echo "motd: [ ${motd_content:-empty} ], issue.net: [ ${issue_content:-empty} ]" | tr -d '\n\r')

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
