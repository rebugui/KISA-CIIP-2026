#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-28
# ============================================================================
# [점검 항목 상세]
# @ID          : U-36
# @Category    : UNIX > 3. 서비스 관리
# @Platform    : RedHat
# @Severity    : 상
# @Title       : r 계열 서비스 비활성화
# @Description : rlogin, rsh, rexec 등 보안에 취약한 서비스의 활성화 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/metadata_parser.sh"

ITEM_ID="U-36"
ITEM_NAME="r 계열 서비스 비활성화"
SEVERITY="상"

GUIDELINE_PURPOSE="r-command 사용을 통한 원격 접속은 NET Backup 또는 클러스터 링 등 용도로 사용되기도하나, 인증 없이 관리자 원격 접속이 가능하여 이에 대한 보안 위협을 방지하기 위함"
GUIDELINE_THREAT="rlogin, rsh, rexec 등의 r-command를 이용하여 원격에서 인증 절차 없이 터미널 접속, 쉘 명령어를 실행이 가능한 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="불필요한 r 계열 서비스가 비활성화된 경우"
GUIDELINE_CRITERIA_BAD="불필요한 r 계열 서비스가 활성화된 경우"
GUIDELINE_REMEDIATION="불필요한 r 계열 서비스 중지 및 비활성화 설정 ※ NET Backup 등 특별한 용도로 사용하지 않는다면 shell(514), login(513), exec(512)서비스 중 지 ※ rlogin, rsh, rexec 서비스는 backup, 클러스터 링 등의 용도로 종종 사용되고 있으므로 해당 서 비 스 사용 유무를 확인하여 미사용 시 서비스 중지 ※ /etc/hosts.equiv 또는 \$HOME/.rhosts 파일을 통해 해당 서비스 사용 여부 확인 (파일이 존재하지 않거나 해당 파일 내에 설정이 없다면 사용하지 않는 것으로 간주)"

diagnose() {
    local status="양호"
    diagnosis_result="GOOD"
    local inspection_summary="r 계열 서비스가 비활성화되어 있습니다."
    local command_result=""
    local command_executed="ps -ef | grep -E 'rlogin|rsh|rexec'"

    # 1. 실제 데이터 추출
    local r_services=$(ps -ef | grep -Ei "rlogin|rsh|rexec" | grep -v grep || echo "")

    # 2. 판정 로직
    if [ -n "$r_services" ]; then
        status="취약"
        diagnosis_result="VULNERABLE"
        inspection_summary="보안에 취약한 r 계열 서비스가 활성화되어 있습니다."
        command_result="실행 중인 서비스: [ $(echo $r_services | awk '{print $8}' | xargs) ]"
    else
        command_result="r 계열 서비스가 발견되지 않았습니다."
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
