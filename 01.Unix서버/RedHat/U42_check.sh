#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-28
# ============================================================================
# [점검 항목 상세]
# @ID          : U-42
# @Category    : UNIX > 3. 서비스 관리
# @Platform    : SOLARIS, LINUX, AIX, HP-UX 등
# @Severity    : (상)
# @Title       : 불필요한 RPC 서비스 비활성화
# @Description : 취약점이 있는 불필요한 RPC 서비스의 활성화 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/metadata_parser.sh"

ITEM_ID="U-42"
ITEM_NAME="불필요한 RPC 서비스 비활성화"
SEVERITY="상"

# 가이드라인 정보 (PDF 내용 반영)
GUIDELINE_PURPOSE="많은 취약점(버퍼 오버 플로우, DoS, 원격 실행 등)이 존재하는 RPC 서비스를 비활성화하여 시스템의 보안성을 높이기 위함"
GUIDELINE_THREAT="RPC 서비스의 취약점을 통해 비인가자가 root 권한 획득 및 각종 공격을 시도할 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="불필요한 RPC 서비스가 비활성화된 경우"
GUIDELINE_CRITERIA_BAD="불필요한 RPC 서비스가 활성화된 경우"
GUIDELINE_REMEDIATION="불필요한 RPC 서비스 중지 및 비활성화 설정"

diagnose() {
    local status="양호"
    diagnosis_result="GOOD"
    local inspection_summary="취약한 RPC 서비스가 비활성화되어 있습니다."
    local command_result=""
    local command_executed="ps -ef | grep -E 'rusersd|rwalld|rstatd'"

    # 1. 실제 데이터 추출
    local rpc_procs=$(ps -ef | grep -Ei "rusersd|rwalld|rstatd|rpc.cmsd|rpc.ttdbserverd" | grep -v grep || echo "")

    # 2. 판정 로직
    if [ -n "$rpc_procs" ]; then
        status="취약"
        diagnosis_result="VULNERABLE"
        inspection_summary="보안에 취약한 RPC 서비스가 활성화되어 있습니다."
        command_result="취약 RPC 프로세스 발견: [ $(echo $rpc_procs | awk '{print $8}' | xargs) ]"
    else
        command_result="불필요한 RPC 서비스가 탐지되지 않았습니다."
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
