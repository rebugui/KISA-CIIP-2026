#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-28
# ============================================================================
# [점검 항목 상세]
# @ID          : U-33
# @Category    : UNIX > 2. 파일 및 디렉토리 관리
# @Platform    : RedHat
# @Severity    : 하
# @Title       : 숨겨진 파일 및 디렉토리 검색 및 제거
# @Description : 시스템 내 불필요하거나 의심스러운 숨겨진 파일 및 디렉터리 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/metadata_parser.sh"

ITEM_ID="U-33"
ITEM_NAME="숨겨진 파일 및 디렉토리 검색 및 제거"
SEVERITY="하"

GUIDELINE_PURPOSE="숨겨진 파일 및 디렉토리 중 의심스러운 내용은 정상 사용자가 아닌 공격자에 의해 생성되었을 가능성이 높으므로 이를 제거하여 보안 위협을 방지하기 위함"
GUIDELINE_THREAT="숨겨진 파일 및 디렉토리를 방치할 경우, 비인가자가 생성한 악성 파일 또는 백 도어 등을 탐지하지 못할 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="불필요하거나 의심스러운 숨겨진 파일 및 디렉토리를 제거한 경우"
GUIDELINE_CRITERIA_BAD="불필요하거나 의심스러운 숨겨진 파일 및 디렉토리를 제거하지 않은 경우"
GUIDELINE_REMEDIATION="ls-al 명령어로 숨겨진 파일 존재 파악 후 불법적이거나 의심스러운 파일을 제거하도록 설정"

diagnose() {
    local status="양호"
    diagnosis_result="GOOD"
    local inspection_summary="의심스러운 숨겨진 파일이 발견되지 않았습니다."
    local command_result=""
    local command_executed="find /tmp /var/tmp -name '.*' -type f"

    # 1. 파일 탐색 (정상적인 파일 몇 개는 제외하는 필터 추가 가능)
    local hidden_files
    hidden_files=$(find /tmp /var/tmp -name ".*" -type f 2>/dev/null | grep -vE ".X11-unix|.ICE-unix|.Test-unix" | head -n 10)

    if [ -n "$hidden_files" ]; then
        # 파일이 발견되면 수동 점검을 위해 '취약' 또는 '검토필요'로 변경
        status="취약" # KISA 가이드에 따라 일단 '발견' 시 취약으로 분류 후 소명
        diagnosis_result="VULNERABLE"
        inspection_summary="임시 디렉터리 내에 숨겨진 파일이 존재합니다. 악성 여부를 수동으로 확인하십시오."
        command_result=$(echo -e "발견된 숨김 파일 리스트:\n${hidden_files}")
    else
        command_result="임시 디렉토리 내에 숨겨진 파일이 없습니다."
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
