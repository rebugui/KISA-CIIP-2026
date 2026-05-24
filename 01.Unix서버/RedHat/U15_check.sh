#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-04-20
# ============================================================================
# [점검 항목 상세]
# @ID          : U-15
# @Category    : UNIX > 2. 파일 및 디렉토리 관리
# @Platform    : RedHat
# @Severity    : 상
# @Title       : 파일 및 디렉터리 소유자 설정
# @Description : 소유자가 존재하지 않는 파일 및 디렉터리 존재 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/metadata_parser.sh"

ITEM_ID="U-15"
ITEM_NAME="파일 및 디렉터리 소유자 설정"
SEVERITY="상"

# 가이드라인 정보
GUIDELINE_PURPOSE="소유자가 존재하지 않는 파일 및 디렉터리를 제거 또는 관리하여 임의의 사용자가 해당 파일을 열람, 수정하는 행위를 사전에 차단하기 위함"
GUIDELINE_THREAT="소유자가 존재하지 않는 파일의 UID와 동일한 값으로 특정 계정의 UID를 변경하면 해당 파일의 소유자가 되어 모든 작업이 가능한 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="소유자가 존재하지 않는 파일 및 디렉터리가 존재하지 않는 경우"
GUIDELINE_CRITERIA_BAD="소유자가 존재하지 않는 파일 및 디렉터리가 존재하는 경우"
GUIDELINE_REMEDIATION="소유자가 존재하지 않는 파일 및 디렉터리 제거 또는 소유자 변경 설정"

diagnose() {
    local status="양호"
    diagnosis_result="GOOD"
    local inspection_summary="소유자 없는 파일이 발견되지 않았습니다."
    local command_result=""
    local command_executed="find / -nouser -o -nogroup"

    # 1. 실제 데이터 추출: 소유자가 없거나 그룹이 없는 파일 검색
    local nouser_found=$(find / \( -nouser -o -nogroup \) -xdev -ls 2>/dev/null | head -n 5 | awk '{print $11}' | xargs)

    # 2. 판정 로직
    if [ -n "$nouser_found" ]; then
        status="취약"
        diagnosis_result="VULNERABLE"
        inspection_summary="소유자가 존재하지 않는 파일 및 디렉터리가 발견되었습니다."
    fi

    # 3. command_result에 실제 파일 경로 기록
    command_result="발견된 파일(최대5개): [ ${nouser_found:-없음} ]"

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
