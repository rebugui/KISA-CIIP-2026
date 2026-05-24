#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-28
# ============================================================================
# [점검 항목 상세]
# @ID          : U-26
# @Category    : UNIX > 2. 파일 및 디렉토리 관리
# @Platform    : RedHat
# @Severity    : 상
# @Title       : /dev에 존재하지 않는 device 파일 점검
# @Description : /dev 디렉터리에 device 파일이 아닌 일반 파일이 존재하는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; LIB_DIR="${SCRIPT_DIR}/../../lib"
source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/metadata_parser.sh"

ITEM_ID="U-26"; ITEM_NAME="/dev에 존재하지 않는 device 파일 점검"; SEVERITY="(상)"
GUIDELINE_PURPOSE="허용한 호스트만 서비스를 사용하게하여 서비스 취약점을 이용한 외부자 공격을 방지하기 위함"
GUIDELINE_THREAT="공격자는 rootkit 설정 파일들을 서버 관리자가 쉽게 발견하지 못하도록 /dev 디렉터리에 device 파일인 것처럼 위장하는 수법을 사용하는 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="/dev 디렉터리에 대한 파일 점검 후 존재하지 않는 device 파일을 제거한 경우"
GUIDELINE_CRITERIA_BAD="/dev 디렉터리에 대한 파일 미점검 또는 존재하지 않는 device 파일을 방치한 경우"
GUIDELINE_REMEDIATION="major, minor number를 가지지 않는 device 파일 제거하도록 설정"

# 전역 변수로 설정하여 main에서 참조 가능하게 함
diagnose() {
    local status="양호"; diagnosis_result="GOOD"
    local inspection_summary="/dev 디렉토리에 device 파일이 아닌 일반 파일이 존재하지 않습니다."
    local command_result=""; local command_executed="find /dev -type f"

    # /dev 디렉토리 내 device 파일이 아닌 일반 파일 탐색
    local fake_dev=$(find /dev -type f 2>/dev/null | xargs)

    if [ -n "$fake_dev" ]; then
        status="취약"; diagnosis_result="VULNERABLE"
        inspection_summary="/dev 디렉토리에 device 파일이 아닌 일반 파일이 존재합니다."
        command_result="발견된 일반 파일: [ $fake_dev ]"
    else
        command_result="/dev 내 특이 파일 없음"
    fi

    save_dual_result "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" "${inspection_summary}" "${command_result}" "${command_executed}" "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
}
main() {
    show_diagnosis_start "${ITEM_ID}" "${ITEM_NAME}"
    [ "$EUID" -ne 0 ] && { echo "root 권한이 필요합니다."; exit 1; }
    diagnose
    show_diagnosis_complete "${ITEM_ID}" "${diagnosis_result}"
}
main "$@"
