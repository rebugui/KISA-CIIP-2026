#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-28
# ============================================================================
# [점검 항목 상세]
# @ID          : U-29
# @Category    : UNIX > 2. 파일 및 디렉토리 관리
# @Platform    : RedHat
# @Severity    : 하
# @Title       : hosts.lpd 파일 소유자 및 권한 설정
# @Description : /etc/hosts.lpd 파일의 소유자 및 권한 설정이 적절한지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

set -euo pipefail

# 스크립트 디렉토리 설정
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../../lib"

# 필수 라이브러리 로드
source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/metadata_parser.sh"

ITEM_ID="U-29"
ITEM_NAME="hosts.lpd 파일 소유자 및 권한 설정"
SEVERITY="하"

# 가이드라인 정보 (제시된 리스트 기준 반영)
GUIDELINE_PURPOSE="비인가자의 임의적인 /etc/hosts.lpd 변조를 막기 위해 /etc/hosts.lpd 파일 제거 또는 소유자 및 권한 관리하기 위함"
GUIDELINE_THREAT="/etc/hosts.lpd 파일의 접근 권한이 적절하지 않을 경우, 비인가자가 /etc/hosts.lpd 파일을 수정하여 허용된 사용자의 서비스를 방해할 수 있으며, 호스트 정보를 획득할 수 있는 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="/etc/hosts.lpd 파일이 존재하지 않거나, 불가피하게 사용 시 /etc/hosts.lpd 파일의 소유자가 root이고, 권한이 600 이하인 경우"
GUIDELINE_CRITERIA_BAD="/etc/hosts.lpd 파일이 존재하며, 파일의 소유자가 root가 아니거나, 권한이 600 이하가 아닌 경우"
GUIDELINE_REMEDIATION="/etc/hosts.lpd 파일 제거 또는 /etc/hosts.lpd 파일 소유자 및 권한 변경 설정"

diagnose() {
    # [중요] 파싱 에러 방지를 위한 기존 변수 초기값 유지
    local status="양호"
    diagnosis_result="GOOD"
    local inspection_summary="/etc/hosts.lpd 파일의 소유자 및 권한 설정이 적절합니다."
    local command_result=""
    local command_executed="ls -l /etc/hosts.lpd"

    # 1. 실제 데이터 추출
    local file_path="/etc/hosts.lpd"
    if [ -f "$file_path" ]; then
        local owner=$(stat -c "%U" "$file_path")
        local perm=$(stat -c "%a" "$file_path")
        local ls_out=$(ls -l "$file_path")

        # 2. 판정 로직
        if [ "$owner" != "root" ] || ! [[ "$perm" =~ ^[0-7]{3,4}$ ]] || [ "$(( 8#$perm & ~8#600 & 07777 ))" -ne 0 ]; then
            status="취약"
            diagnosis_result="VULNERABLE"
            inspection_summary="/etc/hosts.lpd 파일의 소유자 또는 권한 설정이 부적절합니다."
        fi
        command_result="설정 현황: [ ${ls_out} ]"
    else
        command_result="/etc/hosts.lpd 파일이 존재하지 않습니다."
    fi

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
