#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-04-20
# ============================================================================
# [점검 항목 상세]
# @ID          : U-16
# @Category    : UNIX > 2. 파일 및 디렉토리 관리
# @Platform    : RedHat
# @Severity    : 상
# @Title       : /etc/passwd 파일 소유자 및 권한 설정
# @Description : /etc/passwd 파일의 소유자 및 권한 설정이 적절한지 점검
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

ITEM_ID="U-16"
ITEM_NAME="/etc/passwd 파일 소유자 및 권한 설정"
SEVERITY="상"

# 가이드라인 정보
GUIDELINE_PURPOSE="/etc/passwd 파일을 관리자만 제어할 수 있게하여 비인가자들의 임의적인 파일 변조를 방지하기 위함"
GUIDELINE_THREAT="비인가자가 /etc/passwd 파일의 사용자 정보를 변조하여 Shell 변경, 사용자 추가/ 제거 등 root 계정을 포함한 사용자 권한 획득 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="/etc/passwd 파일의 소유자가 root이고, 권한이 644 이하인 경우"
GUIDELINE_CRITERIA_BAD="/etc/passwd 파일의 소유자가 root가 아니거나, 권한이 644 이하가 아닌 경우"
GUIDELINE_REMEDIATION="/etc/passwd 파일 소유자 및 권한 변경 설정"

diagnose() {
    # 파싱 안정성을 위한 초기값 설정
    local status="양호"
    diagnosis_result="GOOD"
    local inspection_summary="/etc/passwd 파일의 소유자 및 권한 설정이 적절합니다."
    local command_result=""
    local command_executed="ls -l /etc/passwd"

    # 1. 실제 데이터 추출
    local file_path="/etc/passwd"
    if [ -f "$file_path" ]; then
        local owner_name=$(stat -c "%U" "$file_path")
        local file_perm=$(stat -c "%a" "$file_path")
        local ls_out=$(ls -l "$file_path")

        # 2. 판정 로직: 소유자 root 및 권한 644 초과 비트 없음 체크
        # 644보다 강한 권한(600/400 등)은 양호, 644에 없는 추가 비트(쓰기 등)는 취약
        if [ "$owner_name" != "root" ] || ! [[ "$file_perm" =~ ^[0-7]{3,4}$ ]] || [ "$(( 8#$file_perm & ~8#644 & 07777 ))" -ne 0 ]; then
            status="취약"
            diagnosis_result="VULNERABLE"
            inspection_summary="/etc/passwd 파일의 소유자가 root가 아니거나 권한 설정(644)이 부적절합니다."
        fi

        # 3. 결과 기록 (JSON 보호를 위한 개행 제거)
        command_result="소유자: ${owner_name}, 권한: ${file_perm}, 상세: ${ls_out}"
        command_result=$(echo "$command_result" | tr -d '\n\r')
    else
        status="수동진단"
        diagnosis_result="MANUAL"
        inspection_summary="/etc/passwd 파일을 찾을 수 없어 자동 점검이 불가합니다. 수동 확인이 필요합니다."
        command_result="파일 없음: /etc/passwd"
    fi

    # U-02와 동일하게 12개의 인자를 모두 전달
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
