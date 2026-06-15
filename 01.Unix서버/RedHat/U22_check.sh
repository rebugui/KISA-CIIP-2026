#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-04-20
# ============================================================================
# [점검 항목 상세]
# @ID          : U-22
# @Category    : UNIX > 2. 파일 및 디렉토리 관리
# @Platform    : RedHat
# @Severity    : 상
# @Title       : /etc/services 파일 소유자 및 권한 설정
# @Description : 네트워크 서비스 포트 정보 파일의 소유자 및 권한 설정 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/metadata_parser.sh"

ITEM_ID="U-22"
ITEM_NAME="/etc/services 파일 소유자 및 권한 설정"
SEVERITY="상"

# 가이드라인 정보 (PDF 가이드 내용 반영)
GUIDELINE_PURPOSE="/etc/services 파일을 관리자만 제어할 수 있게하여 비인가자들의 임의적인 파일 변조를 방지하기 위함"
GUIDELINE_THREAT="/etc/services 파일의 접근 권한이 적절하지 않을 경우, 비인가 사용자가 운영 포트 번호를 변경하여 정상적인 서비스를 제한하거나 허용되지 않은 포트를 오픈하여 악성 서비스를 의도적으로 실행할 수 있는 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="/etc/services 파일의 소유자가 root(또는 bin, sys)이고, 권한이 644 이하인 경우"
GUIDELINE_CRITERIA_BAD="/etc/services 파일의 소유자가 root(또는 bin, sys)가 아니거나, 권한이 644 이하가 아닌 경우"
GUIDELINE_REMEDIATION="/etc/services 파일 소유자 및 권한 변경 설정"

diagnose() {
    local status="양호"
    diagnosis_result="GOOD"
    local inspection_summary="/etc/services 파일의 소유자 및 권한 설정이 적절합니다."
    local command_result=""
    local command_executed="ls -l /etc/services"

    local file_path="/etc/services"
    if [ -f "$file_path" ]; then
        local owner=$(stat -c "%U" "$file_path")
        local perm=$(stat -c "%a" "$file_path")
        local ls_out=$(ls -l "$file_path")

        # 2. 판정 로직: 소유자 root/bin/sys 및 권한 644 이하
        if [[ ! "$owner" =~ ^(root|bin|sys)$ ]] || ! [[ "$perm" =~ ^[0-7]{3,4}$ ]] || [ "$(( 8#$perm & ~8#644 & 07777 ))" -ne 0 ]; then
            status="취약"
            diagnosis_result="VULNERABLE"
            inspection_summary="/etc/services 파일의 소유자 또는 권한 설정이 부적절합니다."
        fi
        command_result="설정 현황: [ ${ls_out} ]"
    else
        status="N/A"
        diagnosis_result="N/A"
        inspection_summary="/etc/services 파일이 존재하지 않아 점검 대상이 아닙니다."
        command_result="/etc/services 파일이 존재하지 않습니다."
    fi

    save_dual_result \
        "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" \
        "${inspection_summary}" "${command_result}" "${command_executed}" \
        "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" \
        "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
    
    return 0
}

main() {
    show_diagnosis_start "${ITEM_ID}" "${ITEM_NAME}"
    [ "$EUID" -ne 0 ] && exit 1
    diagnose
    show_diagnosis_complete "${ITEM_ID}" "${diagnosis_result}"
}

main "$@"
