#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-28
# ============================================================================
# [점검 항목 상세]
# @ID          : U-32
# @Category    : UNIX > 2. 파일 및 디렉토리 관리
# @Platform    : RedHat
# @Severity    : 중
# @Title       : 홈 디렉토리로 지정한 디렉토리의 존재 관리
# @Description : 계정 설정에 명시된 홈 디렉터리가 실제로 존재하는지 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/metadata_parser.sh"

ITEM_ID="U-32"
ITEM_NAME="홈 디렉토리로 지정한 디렉토리의 존재 관리"
SEVERITY="중"

GUIDELINE_PURPOSE="/home 디렉토리 이외의 사용자의 홈 디렉토리 존재 여부를 점검하여 비인가자가 시스템 명령어의 무단 사용을 방지하기 위함"
GUIDELINE_THREAT="/etc/passwd 파일에 설정된 홈 디렉토리가 존재하지 않는 경우, 해당 계정으로 로그인 시 홈 디렉토리가 루트 디렉토리(/)로 할당되어 접근이 가능한 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="홈 디렉토리가 존재하지 않는 계정이 발견되지 않는 경우"
GUIDELINE_CRITERIA_BAD="홈 디렉토리가 존재하지 않는 계정이 발견된 경우"
GUIDELINE_REMEDIATION="홈 디렉토리가 존재하지 않는 계정에 홈 디렉토리 설정 또는 계정 제거하도록 설정"

diagnose() {
    # 변수 범위 수정 (main에서 읽을 수 있도록 전역 설정)
    status="양호"
    diagnosis_result="GOOD"
    inspection_summary="모든 활성 계정의 홈 디렉터리가 실제로 존재합니다."
    command_result=""
    command_executed="grep -v 'nologin\|false' /etc/passwd | cut -d: -f1,6"

    local checked_details=""
    local missing_homes=""
    local total_checked=0

    # /etc/passwd 점검 루프
    while IFS=: read -r user pass uid gid info home shell; do
        # 점검 대상: UID 1000 이상이면서 로그인이 가능한 계정
        if [ "$uid" -ge 1000 ] && [[ ! "$shell" =~ (nologin|false)$ ]]; then
            ((total_checked++))
            
            if [ -d "$home" ]; then
                checked_details+="${user}: ${home} [EXIST]\n"
            else
                checked_details+="${user}: ${home} [MISSING] !!!\n"
                missing_homes+="${user} "
                status="취약"
                diagnosis_result="VULNERABLE"
            fi
        fi
    done < /etc/passwd

    if [ "$diagnosis_result" = "VULNERABLE" ]; then
        inspection_summary="총 ${total_checked}개 중 일부 계정의 홈 디렉터리가 존재하지 않습니다."
        command_result=$(echo -e "점검 상세 리스트:\n${checked_details}\n결과: 홈 디렉토리 부재 계정 -> [ ${missing_homes} ]")
    else
        command_result=$(echo -e "점검 상세 리스트 (총 ${total_checked}개 계정):\n${checked_details}\n모든 홈 디렉터리가 정상적으로 존재합니다.")
    fi

    save_dual_result \
        "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" \
        "${inspection_summary}" "${command_result}" "${command_executed}" \
        "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" \
        "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
    
    return 0
}

main() {
    if [ "$EUID" -ne 0 ]; then
        echo "Error: root 권한이 필요합니다."
        exit 1
    fi

    show_diagnosis_start "${ITEM_ID}" "${ITEM_NAME}"
    diagnose || true
    show_diagnosis_complete "${ITEM_ID}" "${diagnosis_result:-ERROR}"
    exit 0
}

main "$@"
