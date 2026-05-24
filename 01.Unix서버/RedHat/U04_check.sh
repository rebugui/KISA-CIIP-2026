#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-04-20
# ============================================================================
# [점검 항목 상세]
# @ID          : U-04
# @Category    : UNIX > 1. 계정 관리
# @Platform    : SOLARIS, LINUX, AIX, HP-UX 등
# @Severity    : (상)
# @Title       : 패스워드 파일 보호
# @Description : /etc/passwd 파일에 패스워드가 암호화되어 저장되어 있는지 확인
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/metadata_parser.sh"

ITEM_ID="U-04"
ITEM_NAME="패스워드 파일 보호"
SEVERITY="상"

# 가이드라인 정보
GUIDELINE_PURPOSE="일부 오래된 시스템의 경우 /etc/passwd 파일에 비밀번호가 평 문으로 저장되므로 사용자 계정 비밀번호가 암호화되어 저장되어 있는지 점검하여 비인가자의 비밀번호 파일 접근 시에도 사용자 계정 비밀번호가 안전하게 관리되고 있는지 확인하기 위함"
GUIDELINE_THREAT="사용자 계정 비밀번호가 저장된 파일이 유출 또는 탈취 시 평 문으로 저장된 비밀번호 정보가 노출 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="쉐도우 비밀번호를 사용하거나, 비밀번호를 암호화하여 저장하는 경우"
GUIDELINE_CRITERIA_BAD="쉐도우 비밀번호를 사용하지 않고, 비밀번호를 암호화하여 저장하지 않는 경우"
GUIDELINE_REMEDIATION="비밀번호 암호화 저장· 관리 설정"

diagnose() {
    local status="양호"
    diagnosis_result="GOOD"
    local inspection_summary="모든 계정이 쉐도우 패스워드 체계를 사용 중입니다."
    local command_result=""
    local command_executed="awk -F: '\$2 != \"x\"' /etc/passwd"

    # 1. 실제 데이터 추출: x가 아닌 계정 확인 및 샘플 추출
    local non_x_list=$(awk -F: '$2 != "x" {print $1}' /etc/passwd | xargs | sed 's/ /, /g' || echo "")
    local passwd_sample=$(head -n 3 /etc/passwd | awk -F: '{print $1":"$2}' | xargs | sed 's/ / | /g' || echo "")

    # 2. 판정 로직
    if [ -n "$non_x_list" ] || [ ! -f /etc/shadow ]; then
        status="취약"
        diagnosis_result="VULNERABLE"
        inspection_summary="쉐도우 패스워드를 사용하지 않는 계정이 발견되었거나 /etc/shadow 파일이 없습니다."
    fi

    # 3. command_result에 실제 데이터 기록
    command_result="[Passwd Sample: ${passwd_sample}]"
    if [ -n "$non_x_list" ]; then
        command_result+=" | [Non-x Users: ${non_x_list}]"
    fi

    # [핵심 보정] JSON 파싱 에러 방지를 위해 변수 내 모든 줄바꿈 제거
    command_result=$(echo "$command_result" | tr -d '\n\r')

    # 12개의 인자를 모두 전달 (U-02와 동일한 방식)
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
