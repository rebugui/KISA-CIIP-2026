#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-04-20
# ============================================================================
# [점검 항목 상세]
# @ID          : U-13
# @Category    : UNIX > 1. 계정 관리
# @Platform    : RedHat
# @Severity    : 중
# @Title       : 안전한 비밀번호 암호화 알고리즘 사용
# @Description : 안전한 비밀번호 암호화 알고리즘을 사용 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/metadata_parser.sh"

ITEM_ID="U-13"
ITEM_NAME="안전한 비밀번호 암호화 알고리즘 사용"
SEVERITY="중"

# 가이드라인 정보
GUIDELINE_PURPOSE="안전한 비밀번호 암호화 알고리즘을 사용하여 사용자 계정 정보를 보호하기 위함"
GUIDELINE_THREAT="취약한 비밀번호 암호화 알고리즘을 사용할 경우, 노출된 계정에 대해 비인가자가 암호 복호화 공격을 통해 비밀번호를 획득할 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="SHA-2 이상의 안전한 비밀번호 암호화 알고리즘을 사용하는 경우"
GUIDELINE_CRITERIA_BAD="취약한 비밀번호 암호화 알고리즘을 사용하는 경우"
GUIDELINE_REMEDIATION="SHA-2 이상의 안전한 비밀번호 암호화 알고리즘 적용 설정"

diagnose() {
    local status="양호"
    diagnosis_result="GOOD"
    local inspection_summary="SHA-2 이상의 안전한 암호화 알고리즘이 설정되어 있습니다."
    local command_result=""
    local command_executed="grep ENCRYPT_METHOD /etc/login.defs"

    # 1. 실제 데이터 추출: 설정 파일 및 실제 shadow 파일의 해시 식별자 확인
    local encrypt_method=$(grep "^ENCRYPT_METHOD" /etc/login.defs | awk '{print $2}' || echo "미설정")
    local shadow_id=$(grep "^root:" /etc/shadow | cut -d: -f2 | cut -d$ -f2 || echo "N/A")

    # 2. 판정 로직: SHA-512($6) 또는 SHA-256($5) 인지 확인
    if [[ "$encrypt_method" != "SHA512" && "$encrypt_method" != "SHA256" ]] && [[ "$shadow_id" != "6" && "$shadow_id" != "5" ]]; then
        status="취약"
        diagnosis_result="VULNERABLE"
        inspection_summary="안전하지 않은 비밀번호 암호화 알고리즘을 사용 중입니다."
    fi

    # 3. command_result에 실제 데이터 기록
    command_result="ENCRYPT_METHOD: [ ${encrypt_method} ] | Shadow ID: [ \$${shadow_id} ]"

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
