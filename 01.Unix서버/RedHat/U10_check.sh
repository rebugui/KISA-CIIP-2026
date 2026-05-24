#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-04-20
# ============================================================================
# [점검 항목 상세]
# @ID          : U-10
# @Category    : UNIX > 1. 계정 관리
# @Platform    : RedHat
# @Severity    : 중
# @Title       : 동일한 UID 금지
# @Description : 동일한 UID를 가진 계정 존재 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/metadata_parser.sh"

ITEM_ID="U-10"
ITEM_NAME="동일한 UID 금지"
SEVERITY="중"

# 가이드라인 정보
GUIDELINE_PURPOSE="UID가 동일한 사용자 계정을 점검함으로써 타 사용자 계정 소유의 파일 및 디렉터리로의 악의적 접근 예방 및 침해 사고 시 명확한 감사 추적을 하기 위함"
GUIDELINE_THREAT="중복된 UID가 존재할 경우, 시스템은 동일한 사용자로 인식하여 소유자의 권한이 중복되어 불필요한 권한이 부여되며 시스템 로그를 이용한 감사 추적 시 사용자가 구분되지 않는 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="동일한 UID로 설정된 사용자 계정이 존재하지 않는 경우"
GUIDELINE_CRITERIA_BAD="동일한 UID로 설정된 사용자 계정이 존재하는 경우"
GUIDELINE_REMEDIATION="동일한 UID를 가진 사용자 계정의 UID 를 중복되지 않도록 변경하도록 설정"

diagnose() {
    local status="양호"
    diagnosis_result="GOOD"
    local inspection_summary="동일한 UID를 사용하는 계정이 발견되지 않았습니다."
    local command_result=""
    local command_executed="cut -d: -f3 /etc/passwd | sort | uniq -d"

    # 1. 실제 데이터 추출: 중복된 UID 탐색
    local dup_uids=$(cut -d: -f3 /etc/passwd | sort | uniq -d)
    local dup_details=""

    if [ -n "$dup_uids" ]; then
        for uid in $dup_uids; do
            local users=$(awk -F: -v u="$uid" '$3==u {print $1}' /etc/passwd | xargs | sed 's/ /,/g')
            dup_details+="[UID ${uid}: ${users}] "
        done
    fi

    # 2. 판정 로직
    if [ -n "$dup_details" ]; then
        status="취약"
        diagnosis_result="VULNERABLE"
        inspection_summary="동일한 UID를 사용하는 중복 계정이 발견되었습니다."
    fi

    # 3. command_result에 실제 중복 계정 정보를 기록
    command_result="중복 UID 현황: ${dup_details:-없음}"

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
