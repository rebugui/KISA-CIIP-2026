#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-04-20
# ============================================================================
# [점검 항목 상세]
# @ID          : U-08
# @Category    : UNIX > 1. 계정 관리
# @Platform    : RedHat
# @Severity    : 중
# @Title       : 관리자 그룹에 최소한의 계정 포함
# @Description : 관리자 권한이 있는 그룹(root, wheel 등)에 불필요한 계정 포함 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/metadata_parser.sh"

ITEM_ID="U-08"
ITEM_NAME="관리자 그룹에 최소한의 계정 포함"
SEVERITY="중"

# 가이드라인 정보
GUIDELINE_PURPOSE="관리자 그룹에 최소한의 필요 계정만 존재하는지 확인하여 불필요한 권한 남용을 점검하기 위함"
GUIDELINE_THREAT="시스템을 관리하는 root 계정이 속한 그룹은 시스템 운영 파일에 대한 접근 권한이 부여되어 있으므로 해당 관리자 그룹에 속한 계정이 비인가자에게 유출될 경우, 관리자 권한으로 시스템에 접근하여 계정 정보 유출, 환경 설정 파일 및 디렉터리 변조 등의 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="관리자 그룹에 불필요한 계정이 등록되어 있지 않은 경우"
GUIDELINE_CRITERIA_BAD="관리자 그룹에 불필요한 계정이 등록된 경우"
GUIDELINE_REMEDIATION="관리자 그룹에 등록된 계정 확인 후 불필요한 계정 제거하도록 설정"

diagnose() {
    local status="양호"
    diagnosis_result="GOOD"
    local inspection_summary="관리자 그룹에 불필요한 계정이 없습니다."
    local command_executed="grep -E '^root:|^wheel:' /etc/group"

    # 1. 데이터 추출
    local root_members=$(grep "^root:" /etc/group | cut -d: -f4)
    local wheel_members=$(grep "^wheel:" /etc/group | cut -d: -f4)

    # 2. 판정 로직: root 그룹에 root 외 계정이 있거나, wheel 그룹에 계정이 있는 경우
    # 현업 가이드에서는 관리자 외 계정 존재 시 '취약'으로 간주하고 소명을 받습니다.
    # root 그룹 멤버를 콤마로 분리하여 root 외 계정 존재 여부 확인
    local has_extra_root_member=false
    if [ -n "$root_members" ]; then
        IFS=',' read -ra members <<< "$root_members"
        for m in "${members[@]}"; do
            m=$(echo "$m" | xargs)  # trim whitespace
            if [ -n "$m" ] && [ "$m" != "root" ]; then
                has_extra_root_member=true
                break
            fi
        done
    fi

    if [[ -n "$wheel_members" ]] || [[ "$has_extra_root_member" == true ]]; then
        status="취약"  # 또는 "검토필요"
        diagnosis_result="VULNERABLE"
        inspection_summary="관리자 그룹에 등록된 계정이 식별되었습니다. 인가된 사용자인지 수동 점검이 필요합니다. (발견: ${root_members:-root}, ${wheel_members:-wheel없음})"
    fi

    local command_result="[root: ${root_members:-root}] [wheel: ${wheel_members:-none}]"

    save_dual_result \
        "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" \
        "${inspection_summary}" "${command_result}" "${command_executed}" \
        "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" \
        "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
    
    verify_result_saved "${ITEM_ID}"
}

main() {
    show_diagnosis_start "${ITEM_ID}" "${ITEM_NAME}"
    [ "$EUID" -ne 0 ] && { echo "root 권한이 필요합니다."; exit 1; }
    diagnose
    show_diagnosis_complete "${ITEM_ID}" "${diagnosis_result}"
    exit 0
}

main "$@"
