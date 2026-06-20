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
    local command_executed="grep -E '^root:|^wheel:' /etc/group; awk -F: '\$4 == 0 && \$1 != \"root\" {print \$1}' /etc/passwd"

    # 1. 데이터 추출 (grep 실패가 local 선언에 가려지지 않도록 선언과 할당 분리)
    local root_group_row=""
    root_group_row=$(grep "^root:" /etc/group 2>/dev/null || true)
    local root_members=""
    root_members=$(printf '%s' "$root_group_row" | cut -d: -f4)
    local wheel_members=""
    wheel_members=$(grep "^wheel:" /etc/group 2>/dev/null | cut -d: -f4 || true)

    # 1-1. /etc/passwd 에서 기본 GID(4번째 필드)가 0인 root 외 계정 점검
    local gid0_users=""
    gid0_users=$(awk -F: '$4 == 0 && $1 != "root" {print $1}' /etc/passwd 2>/dev/null | xargs || true)

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

    # wheel 그룹 멤버에서 root 외 계정 존재 여부 확인 (root는 기본 포함, 불필요한 계정 아님)
    local has_extra_wheel_member=false
    if [ -n "$wheel_members" ]; then
        IFS=',' read -ra wheel_member_arr <<< "$wheel_members"
        for m in "${wheel_member_arr[@]}"; do
            m=$(echo "$m" | xargs)  # trim whitespace
            if [ -n "$m" ] && [ "$m" != "root" ]; then
                has_extra_wheel_member=true
                break
            fi
        done
    fi

    # root 그룹 행을 확인할 수 없으면 수동진단 (취약 판정이 우선)
    if [ -z "$root_group_row" ]; then
        status="수동진단"
        diagnosis_result="MANUAL"
        inspection_summary="root 그룹 설정을 확인할 수 없음 (/etc/group)"
    fi

    # 판정 분기:
    #  - root 그룹에 root 외 계정이 있거나, /etc/passwd 의 기본 GID 0(=root 등가) 계정이
    #    존재하면 unambiguous 하게 취약 (관리자 권한이 root와 동등하게 부여된 비인가 경로)
    #  - wheel 그룹에만 추가 멤버가 있는 경우 KISA 가이드의 criteria_good("root 계정과
    #    시스템 관리에 허용된 계정")에 해당할 수 있으므로 스크립트가 자동으로 취약 판정
    #    할 수 없음 → 수동진단(MANUAL)으로 라우팅하여 운영자 검토 대상으로 표시
    if [[ "$has_extra_root_member" == true ]] || [[ -n "$gid0_users" ]]; then
        status="취약"
        diagnosis_result="VULNERABLE"
        inspection_summary="관리자 권한이 부여된 비인가 계정이 식별되었습니다. (root 그룹 추가 계정: ${root_members:-root}, 기본 GID 0 계정: ${gid0_users:-없음}, wheel: ${wheel_members:-wheel없음})"
    elif [[ "$has_extra_wheel_member" == true ]]; then
        status="수동진단"
        diagnosis_result="MANUAL"
        inspection_summary="wheel 그룹에 root 외 계정이 등록되어 있습니다. 인가된 시스템 관리 계정인지 운영자 확인이 필요합니다. (wheel 멤버: ${wheel_members:-none})"
    fi

    local command_result="[root: ${root_members:-root}] [wheel: ${wheel_members:-none}] [passwd GID0: ${gid0_users:-none}]"

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
