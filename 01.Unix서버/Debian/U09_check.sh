#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-19
# ============================================================================
# [점검 항목 상세]
# @ID          : U-09
# @Category    : Unix Server
# @Platform    : Debian
# @Severity    : 하
# @Title       : 계정이 존재하지 않는 GID 금지
# @Description : 시스템에 불필요한 그룹(계정이 없고 멤버도 없는 orphan 그룹)이 존재하는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

set -euo pipefail

# 스크립트 디렉토리 설정
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../../lib"

# 필수 라이브러리 로드
source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/command_validator.sh"
source "${LIB_DIR}/timeout_handler.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/metadata_parser.sh"

ITEM_ID="U-09"
ITEM_NAME="계정이 존재하지 않는 GID 금지"
SEVERITY="하"

# 가이드라인 정보
GUIDELINE_PURPOSE="시스템에 불필요한 그룹이 존재하는지 점검하여 불필요한 그룹의 소유권으로 설정된 파일의 노출로 인해 발생할 수 있는 위험에 대해 대비를 하기 위함"
GUIDELINE_THREAT="계정이 존재하지 않거나 불필요한 그룹이 존재하는 경우, 해당 그룹의 소유로 설정된 파일을 통한 권한 남용 또는 의도치 않은 권한 부여, 보안 감사 및 관리의 어려움 등의 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="시스템 관리나 운용에 불필요한 그룹이 제거된 경우"
GUIDELINE_CRITERIA_BAD="시스템 관리나 운용에 불필요한 그룹이 존재하는 경우"
GUIDELINE_REMEDIATION="불필요한 그룹이 존재하는 경우 관리자와 검토하여 제거하도록 설정 ※ /etc/group 파일과 /etc/passwd 파일을 비교하여 점검하기를 권고 함"

# ============================================================================
# 진단 함수
# ============================================================================

diagnose() {
    diagnosis_result="unknown"
    local status="미진단"
    local inspection_summary=""
    local command_result=""
    local command_executed=""
    local newline=$'\n'

    # 진단 로직 구현
    # 1. /etc/passwd에서 사용 중인 GID(Primary Group) 목록 추출
    # 2. /etc/group에서 정의된 그룹 목록 추출
    # 3. /etc/group의 멤버 필드(4번째) 확인
    # 4. 사용되지 않는 그룹(Primary GID로 안 쓰임 AND 멤버 없음) 식별
    # 단, 시스템 기본 그룹(GID < 1000)은 예외 처리 가능하나, KISA 가이드에 "불필요한 그룹"이 대상이므로,
    # 사용자 정의 그룹 대역(>=1000)에서 orphan 그룹을 찾는 것이 안전함. (시스템 그룹 건드리면 위험)

    local orphan_groups=""
    local orphan_count=0
    local raw_output=""
    
    # GID Threshold (Debian default user start)
    local GID_MIN=1000

    # 1. Collect Used GIDs from passwd
    local used_gids
    used_gids=$(cut -d: -f4 /etc/passwd | sort -u)

    # 2. Check each group in /etc/group
    if [ -f "/etc/group" ]; then
        while IFS=: read -r group_name group_pass group_gid group_members; do
            # Skip system groups usually
            if [[ "$group_gid" -lt "$GID_MIN" ]]; then
                continue
            fi
            
            # Check if GID is in used_gids
            local is_primary=false
            if echo "$used_gids" | grep -q "^${group_gid}$"; then
                is_primary=true
            fi

            # Check if group has members in /etc/group (4th field not empty)
            local has_members=false
            if [ -n "$group_members" ]; then
                has_members=true
            fi

            # Only report if NOT primary AND NO members
            if [ "$is_primary" = false ] && [ "$has_members" = false ]; then
                orphan_groups="${orphan_groups}${group_name}(${group_gid}), "
                raw_output="${raw_output}${group_name}:${group_pass}:${group_gid}:${group_members}${newline}"
                ((orphan_count++)) || true
            fi
        done < /etc/group
    fi

    if [ -n "$raw_output" ]; then
        command_result="[Orphan Groups (GID >= 1000, No Members, Not Primary)]${newline}${raw_output}"
    else
        command_result="[Orphan Groups]${newline}No orphan groups found (GID >= 1000)."
    fi
    
    command_executed="awk -F: '\$3 >= 1000 {print}' /etc/group" 

    # 최종 판정
    if [ "$orphan_count" -gt 0 ]; then
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="계정이 존재하지 않는 GID(불필요한 그룹)가 ${orphan_count}개 존재합니다: ${orphan_groups%, }"
    else
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="계정이 존재하지 않는 GID(불필요한 그룹)가 존재하지 않음"
    fi

    # 결과 저장
    save_dual_result \
        "${ITEM_ID}" \
        "${ITEM_NAME}" \
        "${status}" \
        "${diagnosis_result}" \
        "${inspection_summary}" \
        "${command_result}" \
        "${command_executed}" \
        "${GUIDELINE_PURPOSE}" \
        "${GUIDELINE_THREAT}" \
        "${GUIDELINE_CRITERIA_GOOD}" \
        "${GUIDELINE_CRITERIA_BAD}" \
        "${GUIDELINE_REMEDIATION}"

    verify_result_saved "${ITEM_ID}"

    return 0
}

# ============================================================================
# 메인 실행
# ============================================================================

main() {
    show_diagnosis_start "${ITEM_ID}" "${ITEM_NAME}"
    check_disk_space
    diagnose
    show_diagnosis_complete "${ITEM_ID}" "${diagnosis_result:-UNKNOWN}"
    return 0
}

if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi
