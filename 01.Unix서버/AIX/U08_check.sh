#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-19
# ============================================================================
# [점검 항목 상세]
# @ID          : U-08
# @Category    : Unix Server
# @Platform    : AIX
# @Severity    : 중
# @Title       : 관리자 그룹에 최소한의 계정 포함
# @Description : 시스템 관리자 그룹(root)에 불필요한 계정이 포함되어 있는지 점검
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

ITEM_ID="U-08"
ITEM_NAME="관리자 그룹에 최소한의 계정 포함"
SEVERITY="중"

# 가이드라인 정보
GUIDELINE_PURPOSE="관리자 그룹에 최소한의 필요 계정만 존재하는지 확인하여 불필요한 권한 남용을 점검하기 위함"
GUIDELINE_THREAT="시스템을 관리하는 root 계정이 속한 그룹은 시스템 운영 파일에 대한 접근 권한이 부여되어 있으므로 해당 관리자 그룹에 속한 계정이 비인가자에게 유출될 경우, 관리자 권한으로 시스템에 접근하여 계정 정보 유출, 환경 설정 파일 및 디렉터리 변조 등의 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="관리자 그룹에 불필요한 계정이 등록되어 있지 않은 경우"
GUIDELINE_CRITERIA_BAD="관리자 그룹에 불필요한 계정이 등록된 경우"
GUIDELINE_REMEDIATION="관리자 그룹에 등록된 계정 확인 후 불필요한 계정 제거하도록 설정"

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
    # 1. /etc/group 에서 root 그룹 확인 (AIX에서는 root, system 그룹 중요)
    # 가이드라인은 'root' 그룹을 명시 ($U-08 Guide: # chgrpmem -m - <user> root)
    
    local root_group_row=""
    root_group_row=$(grep "^system:" /etc/group 2>/dev/null || echo "")
    # AIX's 'root' often maps to 'system' group for admin dominance, but 'root' group also exists.
    # Checking both 'root' and 'system' might be safer, but let's stick to 'system' + 'root' or just 'root'?
    # KISA Guide Example: "Step 1) /etc/group 파일에 root 그룹에 포함된 계정 확인"
    # AIX Note in Guide: "AIX uses chgrpmem ... root" -> Implies checking 'root' group.
    
    local root_group_check=$(grep "^root:" /etc/group 2>/dev/null || echo "")
    local system_group_check=$(grep "^system:" /etc/group 2>/dev/null || echo "")
    # 이름이 변경된 관리자 그룹도 GID 0 번호 기준으로 수집
    local gid0_group_check=$(awk -F: '$3 == 0' /etc/group 2>/dev/null || echo "")

    local is_vulnerable=false
    local vuln_details=""

    # Check admin groups by name (root/system) AND by GID 0 number
    local admin_group_lines=""
    admin_group_lines=$(printf '%s\n%s\n%s\n' "$root_group_check" "$system_group_check" "$gid0_group_check" | awk 'NF' | sort -u || true)

    local group_name group_line members unauthorized user
    while IFS= read -r group_line; do
        [ -z "$group_line" ] && continue
        group_name=$(echo "$group_line" | awk -F: '{print $1}')
        members=$(echo "$group_line" | awk -F: '{print $4}')
        unauthorized=""
        if [ -n "$members" ]; then
             IFS=',' read -ra ADDR <<< "$members"
             for user in "${ADDR[@]}"; do
                 user=$(echo "$user" | xargs)
                 if [ -n "$user" ] && [ "$user" != "root" ]; then
                     unauthorized="${unauthorized}${user}, "
                     is_vulnerable=true
                 fi
             done
        fi
        if [ -n "$unauthorized" ]; then
             vuln_details="${vuln_details}[${group_name} group] 불필요 계정: ${unauthorized%, }; "
        fi
    done <<< "$admin_group_lines"

    # /etc/passwd 기본 그룹 점검: primary group이 GID 0인 root 외 계정
    local passwd_gid0=""
    passwd_gid0=$(awk -F: '$4 == 0 && $1 != "root" {print $1}' /etc/passwd 2>/dev/null | tr '\n' ',' | sed 's/,$//' || echo "")
    if [ -n "$passwd_gid0" ]; then
        is_vulnerable=true
        vuln_details="${vuln_details}[passwd primary GID 0] 불필요 계정: ${passwd_gid0}; "
    fi

    command_result="[Check: root group]${newline}${root_group_check}${newline}${newline}[Check: system group]${newline}${system_group_check}${newline}${newline}[Check: GID 0 groups]${newline}${gid0_group_check}${newline}${newline}[Check: passwd primary GID 0 (root 제외)]${newline}${passwd_gid0:-없음}"
    command_executed="grep '^root:' /etc/group; grep '^system:' /etc/group; awk -F: '\$3==0' /etc/group; awk -F: '\$4==0 && \$1!=\"root\"' /etc/passwd"

    if [ -z "$root_group_check" ] && [ -z "$system_group_check" ] && [ -z "$gid0_group_check" ]; then
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="/etc/group에서 root/system 그룹 정보를 확인할 수 없어 수동 점검 필요"
    elif [ "$is_vulnerable" = true ]; then
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="${vuln_details} 확인됨"
    else
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="관리자 그룹(root/system)에 불필요한 계정이 존재하지 않음"
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
