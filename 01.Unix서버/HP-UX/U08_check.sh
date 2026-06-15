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
# @Platform    : HP-UX
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
    # 1. /etc/group 에서 root 그룹(GID 0) 행 추출
    local root_group_row=""
    root_group_row=$(grep "^root:" /etc/group 2>/dev/null || echo "")

    local is_vulnerable=false
    local vuln_details=""
    local members=""

    if [ -n "$root_group_row" ]; then
        # Parse members (4th field)
        members=$(echo "$root_group_row" | awk -F: '{print $4}')
        
        local unauthorized_users=""
        
        if [ -n "$members" ]; then
            IFS=',' read -ra ADDR <<< "$members"
            for user in "${ADDR[@]}"; do
                # Trim whitespace
                user=$(echo "$user" | xargs)
                if [ -n "$user" ] && [ "$user" != "root" ]; then
                    # Any user other than 'root' in root group is potentially suspicious
                    unauthorized_users="${unauthorized_users}${user}, "
                    is_vulnerable=true
                fi
            done
        fi
        
        if [ "$is_vulnerable" = true ]; then
            vuln_details="root 그룹에 불필요한 계정 존재: ${unauthorized_users%, }"
        fi
    else
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="root 그룹 설정을 확인할 수 없음 (/etc/group)"
    fi

    # 2. /etc/passwd 에서 기본 GID(4번째 필드)가 0인 root 외 계정 점검
    local gid0_users=""
    gid0_users=$(awk -F: '$4 == 0 && $1 != "root" {print $1}' /etc/passwd 2>/dev/null | xargs || true)
    if [ -n "$gid0_users" ]; then
        is_vulnerable=true
        if [ -n "$vuln_details" ]; then
            vuln_details="${vuln_details} / 기본 그룹(GID 0)이 root인 계정 존재: ${gid0_users// /, }"
        else
            vuln_details="기본 그룹(GID 0)이 root인 계정 존재: ${gid0_users// /, }"
        fi
    fi

    command_result="${root_group_row}${newline}GID 0 계정(/etc/passwd): ${gid0_users:-없음}"
    command_executed="grep '^root:' /etc/group; awk -F: '\$4 == 0 && \$1 != \"root\" {print \$1}' /etc/passwd"

    # 최종 판정 (취약 판정이 수동진단보다 우선)
    if [ "$is_vulnerable" = true ]; then
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="${vuln_details}"
    elif [ "$diagnosis_result" != "MANUAL" ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="관리자 그룹(root)에 불필요한 계정이 존재하지 않음"
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
