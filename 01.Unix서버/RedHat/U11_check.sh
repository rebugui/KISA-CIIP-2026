#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-04-20
# ============================================================================
# [점검 항목 상세]
# @ID          : U-11
# @Category    : UNIX > 1. 계정 관리
# @Platform    : RedHat
# @Severity    : 하
# @Title       : 사용자 shell 점검
# @Description : 로그인이 불필요한 계정(adm, sys, daemon 등)에 쉘 부여 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/metadata_parser.sh"

ITEM_ID="U-11"
ITEM_NAME="사용자 shell 점검"
SEVERITY="하"

# 가이드라인 정보
GUIDELINE_PURPOSE="로그인이 불필요한 계정에 부여된 쉘을 제거하여, 로그인이 필요하지 않은 계정을 통한 시스템 명령어를 실행하지 못하게 하기 위함"
GUIDELINE_THREAT="로그인이 불필요한 계정에 쉘이 부여될 경우, 비인가자가 해당 기본 계정으로 시스템에 접근 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="로그인이 필요하지 않은 계정에 /bin/false(/sbin/nologin)쉘이 부여된 경우"
GUIDELINE_CRITERIA_BAD="로그인이 필요하지 않은 계정에 /bin/false(/sbin/nologin)쉘이 부여되지 않은 경우"
GUIDELINE_REMEDIATION="로그인이 필요하지 않은 계정에 대해 /bin/false(/sbin/nologin)쉘부여 설정"

diagnose() {
    local status="양호"
    diagnosis_result="GOOD"
    local inspection_summary="로그인이 불필요한 계정에 제한적인 쉘이 정상 부여되어 있습니다."
    local command_result=""
    local command_executed="cat /etc/passwd | grep -E '^(daemon|bin|sys|adm|listen|nobody|nobody4|noaccess|diag|operator|games|gopher)'"

    # 1. 실제 데이터 추출: 주요 시스템 계정 쉘 확인
    local target_accounts=("daemon" "bin" "sys" "adm" "listen" "nobody" "nobody4" "noaccess" "diag" "operator" "games" "gopher")
    local vulnerable_found=""
    local evidence=""

    for acc in "${target_accounts[@]}"; do
        local shell_val=$(grep "^${acc}:" /etc/passwd | cut -d: -f7)
        if [ -n "$shell_val" ]; then
            evidence+="${acc}(${shell_val}) "
            if [[ ! "$shell_val" =~ (nologin|false)$ ]]; then
                vulnerable_found+="${acc} "
            fi
        fi
    done

    # 2. 판정 로직
    if [ -n "$vulnerable_found" ]; then
        status="취약"
        diagnosis_result="VULNERABLE"
        inspection_summary="일부 시스템 계정에 유효한 쉘이 부여되어 있습니다."
    fi

    # 3. command_result에 실제 계정별 쉘 상태 기록
    command_result="계정별 쉘 현황: [ ${evidence:-없음} ]"

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
