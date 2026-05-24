#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-19
# ============================================================================
# [점검 항목 상세]
# @ID          : U-11
# @Category    : Unix Server
# @Platform    : Debian
# @Severity    : 하
# @Title       : 사용자 shell 점검
# @Description : 로그인이 불필요한 계정(daemon, bin, sys, adm 등)에 쉘 부여 여부 점검
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

ITEM_ID="U-11"
ITEM_NAME="사용자 shell 점검"
SEVERITY="하"

# 가이드라인 정보
GUIDELINE_PURPOSE="로그인이 불필요한 계정에 부여된 쉘을 제거하여, 로그인이 필요하지 않은 계정을 통한 시스템 명령어를 실행하지 못하게 하기 위함"
GUIDELINE_THREAT="로그인이 불필요한 계정에 쉘이 부여될 경우, 비인가자가 해당 기본 계정으로 시스템에 접근 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="로그인이 필요하지 않은 계정에 /bin/false(/sbin/nologin)쉘이 부여된 경우"
GUIDELINE_CRITERIA_BAD="로그인이 필요하지 않은 계정에 /bin/false(/sbin/nologin)쉘이 부여되지 않은 경우"
GUIDELINE_REMEDIATION="로그인이 필요하지 않은 계정에 대해 /bin/false(/sbin/nologin)쉘부여 설정"

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
    # 대상 계정: daemon, bin, sys, adm, listen, nobody, nobody4, noaccess, diag, operator, games, gopher
    # (KISA 가이드 기준)
    
    local target_users=("daemon" "bin" "sys" "adm" "listen" "nobody" "nobody4" "noaccess" "diag" "operator" "games" "gopher")
    local vulnerable_users=""
    local checked_users=""
    
    # Valid nologin shells
    local nologin_patterns="/bin/false|/sbin/nologin|/usr/sbin/nologin|/dev/null"

    local raw_output=""
    
    for user in "${target_users[@]}"; do
        # Check if user exists in /etc/passwd
        local user_entry=$(grep "^${user}:" /etc/passwd 2>/dev/null || echo "")
        
        if [ -n "$user_entry" ]; then
            # Extract shell (7th used field)
            local shell=$(echo "$user_entry" | cut -d: -f7)
            checked_users="${checked_users}${user}, "
            
            # Check if shell is valid nologin
            if ! echo "$shell" | grep -E -q "^(${nologin_patterns})$"; then
                # User has a login shell!
                vulnerable_users="${vulnerable_users}${user}(${shell}), "
            fi
            
            raw_output="${raw_output}${user_entry}${newline}"
        fi
    done

    if [ -z "$raw_output" ]; then
        raw_output="[No target system accounts found (daemon, bin, sys...)]"
    else
        raw_output="[Checked System Accounts]${newline}${raw_output}"
    fi
    
    command_executed="grep -E '^daemon|^bin|^sys|^adm|^listen|^nobody|^nobody4|^noaccess|^diag|^operator|^games|^gopher' /etc/passwd" 

    # 최종 판정
    if [ -n "$vulnerable_users" ]; then
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="로그인이 불필요한 계정에 쉘이 부여됨: ${vulnerable_users%, }"
    else
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="로그인이 불필요한 계정에 쉘이 부여되지 않음 (또는 해당 계정 없음)"
    fi
    
    command_result="${raw_output}"

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
