#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.1.0
# @Last Updated: 2026-02-24
# ============================================================================
# [점검 항목 상세]
# @ID          : U-07
# @Category    : Unix Server
# @Platform    : AIX
# @Severity    : 하
# @Title       : 불필요한 계정 제거
# @Description : 불필요한 기본 계정 및 장기 미사용 계정(90일 이상) 존재 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/command_validator.sh"
source "${LIB_DIR}/timeout_handler.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/metadata_parser.sh"

ITEM_ID="U-07"
ITEM_NAME="불필요한 계정 제거"
SEVERITY="하"

GUIDELINE_PURPOSE="불필요한 계정이 존재하는지 점검하여 관리되지 않은 계정에 의한 침입에 대비하는지 확인하기 위함"
GUIDELINE_THREAT="로그인이 가능하고 현재 사용하지 않는 불필요한 계정은 사용 중인 계정보다 상대적으로 관리가 취약하여 공격자의 목표가 되어 계정이 탈취될 수 있는 위험이 존재함(퇴직, 전직, 휴직 등의 사유 발생 시 즉시 권한을 회수하는 것을 권고 함)"
GUIDELINE_CRITERIA_GOOD="불필요한 계정이 존재하지 않는 경우"
GUIDELINE_CRITERIA_BAD="불필요한 계정이 존재하는 경우"
GUIDELINE_REMEDIATION="시스템에 존재하는 계정 확인 후 불필요한 계정 제거하도록 설정"

diagnose() {
    diagnosis_result="unknown"
    local status="미진단"
    local inspection_summary=""
    local command_result=""
    local command_executed=""
    local newline=$'\n'

    local is_vulnerable=false
    local unused_accounts=""
    
    local checkable_accounts=""
    if [ -f /etc/passwd ]; then
        checkable_accounts=$(awk -F: '$3 >= 1000 && $7 !~ /nologin|false/ {print $1}' /etc/passwd 2>/dev/null || echo "")
    fi
    
    local recent_login_accounts=""
    local inactive_threshold_days=90
    
    if command -v last >/dev/null 2>&1; then
        recent_login_accounts=$(last -s "-${inactive_threshold_days}d" 2>/dev/null | awk 'NR>1 && $1 !~ /^(reboot|shutdown|wtmp)$/ {print $1}' | sort -u || echo "")
    fi
    
    if [ -n "$checkable_accounts" ]; then
        while IFS= read -r account; do
            [ -z "$account" ] && continue
            if [ -z "$recent_login_accounts" ] || ! echo "$recent_login_accounts" | grep -qw "^${account}$"; then
                unused_accounts="${unused_accounts}${account} "
                is_vulnerable=true
            fi
        done <<< "$checkable_accounts"
    fi
    
    local passwd_check_output=""
    local last_check_output=""
    
    passwd_check_output="점검 대상 계정 (UID>=1000, 로그인 가능):"
    if [ -n "$checkable_accounts" ]; then
        passwd_check_output="${passwd_check_output}${newline}$(echo "$checkable_accounts" | tr '\n' ' ')"
    else
        passwd_check_output="${passwd_check_output}${newline}없음"
    fi
    
    if command -v last >/dev/null 2>&1; then
        last_check_output="최근 90일 내 로그인 계정:"
        if [ -n "$recent_login_accounts" ]; then
            last_check_output="${last_check_output}${newline}$(echo "$recent_login_accounts" | tr '\n' ' ')"
        else
            last_check_output="${last_check_output}${newline}없음"
        fi
    else
        last_check_output="last 명령어 없음"
    fi
    
    command_result="[Check 1: /etc/passwd 필터링]${newline}${passwd_check_output}${newline}${newline}[Check 2: last -s -90d (AIX)]${newline}${last_check_output}"
    command_executed="awk -F: '\$3 >= 1000 && \$7 !~ /nologin|false/ {print \$1}' /etc/passwd; last -s -90d"

    if [ "$is_vulnerable" = true ]; then
        diagnosis_result="VULNERABLE"
        status="취약"
        unused_accounts=$(echo "$unused_accounts" | tr -s ' ' | sed 's/^ *//;s/ *$//')
        inspection_summary="90일 이상 미사용 계정 발견: ${unused_accounts}"
    else
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="90일 이상 미사용 계정 없음 (시스템 계정 및 로그인 불가 계정은 점검 대상에서 제외됨)"
    fi

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
