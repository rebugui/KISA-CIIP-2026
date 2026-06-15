#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-04-20
# ============================================================================
# [점검 항목 상세]
# @ID          : U-02
# @Category    : UNIX > 1. 계정 관리
# @Platform    : RedHat
# @Severity    : 상
# @Title       : 비밀번호 관리 정책 설정
# @Description : 비밀번호의 복잡성 설정(길이, 숫자, 대소문자, 특수문자 등) 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/metadata_parser.sh"

ITEM_ID="U-02"
ITEM_NAME="비밀번호 관리 정책 설정"
SEVERITY="상"

# 가이드라인 정보
GUIDELINE_PURPOSE="사용자의 비밀번호 복잡성과 주기적 변경을 통해 시스템 보안을 강화하기 위함"
GUIDELINE_THREAT="비밀번호 관련 정책이 설정되지 않을 경우, 비인가자의 각종 공격(무차별 대입 공격, 사전 대입 공격 등)에 의해 비밀번호가 노출될 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="비밀번호 관리 정책이 설정된 경우"
GUIDELINE_CRITERIA_BAD="비밀번호 관리 정책이 설정되지 않은 경우"
GUIDELINE_REMEDIATION="root 계정을 포함한 사용자 계정의 비밀번호를 영문, 숫자, 특수 문자를 포함하여 최소 8 자리 이상 및 최소 사용 기간 1일, 최대 사용 기간 90일, 최근 비밀번호 기억 4회 이상으로 설정"

# 정수 형식 검증 (선택적 음수 부호 + 숫자)
is_integer() {
    case "$1" in
        ''|*[!0-9-]*) return 1 ;;
    esac
    [[ "$1" =~ ^-?[0-9]+$ ]]
}

# 복잡성 키 추출: pwquality.conf 우선, 없으면 system-auth의 pam_pwquality 라인 인자
# (가이드: 두 파일 중 하나라도 정책이 설정되어 있으면 인정)
get_pwquality_value() {
    local key="$1"
    local val=""
    if [ -f /etc/security/pwquality.conf ]; then
        val=$(grep -E "^[[:space:]]*${key}[[:space:]]*=" /etc/security/pwquality.conf 2>/dev/null \
            | tail -n 1 | awk -F'=' '{print $2}' | awk '{print $1}' || true)
    fi
    if [ -z "$val" ] && [ -f /etc/pam.d/system-auth ]; then
        val=$(grep -E '^[^#]*pam_pwquality\.so' /etc/pam.d/system-auth 2>/dev/null \
            | grep -oE "${key}=[^[:space:]]+" | tail -n 1 | cut -d'=' -f2 || true)
    fi
    echo "$val"
}

diagnose() {
    local status="양호"
    diagnosis_result="GOOD"
    local inspection_summary="비밀번호 관리 정책(복잡성, 사용 기간, 이력)이 적절히 설정되어 있습니다."
    local command_result=""
    local command_executed="grep -E '^(minlen|dcredit|ucredit|lcredit|ocredit)' /etc/security/pwquality.conf; grep pam_pwquality /etc/pam.d/system-auth; grep -E '^PASS_(MAX|MIN)_DAYS' /etc/login.defs; grep remember /etc/security/pwhistory.conf /etc/pam.d/system-auth"
    local issues=""

    # ------------------------------------------------------------------
    # [1] 복잡성 정책: minlen >= 8, dcredit/ucredit/lcredit/ocredit <= -1
    #     (pwquality.conf 또는 system-auth pam_pwquality 인자)
    #     형식 오류(비정수) 값은 해당 키 취약 처리 (조용한 GOOD 금지)
    # ------------------------------------------------------------------
    local minlen dcredit ucredit lcredit ocredit
    minlen=$(get_pwquality_value "minlen")
    dcredit=$(get_pwquality_value "dcredit")
    ucredit=$(get_pwquality_value "ucredit")
    lcredit=$(get_pwquality_value "lcredit")
    ocredit=$(get_pwquality_value "ocredit")

    if [ -z "$minlen" ]; then
        issues="${issues}minlen 미설정; "
    elif ! is_integer "$minlen"; then
        issues="${issues}minlen 값 형식 오류(${minlen}); "
    elif [ "$minlen" -lt 8 ]; then
        issues="${issues}minlen ${minlen} (<8); "
    fi

    local credit_key credit_val
    for credit_key in dcredit ucredit lcredit ocredit; do
        case "$credit_key" in
            dcredit) credit_val="$dcredit" ;;
            ucredit) credit_val="$ucredit" ;;
            lcredit) credit_val="$lcredit" ;;
            ocredit) credit_val="$ocredit" ;;
        esac
        if [ -z "$credit_val" ]; then
            issues="${issues}${credit_key} 미설정; "
        elif ! is_integer "$credit_val"; then
            issues="${issues}${credit_key} 값 형식 오류(${credit_val}); "
        elif [ "$credit_val" -gt -1 ]; then
            issues="${issues}${credit_key} ${credit_val} (>-1); "
        fi
    done

    # ------------------------------------------------------------------
    # [2] 사용 기간 정책: login.defs PASS_MAX_DAYS 1~90, PASS_MIN_DAYS >= 1
    # ------------------------------------------------------------------
    local pass_max_days pass_min_days
    pass_max_days=$(grep -E '^[[:space:]]*PASS_MAX_DAYS[[:space:]]' /etc/login.defs 2>/dev/null \
        | tail -n 1 | awk '{print $2}' || true)
    pass_min_days=$(grep -E '^[[:space:]]*PASS_MIN_DAYS[[:space:]]' /etc/login.defs 2>/dev/null \
        | tail -n 1 | awk '{print $2}' || true)

    if [ -z "$pass_max_days" ]; then
        issues="${issues}PASS_MAX_DAYS 미설정; "
    elif ! is_integer "$pass_max_days"; then
        issues="${issues}PASS_MAX_DAYS 값 형식 오류(${pass_max_days}); "
    elif [ "$pass_max_days" -gt 90 ] || [ "$pass_max_days" -lt 1 ]; then
        issues="${issues}PASS_MAX_DAYS ${pass_max_days} (1~90 아님); "
    fi

    if [ -z "$pass_min_days" ]; then
        issues="${issues}PASS_MIN_DAYS 미설정; "
    elif ! is_integer "$pass_min_days"; then
        issues="${issues}PASS_MIN_DAYS 값 형식 오류(${pass_min_days}); "
    elif [ "$pass_min_days" -lt 1 ]; then
        issues="${issues}PASS_MIN_DAYS ${pass_min_days} (<1); "
    fi

    # ------------------------------------------------------------------
    # [3] 이력 정책: pwhistory remember >= 4
    #     (pwhistory.conf 또는 system-auth pam_pwhistory 인자)
    # ------------------------------------------------------------------
    local remember=""
    if [ -f /etc/security/pwhistory.conf ]; then
        remember=$(grep -E '^[[:space:]]*remember[[:space:]]*=' /etc/security/pwhistory.conf 2>/dev/null \
            | tail -n 1 | awk -F'=' '{print $2}' | awk '{print $1}' || true)
    fi
    if [ -z "$remember" ] && [ -f /etc/pam.d/system-auth ]; then
        remember=$(grep -E '^[^#]*pam_pwhistory\.so' /etc/pam.d/system-auth 2>/dev/null \
            | grep -oE 'remember=[^[:space:]]+' | tail -n 1 | cut -d'=' -f2 || true)
    fi

    if [ -z "$remember" ]; then
        issues="${issues}비밀번호 이력(remember) 미설정; "
    elif ! is_integer "$remember"; then
        issues="${issues}remember 값 형식 오류(${remember}); "
    elif [ "$remember" -lt 4 ]; then
        issues="${issues}remember ${remember} (<4); "
    fi

    # ------------------------------------------------------------------
    # 판정: 하나라도 미흡하면 취약
    # ------------------------------------------------------------------
    if [ -n "$issues" ]; then
        status="취약"
        diagnosis_result="VULNERABLE"
        inspection_summary="비밀번호 관리 정책 미흡: ${issues% }"
    fi

    command_result="[복잡성] minlen=${minlen:-미설정}, dcredit=${dcredit:-미설정}, ucredit=${ucredit:-미설정}, lcredit=${lcredit:-미설정}, ocredit=${ocredit:-미설정} | [기간] PASS_MAX_DAYS=${pass_max_days:-미설정}, PASS_MIN_DAYS=${pass_min_days:-미설정} | [이력] remember=${remember:-미설정}"

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
