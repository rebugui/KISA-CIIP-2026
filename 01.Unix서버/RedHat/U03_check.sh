#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-04-20
# ============================================================================
# [점검 항목 상세]
# @ID          : U-03
# @Category    : UNIX > 1. 계정 관리
# @Platform    : RedHat
# @Severity    : 상
# @Title       : 계정 잠금 임계값 설정
# @Description : 계정 접속 시도 실패 시 계정 잠금 임계값 설정 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/metadata_parser.sh"

ITEM_ID="U-03"
ITEM_NAME="계정 잠금 임계값 설정"
SEVERITY="상"

# 가이드라인 정보
GUIDELINE_PURPOSE="계정 탈취 목적의 무차별 대입 공격 시 해당 계정을 잠금으로써 인증 요청에 응답하는 리소스 낭비를 차단하고 대입 공격으로 인한 비밀번호 노출 공격을 무력화하기 위함"
GUIDELINE_THREAT="계정 잠금 임계값이 설정되어 있지 않을 경우, 비밀번호 탈취 공격(무차별 대입 공격, 사전 대입 공격, 추측 공격 등)의 인증 요청에 대해 설정된 비밀번호가 일치할 때까지 지속적으로 응답하여 해당 계정의 비밀번호가 유출될 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="계정 잠금 임계값이 10회 이하의 값으로 설정된 경우"
GUIDELINE_CRITERIA_BAD="계정 잠금 임계값이 설정되어 있지 않거나, 10회 이하의 값으로 설정되지 않은 경우"
GUIDELINE_REMEDIATION="계정 잠금 임계값을 10회 이하로 설정"

# 비주석 pam_faillock/pam_tally2 라인에서 deny 값 추출
extract_pam_deny() {
    local file="$1"
    local val=""
    if [ -r "$file" ]; then
        val=$(grep -E 'pam_faillock\.so|pam_tally2\.so' "$file" 2>/dev/null \
            | grep -vE '^[[:space:]]*#' \
            | grep -oE 'deny=[0-9]+' | cut -d= -f2 | head -n 1 || true)
    fi
    echo "$val"
}

# 잠금 임계값이 1~10 범위인지 확인 (0은 잠금 미적용)
deny_in_range() {
    [ -n "$1" ] && [ "$1" -ge 1 ] && [ "$1" -le 10 ]
}

diagnose() {
    local status="취약"
    diagnosis_result="VULNERABLE"
    local inspection_summary=""
    local command_result=""
    local command_executed="grep -E 'pam_faillock|pam_tally2' /etc/pam.d/system-auth /etc/pam.d/password-auth; grep -E '^deny' /etc/security/faillock.conf"

    # 1. 실제 데이터 추출 (RedHat 기준)
    # deny는 system-auth와 password-auth 양쪽 모두에 적용되거나,
    # /etc/security/faillock.conf에 중앙 설정되어야 함
    local sys_deny pw_deny conf_deny
    sys_deny=$(extract_pam_deny /etc/pam.d/system-auth)
    pw_deny=$(extract_pam_deny /etc/pam.d/password-auth)
    conf_deny=""
    if [ -r /etc/security/faillock.conf ]; then
        conf_deny=$(grep -E '^[[:space:]]*deny[[:space:]]*=' /etc/security/faillock.conf 2>/dev/null \
            | grep -oE '[0-9]+' | head -n 1 || true)
    fi

    # 2. 판정 로직 (faillock.conf 중앙 설정 또는 두 PAM 파일 모두 1~10 설정 시 양호)
    if deny_in_range "$conf_deny"; then
        status="양호"
        diagnosis_result="GOOD"
        inspection_summary="계정 잠금 임계값이 /etc/security/faillock.conf에 적절히 설정됨 (deny=${conf_deny})"
    elif deny_in_range "$sys_deny" && deny_in_range "$pw_deny"; then
        status="양호"
        diagnosis_result="GOOD"
        inspection_summary="계정 잠금 임계값이 system-auth/password-auth 모두 적절히 설정됨 (deny=${sys_deny}/${pw_deny})"
    elif deny_in_range "$sys_deny" || deny_in_range "$pw_deny"; then
        inspection_summary="계정 잠금 임계값이 한쪽 PAM 파일에만 설정되어 미보호 인증 경로가 존재함 (system-auth deny=${sys_deny:-미설정}, password-auth deny=${pw_deny:-미설정})"
    else
        inspection_summary="계정 잠금 임계값이 설정되지 않았거나 기준(1~10회)을 벗어남 (system-auth deny=${sys_deny:-미설정}, password-auth deny=${pw_deny:-미설정}, faillock.conf deny=${conf_deny:-미설정})"
    fi

    # 3. command_result에 실제 설정값 기록 (개행 제거)
    command_result="[system-auth] deny=${sys_deny:-미설정} | [password-auth] deny=${pw_deny:-미설정} | [faillock.conf] deny=${conf_deny:-미설정}"

    # [중요] U-02와 동일하게 12개의 인자를 모두 전달
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
