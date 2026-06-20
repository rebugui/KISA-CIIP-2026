#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : U-03
# @Category    : Unix Server
# @Platform    : Debian
# @Severity    : 상
# @Title       : 계정 잠금 임계값 설정
# @Description : pam_faillock.so 또는 faillock 설정 확인
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


ITEM_ID="U-03"
ITEM_NAME="계정 잠금 임계값 설정"
SEVERITY="상"

# 가이드라인 정보
GUIDELINE_PURPOSE="계정 탈취 목적의 무차별 대입 공격 시 해당 계정을 잠금으로써 인증 요청에 응답하는 리소스 낭비를 차단하고 대입 공격으로 인한 비밀번호 노출 공격을 무력화하기 위함"
GUIDELINE_THREAT="계정 잠금 임계값이 설정되어 있지 않을 경우, 비밀번호 탈취 공격(무차별 대입 공격, 사전 대입 공격, 추측 공격 등)의 인증 요청에 대해 설정된 비밀번호가 일치할 때까지 지속적으로 응답하여 해당 계정의 비밀번호가 유출될 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="계정 잠금 임계값이 10회 이하의 값으로 설정된 경우"
GUIDELINE_CRITERIA_BAD="계정 잠금 임계값이 설정되어 있지 않거나, 10회 이하의 값으로 설정되지 않은 경우"
GUIDELINE_REMEDIATION="계정 잠금 임계값을 10회 이하로 설정"

# ============================================================================
# 진단 함수
# ============================================================================

# 진단 수행
diagnose() {
    echo "===================================================================" >&2
    echo "진단 항목: ${ITEM_ID} - ${ITEM_NAME}" >&2
    echo "심각도: ${SEVERITY}" >&2
    echo "===================================================================" >&2
    echo "" >&2

    diagnosis_result="unknown"
    status="미진단"
    inspection_summary=""
    command_result=""
    command_executed=""

    # 진단 로직 구현
    # pam_faillock.so 또는 faillock 설정 확인
    # KISA Debian 가이드라인: /etc/pam.d/common-auth (Step 1) 및
    # /etc/pam.d/common-account (Step 2) 두 파일 모두에 pam_faillock.so가
    # 설정되어야 계정 잠금이 실제로 강제됨. 중앙 설정은 /etc/security/faillock.conf.

    local newline=$'\n'

    # 비주석 pam_faillock/pam_tally2 라인에서 deny 값 추출 (RedHat U-03 패턴 미러)
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

    deny_in_range() {
        [ -n "$1" ] && [ "$1" -ge 1 ] && [ "$1" -le 10 ]
    }

    # Debian 기준 두 단계 PAM 설정 + 중앙 faillock.conf
    local auth_deny acct_deny conf_deny=""
    auth_deny=$(extract_pam_deny /etc/pam.d/common-auth)
    acct_deny=$(extract_pam_deny /etc/pam.d/common-account)
    # 추가 보조 파일(존재 시) — 보고용 raw 출력에만 활용
    local sys_deny pw_deny login_deny
    sys_deny=$(extract_pam_deny /etc/pam.d/system-auth)
    pw_deny=$(extract_pam_deny /etc/pam.d/password-auth)
    login_deny=$(extract_pam_deny /etc/pam.d/login)

    if [ -r /etc/security/faillock.conf ]; then
        conf_deny=$(grep -E '^[[:space:]]*deny[[:space:]]*=' /etc/security/faillock.conf 2>/dev/null \
            | grep -vE '^[[:space:]]*#' \
            | grep -oE '[0-9]+' | head -n 1 || true)
    fi

    # 판정: 중앙 faillock.conf의 deny가 1~10이면 양호,
    # 그렇지 않으면 common-auth와 common-account 두 파일 모두 1~10이어야 양호.
    local is_secure=false
    local config_details=""
    if deny_in_range "$conf_deny"; then
        is_secure=true
        config_details="/etc/security/faillock.conf deny=${conf_deny}"
    elif deny_in_range "$auth_deny" && deny_in_range "$acct_deny"; then
        is_secure=true
        config_details="common-auth deny=${auth_deny}, common-account deny=${acct_deny}"
    elif deny_in_range "$auth_deny" || deny_in_range "$acct_deny"; then
        config_details="한쪽 PAM 파일에만 설정되어 미보호 인증 경로 존재 (common-auth deny=${auth_deny:-미설정}, common-account deny=${acct_deny:-미설정})"
    else
        config_details="common-auth deny=${auth_deny:-미설정}, common-account deny=${acct_deny:-미설정}, faillock.conf deny=${conf_deny:-미설정}"
    fi

    # --- 명령어 실행 및 원본 출력 캡처 ---
    local raw_pam_output=""
    local pam_files_for_report=(
        "/etc/pam.d/common-auth"
        "/etc/pam.d/common-account"
        "/etc/pam.d/system-auth"
        "/etc/pam.d/password-auth"
        "/etc/pam.d/login"
    )
    for pam_file in "${pam_files_for_report[@]}"; do
        if [ -f "$pam_file" ]; then
            local grep_result=""
            grep_result=$(grep -E "pam_faillock.so|pam_tally2.so" "$pam_file" 2>/dev/null || echo "")
            if [ -n "$grep_result" ]; then
                raw_pam_output="${raw_pam_output}[${pam_file}]${newline}${grep_result}${newline}"
            fi
        fi
    done
    if [ -z "$raw_pam_output" ]; then
        raw_pam_output="[No pam_faillock.so or pam_tally2.so found in PAM configuration files]${newline}"
    fi

    local conf_output=""
    if [ -r /etc/security/faillock.conf ]; then
        conf_output=$(grep -E '^[[:space:]]*deny[[:space:]]*=' /etc/security/faillock.conf 2>/dev/null | grep -vE '^[[:space:]]*#' || echo "")
    fi

    command_result="[common-auth] deny=${auth_deny:-미설정} | [common-account] deny=${acct_deny:-미설정} | [system-auth] deny=${sys_deny:-미설정} | [password-auth] deny=${pw_deny:-미설정} | [login] deny=${login_deny:-미설정} | [faillock.conf] deny=${conf_deny:-미설정}${newline}${raw_pam_output}"
    if [ -n "$conf_output" ]; then
        command_result="${command_result}[FILE: /etc/security/faillock.conf]${newline}${conf_output}${newline}"
    fi
    command_executed="grep -E 'pam_faillock.so|pam_tally2.so' /etc/pam.d/{common-auth,common-account,system-auth,password-auth,login}; grep -E '^deny' /etc/security/faillock.conf"

    # 최종 판정
    if [ "$is_secure" = true ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="계정 잠금 임계값 적절히 설정됨 (${config_details})"
    else
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="계정 잠금 임계값 미설정 또는 부적절 (${config_details})"
    fi

    echo "" >&2
  #  echo "진단 결과: ${status}" >&2
  # echo "판정: ${diagnosis_result}" >&2
  # echo "설명: ${inspection_summary}" >&2
    echo "" >&2

    # 결과 생성 (PC 패턴: 스크립트에서 모드 확인 후 처리)
    # Run-all 모드 확인
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

    # 결과 저장 확인
    verify_result_saved "${ITEM_ID}"


    return 0
}

# ============================================================================
# 메인 실행
# ============================================================================

main() {
    # 진단 시작 표시
    show_diagnosis_start "${ITEM_ID}" "${ITEM_NAME}"

    # 디스크 공간 확인
    check_disk_space

    # 진단 수행
    diagnose

    # 진단 완료 표시
    show_diagnosis_complete "${ITEM_ID}" "${diagnosis_result:-UNKNOWN}"

    return 0
}

# 스크립트 직접 실행 시에만 진단 수행
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi
