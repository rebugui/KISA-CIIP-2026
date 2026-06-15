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
# @Platform    : Solaris
# @Severity    : 상
# @Title       : 계정 잠금 임계값 설정
# @Description : /etc/default/login RETRIES 및 /etc/security/policy.conf LOCK_AFTER_RETRIES 설정 확인
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
    # Solaris: /etc/default/login RETRIES + /etc/security/policy.conf LOCK_AFTER_RETRIES
    # 잠금이 실제 적용되려면 RETRIES(1~10)와 LOCK_AFTER_RETRIES=YES가 모두 필요

    local newline=$'\n'
    local login_file="/etc/default/login"
    local policy_file="/etc/security/policy.conf"
    local retries_val=""
    local lock_after=""
    local raw_login_output=""
    local raw_policy_output=""
    local files_unreadable=""

    command_executed="grep '^RETRIES' ${login_file}; grep '^LOCK_AFTER_RETRIES' ${policy_file}"

    # 1) /etc/default/login의 RETRIES 확인 (주석 제외)
    if [ -r "$login_file" ]; then
        raw_login_output=$(grep '^RETRIES' "$login_file" 2>/dev/null | tail -1 || true)
        retries_val=$(echo "$raw_login_output" | grep -oE '[0-9]+' | head -1 || true)
        command_result="[FILE: ${login_file}]${newline}${raw_login_output:-RETRIES 설정 없음}${newline}"
    else
        files_unreadable="${login_file}"
        command_result="[FILE: ${login_file}] 파일 없음 또는 읽기 불가${newline}"
    fi

    # 2) /etc/security/policy.conf의 LOCK_AFTER_RETRIES 확인 (판정에 반영)
    if [ -r "$policy_file" ]; then
        raw_policy_output=$(grep '^LOCK_AFTER_RETRIES' "$policy_file" 2>/dev/null | tail -1 || true)
        lock_after=$(echo "$raw_policy_output" | cut -d= -f2 | tr -d '[:space:]' | tr '[:lower:]' '[:upper:]' || true)
        command_result="${command_result}[FILE: ${policy_file}]${newline}${raw_policy_output:-LOCK_AFTER_RETRIES 설정 없음}${newline}"
    else
        files_unreadable="${files_unreadable:+${files_unreadable}, }${policy_file}"
        command_result="${command_result}[FILE: ${policy_file}] 파일 없음 또는 읽기 불가${newline}"
    fi

    # 최종 판정
    # - 점검 파일을 읽을 수 없으면 수동진단
    # - RETRIES 1~10 AND LOCK_AFTER_RETRIES=YES → 양호, 그 외 취약 (0/미설정은 잠금 미적용)
    if [ -n "$files_unreadable" ]; then
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="점검 대상 파일(${files_unreadable})을 읽을 수 없어 계정 잠금 임계값을 확인하지 못함. 수동 점검 필요"
    elif [ -n "$retries_val" ] && [ "$retries_val" -ge 1 ] && [ "$retries_val" -le 10 ] && [ "$lock_after" = "YES" ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="계정 잠금 임계값 적절히 설정됨 (RETRIES=${retries_val}, LOCK_AFTER_RETRIES=YES)"
    else
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="계정 잠금 임계값 미설정 또는 부적절 (RETRIES=${retries_val:-미설정}, LOCK_AFTER_RETRIES=${lock_after:-미설정}; RETRIES 1~10 및 LOCK_AFTER_RETRIES=YES 필요)"
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
