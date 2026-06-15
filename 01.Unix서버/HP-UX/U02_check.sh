#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : U-02
# @Category    : Unix Server
# @Platform    : HP-UX
# @Severity    : 상
# @Title       : 비밀번호 관리 정책 설정
# @Description : 비밀번호 복잡성 설정 및 최소/최대 사용 기간 확인
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


ITEM_ID="U-02"
ITEM_NAME="비밀번호 관리 정책 설정"
SEVERITY="상"

# 가이드라인 정보
GUIDELINE_PURPOSE="사용자의 비밀번호 복잡성과 주기적 변경을 통해 시스템 보안을 강화하기 위함"
GUIDELINE_THREAT="비밀번호 관련 정책이 설정되지 않을 경우, 비인가자의 각종 공격(무차별 대입 공격, 사전 대입 공격 등)에 의해 비밀번호가 노출될 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="비밀번호 관리 정책이 설정된 경우"
GUIDELINE_CRITERIA_BAD="비밀번호 관리 정책이 설정되지 않은 경우"
GUIDELINE_REMEDIATION="root 계정을 포함한 사용자 계정의 비밀번호를 영문, 숫자, 특수 문자를 포함하여 최소 8 자리 이상 및 최소 사용 기간 1일, 최대 사용 기간 90일, 최근 비밀번호 기억 4회 이상으로 설정"

# ============================================================================
# 진단 함수
# ============================================================================

# /etc/default/security 형식(KEY=VALUE)에서 키 값 추출 (마지막 정의 우선, POSIX 파이프라인)
u02_get_key() {
    grep "^[[:space:]]*${1}=" "${2}" 2>/dev/null | tail -1 | cut -d= -f2- | cut -d'#' -f1 | tr -d ' \t\r' || true
}

# 양의 정수(0 포함) 여부 확인
u02_is_number() {
    case "$1" in
        ''|*[!0-9]*) return 1 ;;
        *) return 0 ;;
    esac
}

# 진단 수행
diagnose() {

    diagnosis_result="unknown"
    local status="미진단"
    local inspection_summary=""
    local command_result=""
    local command_executed=""

    # 진단 로직 구현 (KISA 가이드 HP-UX 기준: /etc/default/security)
    #  - MIN_PASSWORD_LENGTH >= 8
    #  - PASSWORD_MAXDAYS 1~90 (일 단위, 0/미설정은 만료 없음으로 취약)
    #  - PASSWORD_MINDAYS >= 1
    #  - HISTORY 값은 참고 증적으로 기록
    # Trusted Mode(/tcb 존재) 여부는 증적에 기록

    local security_file="/etc/default/security"
    local newline=$'\n'
    local security_output=""
    local trusted_note=""
    local config_details=""

    # Trusted Mode 여부 확인 (/tcb 존재 시 Trusted System)
    if [ -d /tcb ]; then
        trusted_note="Trusted Mode(/tcb 존재): trusted DB(/tcb/files/auth) 정책이 우선 적용될 수 있음"
    else
        trusted_note="Trusted Mode 아님 (/tcb 미존재)"
    fi

    if [ -f "$security_file" ] && [ -r "$security_file" ]; then
        # Raw output 저장
        security_output=$(grep -E "^[[:space:]]*(MIN_PASSWORD_LENGTH|PASSWORD_MAXDAYS|PASSWORD_MINDAYS|HISTORY)=" "$security_file" 2>/dev/null || echo "관련 정책 키 미설정")

        local min_password_length=""
        local password_maxdays=""
        local password_mindays=""
        local history_depth=""
        min_password_length=$(u02_get_key "MIN_PASSWORD_LENGTH" "$security_file")
        password_maxdays=$(u02_get_key "PASSWORD_MAXDAYS" "$security_file")
        password_mindays=$(u02_get_key "PASSWORD_MINDAYS" "$security_file")
        history_depth=$(u02_get_key "HISTORY" "$security_file")

        config_details="MIN_PASSWORD_LENGTH=${min_password_length:-미설정}, PASSWORD_MAXDAYS=${password_maxdays:-미설정}, PASSWORD_MINDAYS=${password_mindays:-미설정}, HISTORY=${history_depth:-미설정}"

        local minlen_ok=false
        local maxdays_ok=false
        local mindays_ok=false
        local history_ok=false

        # MIN_PASSWORD_LENGTH >= 8
        if u02_is_number "$min_password_length" && [ "$min_password_length" -ge 8 ]; then
            minlen_ok=true
        fi

        # PASSWORD_MAXDAYS 1~90 (0 또는 미설정은 만료 없음 → 취약)
        if u02_is_number "$password_maxdays" && [ "$password_maxdays" -ge 1 ] && [ "$password_maxdays" -le 90 ]; then
            maxdays_ok=true
        fi

        # PASSWORD_MINDAYS >= 1
        if u02_is_number "$password_mindays" && [ "$password_mindays" -ge 1 ]; then
            mindays_ok=true
        fi

        # HISTORY >= 1 (미설정/0은 비밀번호 재사용 제한 없음 → 취약)
        if u02_is_number "$history_depth" && [ "$history_depth" -ge 1 ]; then
            history_ok=true
        fi

        if [ "$minlen_ok" = true ] && [ "$maxdays_ok" = true ] && [ "$mindays_ok" = true ] && [ "$history_ok" = true ]; then
            diagnosis_result="GOOD"
            status="양호"
            inspection_summary="비밀번호 관리 정책이 적절하게 설정됨 (${config_details}) [${trusted_note}]"
        else
            diagnosis_result="VULNERABLE"
            status="취약"
            inspection_summary="비밀번호 관리 정책 미흡: ${config_details} (기준: MIN_PASSWORD_LENGTH>=8, PASSWORD_MAXDAYS 1~90, PASSWORD_MINDAYS>=1, HISTORY>=1) [${trusted_note}]"
        fi
    else
        # 파일이 없거나 읽을 수 없는 경우 → 수동 점검
        security_output=$(ls -l "$security_file" 2>/dev/null || echo "File not found: ${security_file}")
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="/etc/default/security 파일이 없거나 읽을 수 없어 비밀번호 관리 정책을 확인하지 못함 - 수동 점검 필요 [${trusted_note}]"
    fi

    # 명령어 실행 결과 결합 (raw output)
    command_result="[/etc/default/security 비밀번호 정책]${newline}${security_output}${newline}${newline}[Trusted Mode 확인]${newline}${trusted_note}"

    command_executed="grep -E '^(MIN_PASSWORD_LENGTH|PASSWORD_MAXDAYS|PASSWORD_MINDAYS|HISTORY)=' /etc/default/security; ls -d /tcb"

    #echo ""
    #echo "진단 결과: ${status}"
    #echo "판정: ${diagnosis_result}"
    #echo "설명: ${inspection_summary}"
    #echo ""

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
