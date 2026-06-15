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
# @Platform    : Solaris
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

# /etc/default/passwd 형식(KEY=VALUE)에서 키 값 추출 (마지막 정의 우선, POSIX 파이프라인)
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

    # 진단 로직 구현 (KISA 가이드 Solaris 기준: /etc/default/passwd)
    #  - PASSLENGTH >= 8 (비밀번호 최소 길이)
    #  - MAXWEEKS 1~12 (주 단위 최대 사용 기간, 90일 ≈ 12주, 0/미설정은 만료 없음으로 취약)
    #  - MINWEEKS >= 1 (주 단위 최소 사용 기간)
    #  - HISTORY >= 4 (최근 비밀번호 기억 횟수)
    #  - 복잡성: MINDIGIT/MINSPECIAL/MINNONALPHA 중 1개 이상 설정 (영문+숫자/특수문자 조합 강제)

    local passwd_policy_file="/etc/default/passwd"
    local newline=$'\n'
    local policy_output=""
    local config_details=""

    if [ -f "$passwd_policy_file" ] && [ -r "$passwd_policy_file" ]; then
        # Raw output 저장
        policy_output=$(grep -E "^[[:space:]]*(PASSLENGTH|MAXWEEKS|MINWEEKS|HISTORY|MINDIGIT|MINSPECIAL|MINNONALPHA)=" "$passwd_policy_file" 2>/dev/null || echo "관련 정책 키 미설정")

        local passlength=""
        local max_weeks=""
        local min_weeks=""
        local history_count=""
        local min_digit=""
        local min_special=""
        local min_nonalpha=""
        passlength=$(u02_get_key "PASSLENGTH" "$passwd_policy_file")
        max_weeks=$(u02_get_key "MAXWEEKS" "$passwd_policy_file")
        min_weeks=$(u02_get_key "MINWEEKS" "$passwd_policy_file")
        history_count=$(u02_get_key "HISTORY" "$passwd_policy_file")
        min_digit=$(u02_get_key "MINDIGIT" "$passwd_policy_file")
        min_special=$(u02_get_key "MINSPECIAL" "$passwd_policy_file")
        min_nonalpha=$(u02_get_key "MINNONALPHA" "$passwd_policy_file")

        config_details="PASSLENGTH=${passlength:-미설정}, MAXWEEKS=${max_weeks:-미설정}(주), MINWEEKS=${min_weeks:-미설정}(주), HISTORY=${history_count:-미설정}, MINDIGIT=${min_digit:-미설정}, MINSPECIAL=${min_special:-미설정}, MINNONALPHA=${min_nonalpha:-미설정}"

        local passlength_ok=false
        local maxweeks_ok=false
        local minweeks_ok=false
        local history_ok=false
        local complexity_ok=false

        # PASSLENGTH >= 8
        if u02_is_number "$passlength" && [ "$passlength" -ge 8 ]; then
            passlength_ok=true
        fi

        # MAXWEEKS 1~12 (0 또는 미설정은 만료 없음 → 취약)
        if u02_is_number "$max_weeks" && [ "$max_weeks" -ge 1 ] && [ "$max_weeks" -le 12 ]; then
            maxweeks_ok=true
        fi

        # MINWEEKS >= 1
        if u02_is_number "$min_weeks" && [ "$min_weeks" -ge 1 ]; then
            minweeks_ok=true
        fi

        # HISTORY >= 4
        if u02_is_number "$history_count" && [ "$history_count" -ge 4 ]; then
            history_ok=true
        fi

        # 복잡성: MINDIGIT/MINSPECIAL/MINNONALPHA 중 1개 이상 >= 1
        if { u02_is_number "$min_digit" && [ "$min_digit" -ge 1 ]; } || \
           { u02_is_number "$min_special" && [ "$min_special" -ge 1 ]; } || \
           { u02_is_number "$min_nonalpha" && [ "$min_nonalpha" -ge 1 ]; }; then
            complexity_ok=true
        fi

        if [ "$passlength_ok" = true ] && [ "$maxweeks_ok" = true ] && \
           [ "$minweeks_ok" = true ] && [ "$history_ok" = true ] && \
           [ "$complexity_ok" = true ]; then
            diagnosis_result="GOOD"
            status="양호"
            inspection_summary="비밀번호 관리 정책이 적절하게 설정됨 (${config_details})"
        else
            diagnosis_result="VULNERABLE"
            status="취약"
            inspection_summary="비밀번호 관리 정책 미흡: ${config_details} (기준: PASSLENGTH>=8, MAXWEEKS 1~12, MINWEEKS>=1, HISTORY>=4, 복잡성(MINDIGIT/MINSPECIAL/MINNONALPHA) 1개 이상)"
        fi
    else
        # 파일이 없거나 읽을 수 없는 경우 → 수동 점검
        policy_output=$(ls -l "$passwd_policy_file" 2>/dev/null || echo "File not found: ${passwd_policy_file}")
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="/etc/default/passwd 파일이 없거나 읽을 수 없어 비밀번호 관리 정책을 확인하지 못함 - 수동 점검 필요"
    fi

    # 명령어 실행 결과 결합 (raw output)
    command_result="[/etc/default/passwd 비밀번호 정책]${newline}${policy_output}"

    command_executed="grep -E '^(PASSLENGTH|MAXWEEKS|MINWEEKS|HISTORY|MINDIGIT|MINSPECIAL|MINNONALPHA)=' /etc/default/passwd"

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
