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
# @Platform    : Debian
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

# 진단 수행
diagnose() {

    diagnosis_result="unknown"
    local status="미진단"
    local inspection_summary=""
    local command_result=""
    local command_executed=""

    # 진단 로직 구현
    # 1) PAM 복잡성 설정 확인 (pam_pwquality.so 또는 pam_cracklib.so)
    # 2) /etc/login.defs의 PASS_MAX_DAYS, PASS_MIN_DAYS 확인

    local is_secure=false
    local config_details=""
    local found_pam_module=false
    local complexity_ok=false
    local age_ok=false

    # Raw command outputs
    local pam_output=""
    local login_defs_output=""
    local newline=$'\n'

    # ============================================================================
    # 1) PAM 복잡성 설정 확인
    # ============================================================================
    local pam_files=(
        "/etc/pam.d/common-password"
        "/etc/pam.d/common-auth"
        "/etc/pam.d/system-auth"
        "/etc/pam.d/passwd"
    )

    local active_pam_file=""
    local pam_module=""

    for pam_file in "${pam_files[@]}"; do
        if [ -f "$pam_file" ]; then
            # pam_pwquality.so 또는 pam_cracklib.so 확인
            if grep -q "pam_pwquality.so" "$pam_file"; then
                pam_module="pam_pwquality.so"
                found_pam_module=true
                active_pam_file="$pam_file"
                break
            elif grep -q "pam_cracklib.so" "$pam_file"; then
                pam_module="pam_cracklib.so"
                found_pam_module=true
                active_pam_file="$pam_file"
                break
            fi
        fi
    done || true

    if [ "$found_pam_module" = true ]; then
        # PAM 설정의 raw output 저장
        pam_output=$(grep -E "^[\s]*password.*${pam_module}" "$active_pam_file" 2>/dev/null || echo "")

        # 각 설정값 추출 (인라인 PAM 인자 우선)
        local minlen=$(echo "$pam_output" | grep -oP 'minlen=\K[0-9]+' | head -1)
        local ucredit=$(echo "$pam_output" | grep -oP 'ucredit=\K-?[0-9]+' | head -1)
        local lcredit=$(echo "$pam_output" | grep -oP 'lcredit=\K-?[0-9]+' | head -1)
        local dcredit=$(echo "$pam_output" | grep -oP 'dcredit=\K-?[0-9]+' | head -1)
        local ocredit=$(echo "$pam_output" | grep -oP 'ocredit=\K-?[0-9]+' | head -1)

        # 인라인 인자가 없으면 /etc/security/pwquality.conf 에서 보완
        # (KISA Debian 가이드: pwquality.conf 또는 common-password 중 하나라도 정책 설정 시 양호)
        local pwquality_conf="/etc/security/pwquality.conf"
        if [ -f "$pwquality_conf" ]; then
            [ -z "$minlen" ]  && minlen=$(grep -oP '^\s*minlen\s*=\s*\K[0-9]+' "$pwquality_conf" 2>/dev/null | tail -1)
            [ -z "$ucredit" ] && ucredit=$(grep -oP '^\s*ucredit\s*=\s*\K-?[0-9]+' "$pwquality_conf" 2>/dev/null | tail -1)
            [ -z "$lcredit" ] && lcredit=$(grep -oP '^\s*lcredit\s*=\s*\K-?[0-9]+' "$pwquality_conf" 2>/dev/null | tail -1)
            [ -z "$dcredit" ] && dcredit=$(grep -oP '^\s*dcredit\s*=\s*\K-?[0-9]+' "$pwquality_conf" 2>/dev/null | tail -1)
            [ -z "$ocredit" ] && ocredit=$(grep -oP '^\s*ocredit\s*=\s*\K-?[0-9]+' "$pwquality_conf" 2>/dev/null | tail -1)
        fi

        config_details="[PAM 복잡성] ${pam_module}: "
        config_details="${config_details}minlen=${minlen:-미설정}, "
        config_details="${config_details}ucredit=${ucredit:-미설정}, "
        config_details="${config_details}lcredit=${lcredit:-미설정}, "
        config_details="${config_details}dcredit=${dcredit:-미설정}, "
        config_details="${config_details}ocredit=${ocredit:-미설정}"

        # 판정: 모든 설정이 적절한지 확인
        # minlen >= 8, ucredit <= -1, lcredit <= -1, dcredit <= -1, ocredit <= -1
        local minlen_ok=false
        local ucredit_ok=false
        local lcredit_ok=false
        local dcredit_ok=false
        local ocredit_ok=false

        if [ -n "$minlen" ] && [ "$minlen" -ge 8 ]; then
            minlen_ok=true
        fi

        if [ -n "$ucredit" ] && [ "$ucredit" -le -1 ]; then
            ucredit_ok=true
        fi

        if [ -n "$lcredit" ] && [ "$lcredit" -le -1 ]; then
            lcredit_ok=true
        fi

        if [ -n "$dcredit" ] && [ "$dcredit" -le -1 ]; then
            dcredit_ok=true
        fi

        if [ -n "$ocredit" ] && [ "$ocredit" -le -1 ]; then
            ocredit_ok=true
        fi

        # 모든 조건 충족 시 양호
        if [ "$minlen_ok" = true ] && [ "$ucredit_ok" = true ] && \
           [ "$lcredit_ok" = true ] && [ "$dcredit_ok" = true ] && \
           [ "$ocredit_ok" = true ]; then
            complexity_ok=true
        fi
    else
        config_details="[PAM 복잡성] 모듈 미설치 (pam_pwquality.so 또는 pam_cracklib.so 없음)"
        # 원본 grep 출력 저장 (검사한 모든 파일의 결과)
        local all_pam_checks=""
        for check_file in "${pam_files[@]}"; do
            if [ -f "$check_file" ]; then
                local file_output=$(grep -E "pam_pwquality.so|pam_cracklib.so" "$check_file" 2>/dev/null || echo "")
                if [ -n "$file_output" ]; then
                    all_pam_checks="${all_pam_checks}[${check_file}]${newline}${file_output}${newline}${newline}"
                fi
            fi
        done
        if [ -z "$all_pam_checks" ]; then
            pam_output="검사한 모든 PAM 파일에서 pam_pwquality.so 또는 pam_cracklib.so 미발견"
        else
            pam_output="${all_pam_checks}"
        fi
    fi

    # ============================================================================
    # 2) 비밀번호 사용 기간 확인 (/etc/login.defs)
    # ============================================================================
    local login_defs_file="/etc/login.defs"
    local pass_max_days=""
    local pass_min_days=""

    if [ -f "$login_defs_file" ]; then
        # Raw output 저장
        login_defs_output=$(grep -E "^[\s]*(PASS_MAX_DAYS|PASS_MIN_DAYS)" "$login_defs_file" 2>/dev/null || echo "")

        pass_max_days=$(echo "$login_defs_output" | grep "PASS_MAX_DAYS" | awk '{print $2}')
        pass_min_days=$(echo "$login_defs_output" | grep "PASS_MIN_DAYS" | awk '{print $2}')

        config_details="${config_details} | [사용 기간] PASS_MAX_DAYS=${pass_max_days:-미설정}, PASS_MIN_DAYS=${pass_min_days:-미설정}"

        # 판정: PASS_MAX_DAYS <= 90, PASS_MIN_DAYS >= 1
        local max_days_ok=false
        local min_days_ok=false

        if [ -n "$pass_max_days" ] && [ "$pass_max_days" -le 90 ]; then
            max_days_ok=true
        fi

        if [ -n "$pass_min_days" ] && [ "$pass_min_days" -ge 1 ]; then
            min_days_ok=true
        fi

        if [ "$max_days_ok" = true ] && [ "$min_days_ok" = true ]; then
            age_ok=true
        fi
    else
        config_details="${config_details} | [사용 기간] /etc/login.defs 파일 없음"
        # 원본 ls -l 출력 저장 (파일 존재 여부 확인)
        login_defs_output=$(ls -l "$login_defs_file" 2>/dev/null || echo "파일 없음: ${login_defs_file}")
    fi

    # ============================================================================
    # 최종 판정
    # ============================================================================
    # 복잡성 설정과 사용 기간 설정 모두 확인되어야 양호
    if [ "$complexity_ok" = true ] && [ "$age_ok" = true ]; then
        is_secure=true
    fi

    if [ "$found_pam_module" = false ]; then
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="비밀번호 복잡성 정책 미설정 (PAM 모듈 없음)"
    elif [ "$is_secure" = true ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="비밀번호 관리 정책 적절하게 설정됨 (${config_details})"
    else
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="비밀번호 관리 정책 부적절하게 설정됨 (${config_details})"
    fi

    # 명령어 실행 결과 결합 (raw output)
    command_result="[PAM Password File: ${active_pam_file:-[none]}]${newline}${pam_output}${newline}${newline}"
    command_result="${command_result}[/etc/login.defs]${newline}${login_defs_output}"

    command_executed="grep -E 'pam_pwquality.so|pam_cracklib.so' /etc/pam.d/common-password /etc/pam.d/common-auth; grep -E '^PASS_(MAX|MIN)_DAYS' /etc/login.defs"

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
