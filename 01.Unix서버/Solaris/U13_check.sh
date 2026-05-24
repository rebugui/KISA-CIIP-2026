#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : U-13
# @Category    : Unix Server
# @Platform    : Solaris
# @Severity    : 중
# @Title       : 안전한 비밀번호 암호화 알고리즘 사용
# @Description : SHA512 또는更强 알고리즘 확인
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


ITEM_ID="U-13"
ITEM_NAME="안전한 비밀번호 암호화 알고리즘 사용"
SEVERITY="중"

# 가이드라인 정보
GUIDELINE_PURPOSE="안전한 비밀번호 암호화 알고리즘을 사용하여 사용자 계정 정보를 보호하기 위함"
GUIDELINE_THREAT="취약한 비밀번호 암호화 알고리즘을 사용할 경우, 노출된 계정에 대해 비인가자가 암호 복호화 공격을 통해 비밀번호를 획득할 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="SHA-2 이상의 안전한 비밀번호 암호화 알고리즘을 사용하는 경우"
GUIDELINE_CRITERIA_BAD="취약한 비밀번호 암호화 알고리즘을 사용하는 경우"
GUIDELINE_REMEDIATION="SHA-2 이상의 안전한 비밀번호 암호화 알고리즘 적용 설정"

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
    local newline=$'\n'

    # 진단 로직 구현
    # SHA512 또는更强 알고리즘 확인

    local is_secure=false
    local details=""
    local encrypt_method=""
    local pam_algorithm=""

    # 1) /etc/default/passwd 확인 (Solaris uses CRYPT_ALGORITHM and CRYPT_DEFAULT)
    if [ -f /etc/default/passwd ]; then
        encrypt_method=$(grep "^CRYPT_ALGORITHM\|CRYPT_DEFAULT" /etc/default/passwd 2>/dev/null | grep -v "^#" | head -1 | awk '{print $2}')
        if [ -n "$encrypt_method" ]; then
            details="/etc/default/passwd: ${encrypt_method}"
        fi
    fi

    # 2) PAM 설정 확인 (Solaris uses /etc/pam.conf or /etc/pam.d/*)
    local pam_files=(
        "/etc/pam.conf"
        "/etc/pam.d/common-auth"
        "/etc/pam.d/system-auth"
        "/etc/pam.d/passwd"
    )

    for pam_file in "${pam_files[@]}"; do
        if [ -f "$pam_file" ]; then
            # Solaris: Check for unix_cred.so.1 or crypt_unix.so.1 with algorithm
            # SHA512 확인 (우선)
            if grep -q "sha512" "$pam_file" 2>/dev/null; then
                pam_algorithm="sha512"
                is_secure=true
                if [ -n "$details" ]; then
                    details="${details}, PAM: ${pam_algorithm}"
                else
                    details="PAM 알고리즘: ${pam_algorithm}"
                fi
                break
            # SHA256 확인 (최소 허용)
            elif grep -q "sha256" "$pam_file" 2>/dev/null; then
                pam_algorithm="sha256"
                is_secure=true
                if [ -n "$details" ]; then
                    details="${details}, PAM: ${pam_algorithm}"
                else
                    details="PAM 알고리즘: ${pam_algorithm}"
                fi
                break
            # yescrypt 확인 (더 강력함)
            elif grep -q "yescrypt" "$pam_file" 2>/dev/null; then
                pam_algorithm="yescrypt"
                is_secure=true
                if [ -n "$details" ]; then
                    details="${details}, PAM: ${pam_algorithm}"
                else
                    details="PAM 알고리즘: ${pam_algorithm}"
                fi
                break
            fi
        fi
    done || true

    # 3) PAM에 sha512/sha256/yescrypt가 없더라도 /etc/default/passwd에 안전한 알고리즘이 설정된 경우 양호
    if [ "$is_secure" = false ]; then
        # /etc/default/passwd의 CRYPT_ALGORITHM/CRYPT_DEFAULT 확인
        case "$encrypt_method" in
            5|6|2a|2y|2b|sha512|sha256|yescrypt)
                is_secure=true
                ;;
        esac
    fi

    # 최종 판정
    if [ "$is_secure" = true ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="안전한 비밀번호 암호화 알고리즘 사용됨 (${details})"
        local encrypt_output=$(grep '^CRYPT_ALGORITHM\|^CRYPT_DEFAULT' /etc/default/passwd 2>/dev/null || echo "No CRYPT settings found")
        local pam_output=$(grep -E 'sha512|sha256' /etc/pam.conf /etc/pam.d/* 2>/dev/null || echo "No PAM algorithm found")
        command_result="[Command: grep '^CRYPT_ALGORITHM\\|^CRYPT_DEFAULT' /etc/default/passwd]${newline}${encrypt_output}${newline}${newline}[Command: grep -E 'sha512|sha256' /etc/pam.conf /etc/pam.d/*]${newline}${pam_output}"
        command_executed="grep '^CRYPT_ALGORITHM\\|^CRYPT_DEFAULT' /etc/default/passwd && grep -E 'sha512|sha256' /etc/pam.conf /etc/pam.d/* 2>/dev/null"
    else
        diagnosis_result="VULNERABLE"
        status="취약"
        local encrypt_output=$(grep '^CRYPT_ALGORITHM\|^CRYPT_DEFAULT' /etc/default/passwd 2>/dev/null || echo "No CRYPT settings found")
        local pam_output=$(grep -E 'sha512|sha256' /etc/pam.conf /etc/pam.d/* 2>/dev/null || echo "No PAM algorithm found")
        if [ -z "$details" ]; then
            inspection_summary="비밀번호 암호화 알고리즘 미설정 또는 약한 알고리즘 사용 (MD5, DES 등)"
            command_result="[Command: grep '^CRYPT_ALGORITHM\\|^CRYPT_DEFAULT' /etc/default/passwd]${newline}${encrypt_output}${newline}${newline}[Command: grep -E 'sha512|sha256' /etc/pam.conf /etc/pam.d/*]${newline}${pam_output}"
        else
            inspection_summary="비밀번호 암호화 알고리즘 부적절 (${details})"
            command_result="[Command: grep '^CRYPT_ALGORITHM\\|^CRYPT_DEFAULT' /etc/default/passwd]${newline}${encrypt_output}${newline}${newline}[Command: grep -E 'sha512|sha256' /etc/pam.conf /etc/pam.d/*]${newline}${pam_output}"
        fi
        command_executed="grep '^CRYPT_ALGORITHM\\|^CRYPT_DEFAULT' /etc/default/passwd && grep -E 'sha512|sha256' /etc/pam.conf /etc/pam.d/* 2>/dev/null"
    fi

    # echo ""
    # echo "진단 결과: ${status}"
    # echo "판정: ${diagnosis_result}"
    # echo "설명: ${inspection_summary}"
    # echo ""

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

    return 0
}

# 스크립트 직접 실행 시에만 진단 수행
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi
