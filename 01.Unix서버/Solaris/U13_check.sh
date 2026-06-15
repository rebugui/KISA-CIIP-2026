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
    # Solaris: /etc/security/policy.conf의 CRYPT_DEFAULT 값 확인
    # 가이드: CRYPT_DEFAULT = 5(SHA-256) 또는 6(SHA-512) → 안전
    # 1(BSD MD5), 2a/2x/2y(Blowfish), md5, __unix__ 또는 미설정(기본 __unix__) → 취약
    # CRYPT_ALGORITHMS_ALLOW는 증적으로 함께 수집

    local policy_file="/etc/security/policy.conf"
    local is_secure=false
    local is_manual=false
    local details=""
    local crypt_raw=""
    local crypt_default=""
    local crypt_allow=""

    # 1) /etc/security/policy.conf에서 CRYPT_DEFAULT / CRYPT_ALGORITHMS_ALLOW 추출
    #    (들여쓰기 허용, 주석 제외)
    if [ -f "$policy_file" ]; then
        if [ -r "$policy_file" ]; then
            crypt_raw=$(grep -E '^[[:space:]]*CRYPT_(DEFAULT|ALGORITHMS_ALLOW)[[:space:]]*=' "$policy_file" 2>/dev/null | grep -v '^[[:space:]]*#' || true)
            crypt_default=$(grep -E '^[[:space:]]*CRYPT_DEFAULT[[:space:]]*=' "$policy_file" 2>/dev/null | grep -v '^[[:space:]]*#' | tail -1 | cut -d= -f2- | tr -d '[:space:]' || true)
            crypt_allow=$(grep -E '^[[:space:]]*CRYPT_ALGORITHMS_ALLOW[[:space:]]*=' "$policy_file" 2>/dev/null | grep -v '^[[:space:]]*#' | tail -1 | cut -d= -f2- | tr -d '[:space:]' || true)
        else
            is_manual=true
            details="${policy_file} 읽기 권한 없음"
        fi
    else
        details="${policy_file} 파일 없음 (CRYPT_DEFAULT 미설정 - 기본 __unix__ crypt 사용)"
    fi

    # 2) CRYPT_DEFAULT 값 판정 (SHA-2 계열인 5/6만 안전, Blowfish/MD5/__unix__는 취약)
    if [ "$is_manual" = false ]; then
        case "$crypt_default" in
            6)
                is_secure=true
                details="CRYPT_DEFAULT=6 (SHA-512)"
                ;;
            5)
                is_secure=true
                details="CRYPT_DEFAULT=5 (SHA-256)"
                ;;
            "")
                if [ -z "$details" ]; then
                    details="CRYPT_DEFAULT 미설정 (기본 __unix__ crypt 사용)"
                fi
                ;;
            *)
                details="CRYPT_DEFAULT=${crypt_default} (취약한 알고리즘)"
                ;;
        esac
        if [ -n "$crypt_allow" ]; then
            details="${details}, CRYPT_ALGORITHMS_ALLOW=${crypt_allow}"
        fi
    fi

    # 3) /etc/shadow 저장 해시 점검 (CRYPT_DEFAULT가 안전해도 기존 약한 해시가 남아있으면 취약)
    #    $5$/$6$(SHA-2) 외의 실사용 해시($1$ MD5, $2x$ Blowfish, 13자 전통 crypt 등)는 취약
    local shadow_file="/etc/shadow"
    local shadow_checked=false
    local weak_hash_accounts=""
    if [ "$is_manual" = false ] && [ -r "$shadow_file" ]; then
        shadow_checked=true
        weak_hash_accounts=$(awk -F: '
            $2 == "" { next }
            $2 ~ /^[*!]/ || $2 == "NP" || $2 == "UP" || $2 == "x" { next }
            $2 ~ /^\$[56]\$/ { next }
            $2 ~ /^\$2[abxy]?\$/ { print $1 "(Blowfish)"; next }
            $2 ~ /^\$1\$/ { print $1 "(MD5)"; next }
            $2 ~ /^\$md5/ { print $1 "(Sun-MD5)"; next }
            { print $1 "(legacy-crypt)" }' "$shadow_file" 2>/dev/null | head -10 || true)
    fi

    if [ "$is_manual" = false ]; then
        if [ -n "$weak_hash_accounts" ]; then
            is_secure=false
            details="${details}, /etc/shadow 약한 해시 계정: $(echo "$weak_hash_accounts" | tr '\n' ' ')"
        elif [ "$is_secure" = true ] && [ "$shadow_checked" = false ]; then
            # 정책은 안전하나 실제 저장 해시를 확인할 수 없는 경우 → 수동 확인
            is_manual=true
            details="${details}, /etc/shadow 읽기 불가로 저장된 해시 알고리즘 확인 필요"
        fi
    fi

    # 최종 판정
    if [ "$is_manual" = true ]; then
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="비밀번호 암호화 알고리즘 설정 확인 불가 (${details}) - 수동 점검 필요"
        command_result="[Command: grep -E '^[[:space:]]*CRYPT_(DEFAULT|ALGORITHMS_ALLOW)' ${policy_file}]${newline}${details}"
        command_executed="grep -E '^[[:space:]]*CRYPT_(DEFAULT|ALGORITHMS_ALLOW)' ${policy_file}"
    elif [ "$is_secure" = true ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="안전한 비밀번호 암호화 알고리즘 사용됨 (${details}, /etc/shadow 약한 해시 없음)"
        command_result="[Command: grep -E '^[[:space:]]*CRYPT_(DEFAULT|ALGORITHMS_ALLOW)' ${policy_file}]${newline}${crypt_raw}"
        command_executed="grep -E '^[[:space:]]*CRYPT_(DEFAULT|ALGORITHMS_ALLOW)' /etc/security/policy.conf; awk -F: /etc/shadow (해시 알고리즘 확인)"
    else
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="취약한 비밀번호 암호화 알고리즘 사용 (${details})"
        if [ -n "$crypt_raw" ]; then
            command_result="[Command: grep -E '^[[:space:]]*CRYPT_(DEFAULT|ALGORITHMS_ALLOW)' ${policy_file}]${newline}${crypt_raw}"
        else
            command_result="[Command: grep -E '^[[:space:]]*CRYPT_(DEFAULT|ALGORITHMS_ALLOW)' ${policy_file}]${newline}${details}"
        fi
        command_executed="grep -E '^[[:space:]]*CRYPT_(DEFAULT|ALGORITHMS_ALLOW)' /etc/security/policy.conf; awk -F: /etc/shadow (해시 알고리즘 확인)"
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
