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
# @Platform    : HP-UX
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
    # HP-UX: /etc/default/security의 CRYPT_DEFAULT 값 확인
    # 가이드: CRYPT_DEFAULT = 5(SHA-256) 또는 6(SHA-512) → 안전
    # 그 외(1/MD5/DES 등) 또는 미설정(기본 DES crypt) → 취약

    local sec_file="/etc/default/security"
    local is_secure=false
    local is_manual=false
    local details=""
    local crypt_raw=""
    local crypt_default=""

    # 1) /etc/default/security에서 CRYPT_DEFAULT 추출 (들여쓰기 허용, 주석 제외)
    if [ -f "$sec_file" ]; then
        if [ -r "$sec_file" ]; then
            crypt_raw=$(grep -E '^[[:space:]]*CRYPT_DEFAULT[[:space:]]*=' "$sec_file" 2>/dev/null | grep -v '^[[:space:]]*#' || true)
            crypt_default=$(echo "$crypt_raw" | tail -1 | cut -d= -f2- | tr -d '[:space:]' || true)
        else
            is_manual=true
            details="${sec_file} 읽기 권한 없음"
        fi
    else
        details="${sec_file} 파일 없음 (CRYPT_DEFAULT 미설정 - 기본 DES crypt 사용)"
    fi

    # 2) CRYPT_DEFAULT 값 판정
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
                    details="CRYPT_DEFAULT 미설정 (기본 DES crypt 사용)"
                fi
                ;;
            *)
                details="CRYPT_DEFAULT=${crypt_default} (취약한 알고리즘)"
                ;;
        esac
    fi

    # 3) CRYPT_DEFAULT 양호 시 /etc/shadow 실제 해시 확인
    #    - shadow 미사용(11i v2+): 취약 (Trusted Mode(/tcb)는 별도 저장소 → 수동진단)
    #    - 잠금/빈 값 외 해시 중 $5$/$6$가 아닌 항목 존재: 취약 (레거시 DES/MD5 잔존)
    if [ "$is_manual" = false ] && [ "$is_secure" = true ]; then
        if [ -f /etc/shadow ]; then
            if [ -r /etc/shadow ]; then
                local legacy_hash_users=""
                legacy_hash_users=$(awk -F: '$2 != "" && $2 != "x" && $2 != "NP" && $2 !~ /^[!*]/ && $2 !~ /^\$[56]\$/ { print $1 }' /etc/shadow 2>/dev/null | head -10 | tr '\n' ' ' || true)
                if [ -n "$legacy_hash_users" ]; then
                    is_secure=false
                    details="${details}, /etc/shadow에 SHA-2 이외 해시 잔존 계정: ${legacy_hash_users}"
                else
                    details="${details}, /etc/shadow 해시 SHA-2 확인"
                fi
            else
                is_manual=true
                details="${details}, /etc/shadow 읽기 불가로 실제 해시 확인 필요"
            fi
        elif [ -d /tcb ]; then
            is_manual=true
            details="${details}, /etc/shadow 미사용(Trusted Mode /tcb 사용) - 저장 해시 수동 확인 필요"
        else
            is_secure=false
            details="${details}, /etc/shadow 미사용(쉐도우 패스워드 미적용)"
        fi
    fi

    # 최종 판정
    if [ "$is_manual" = true ]; then
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="비밀번호 암호화 알고리즘 설정 확인 불가 (${details}) - 수동 점검 필요"
        command_result="[Command: grep -E '^[[:space:]]*CRYPT_DEFAULT' ${sec_file}]${newline}${details}"
        command_executed="grep -E '^[[:space:]]*CRYPT_DEFAULT' ${sec_file}"
    elif [ "$is_secure" = true ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="안전한 비밀번호 암호화 알고리즘 사용됨 (${details})"
        command_result="[Command: grep -E '^[[:space:]]*CRYPT_DEFAULT' ${sec_file}]${newline}${crypt_raw}"
        command_executed="grep -E '^[[:space:]]*CRYPT_DEFAULT' /etc/default/security"
    else
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="취약한 비밀번호 암호화 알고리즘 사용 (${details})"
        if [ -n "$crypt_raw" ]; then
            command_result="[Command: grep -E '^[[:space:]]*CRYPT_DEFAULT' ${sec_file}]${newline}${crypt_raw}"
        else
            command_result="[Command: grep -E '^[[:space:]]*CRYPT_DEFAULT' ${sec_file}]${newline}${details}"
        fi
        command_executed="grep -E '^[[:space:]]*CRYPT_DEFAULT' /etc/default/security"
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
