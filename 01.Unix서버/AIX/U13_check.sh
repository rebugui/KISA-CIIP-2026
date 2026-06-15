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
# @Platform    : AIX
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
    # AIX: /etc/security/login.cfg의 usw 스탠자 pwd_algorithm 속성 확인
    # 가이드: chsec -f /etc/security/login.cfg -s usw -a pwd_algorithm=<SHA-2 이상>
    # 안전: ssha512, ssha256, sha512, sha256 / 취약: crypt 또는 미설정(기본 crypt)

    local login_cfg="/etc/security/login.cfg"
    local is_secure=false
    local is_manual=false
    local details=""
    local pwd_algorithm=""
    local pwd_algorithm_lower=""
    local usw_raw=""
    local root_hash_info=""

    # 1) /etc/security/login.cfg의 usw 스탠자에서 pwd_algorithm 추출 (들여쓰기 허용)
    if [ -f "$login_cfg" ]; then
        if [ -r "$login_cfg" ]; then
            pwd_algorithm=$(awk '
                /^usw:/ { in_usw = 1; next }
                /^[^[:space:]]/ { in_usw = 0 }
                in_usw && $0 ~ /^[[:space:]]*pwd_algorithm[[:space:]]*=/ {
                    sub(/^[[:space:]]*pwd_algorithm[[:space:]]*=[[:space:]]*/, "")
                    gsub(/[[:space:]]+.*$/, "")
                    print
                    exit
                }' "$login_cfg" 2>/dev/null || true)
            usw_raw=$(awk '
                /^[^[:space:]]/ && !/^usw:/ { in_usw = 0 }
                /^usw:/ { in_usw = 1 }
                in_usw { print }' "$login_cfg" 2>/dev/null | head -20 || true)
            [ -z "$usw_raw" ] && usw_raw="usw 스탠자 없음"
        else
            is_manual=true
            details="${login_cfg} 읽기 권한 없음"
        fi
    else
        details="${login_cfg} 파일 없음 (pwd_algorithm 미설정 - 기본 crypt 사용)"
    fi

    # 2) pwd_algorithm 값 판정 (AIX 값은 소문자이나 대소문자 무시 비교)
    if [ "$is_manual" = false ]; then
        if [ -n "$pwd_algorithm" ]; then
            pwd_algorithm_lower=$(echo "$pwd_algorithm" | tr '[:upper:]' '[:lower:]' || true)
            case "$pwd_algorithm_lower" in
                ssha512|ssha256|sha512|sha256)
                    is_secure=true
                    details="usw 스탠자 pwd_algorithm = ${pwd_algorithm} (SHA-2 이상)"
                    ;;
                *)
                    details="usw 스탠자 pwd_algorithm = ${pwd_algorithm} (취약한 알고리즘)"
                    ;;
            esac
        elif [ -z "$details" ]; then
            details="usw 스탠자에 pwd_algorithm 미설정 (기본 crypt 사용)"
        fi
    fi

    # 3) /etc/security/passwd의 root 해시 접두사 확인 (증적, 대소문자 무시)
    if [ -f /etc/security/passwd ] && [ -r /etc/security/passwd ]; then
        local root_hash
        root_hash=$(awk '
            /^[^[:space:]]/ && !/^root:/ { in_root = 0 }
            /^root:/ { in_root = 1 }
            in_root && $0 ~ /^[[:space:]]*password[[:space:]]*=/ { print $3; exit }' \
            /etc/security/passwd 2>/dev/null || true)
        if [ -n "$root_hash" ]; then
            if echo "$root_hash" | grep -qiE '^\{s?sha(256|512)\}'; then
                root_hash_info="root 비밀번호 해시: SHA-2 계열 LPA 접두사 확인"
            elif echo "$root_hash" | grep -qiE '^\{'; then
                root_hash_info="root 비밀번호 해시: SHA-2 이외 LPA 접두사 사용"
            else
                root_hash_info="root 비밀번호 해시: LPA 접두사 없음 (legacy crypt 추정)"
            fi
        fi
    fi

    # 최종 판정
    if [ "$is_manual" = true ]; then
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="비밀번호 암호화 알고리즘 설정 확인 불가 (${details}) - 수동 점검 필요"
        command_result="[Command: awk '/^usw:/,/^[^ \\t]/' ${login_cfg}]${newline}${details}"
        command_executed="awk '/^usw:/,/^[^ \t]/' ${login_cfg}"
    elif [ "$is_secure" = true ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="안전한 비밀번호 암호화 알고리즘 사용됨 (${details})"
        command_result="[Command: awk '/^usw:/,/^[^ \\t]/' ${login_cfg}]${newline}${usw_raw}"
        if [ -n "$root_hash_info" ]; then
            command_result="${command_result}${newline}${newline}${root_hash_info}"
        fi
        command_executed="awk '/^usw:/,/^[^ \t]/' /etc/security/login.cfg"
    else
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="취약한 비밀번호 암호화 알고리즘 사용 (${details})"
        if [ -n "$usw_raw" ]; then
            command_result="[Command: awk '/^usw:/,/^[^ \\t]/' ${login_cfg}]${newline}${usw_raw}"
        else
            command_result="[Command: awk '/^usw:/,/^[^ \\t]/' ${login_cfg}]${newline}${details}"
        fi
        if [ -n "$root_hash_info" ]; then
            command_result="${command_result}${newline}${newline}${root_hash_info}"
        fi
        command_executed="awk '/^usw:/,/^[^ \t]/' /etc/security/login.cfg"
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
