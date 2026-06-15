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
# @Platform    : Debian
# @Severity    : 중
# @Title       : 안전한 비밀번호 암호화 알고리즘 사용
# @Description : SHA512 또는 더 강한 알고리즘 확인
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
    # SHA-2 이상 알고리즘 사용 여부 점검 (worst-of: 약한 지표가 하나라도 있으면 취약)
    # [Leg 1] /etc/login.defs ENCRYPT_METHOD
    # [Leg 2] /etc/pam.d/common-password 등 pam_unix.so 해시 옵션 (실제 해시 결정 주체)
    # [Leg 3] /etc/shadow root 계정 실해시 접두사

    local weak_findings=""
    local good_findings=""
    local details=""
    local raw_output=""
    local encrypt_method=""
    local evidence_available=false

    # [Leg 1] /etc/login.defs ENCRYPT_METHOD 확인
    raw_output=$(grep "^ENCRYPT_METHOD" /etc/login.defs 2>/dev/null || echo "No ENCRYPT_METHOD in /etc/login.defs")
    if [ -r /etc/login.defs ]; then
        evidence_available=true
        encrypt_method=$(grep "^ENCRYPT_METHOD" /etc/login.defs 2>/dev/null | awk '{print $2}' || true)
        if [ -n "$encrypt_method" ]; then
            details="login.defs ENCRYPT_METHOD: ${encrypt_method}"
            case "$encrypt_method" in
                SHA512|sha512|SHA256|sha256|YESCRYPT|yescrypt)
                    good_findings="${good_findings}login.defs(${encrypt_method}) "
                    ;;
                MD5|md5|DES|des|CRYPT|crypt|BIGCRYPT|bigcrypt)
                    weak_findings="${weak_findings}login.defs(${encrypt_method}) "
                    ;;
            esac
        fi
    fi

    # [Leg 2] PAM 설정 확인 — Debian은 /etc/pam.d/common-password의 pam_unix.so 옵션이 실제 해시 결정
    local pam_files=(
        "/etc/pam.d/common-password"
        "/etc/pam.d/system-auth"
        "/etc/pam.d/password-auth"
    )
    local pam_file pam_lines pam_line
    for pam_file in "${pam_files[@]}"; do
        [ -f "$pam_file" ] || continue
        pam_lines=$(grep -E '^[[:space:]]*password[^#]*pam_unix\.so' "$pam_file" 2>/dev/null || true)
        [ -z "$pam_lines" ] && continue
        evidence_available=true
        raw_output="${raw_output}${newline}[${pam_file}]${newline}${pam_lines}"
        while IFS= read -r pam_line; do
            [ -z "$pam_line" ] && continue
            if echo "$pam_line" | grep -qwE '(md5|des|bigcrypt)'; then
                weak_findings="${weak_findings}${pam_file##*/}(약한 해시 옵션) "
                details="${details:+${details}, }PAM ${pam_file##*/}: 약한 해시 옵션(md5/des)"
            elif echo "$pam_line" | grep -qwE '(sha512|sha256|yescrypt)'; then
                good_findings="${good_findings}${pam_file##*/}(안전 해시 옵션) "
                details="${details:+${details}, }PAM ${pam_file##*/}: 안전 해시 옵션"
            fi
        done <<< "$pam_lines"
    done

    # [Leg 3] /etc/shadow root 계정 실해시 접두사 확인 (해시 원문은 증적에 미기록)
    local root_hash=""
    if [ -r /etc/shadow ]; then
        root_hash=$(awk -F: '$1 == "root" { print $2; exit }' /etc/shadow 2>/dev/null || true)
        if [ -n "$root_hash" ]; then
            evidence_available=true
            case "$root_hash" in
                '!'*|'*'*)
                    raw_output="${raw_output}${newline}[/etc/shadow] root: 잠금 계정 (해시 판정 제외)"
                    ;;
                '$6$'*|'$5$'*|'$y$'*|'$7$'*)
                    good_findings="${good_findings}shadow(root: 안전 해시 ${root_hash:0:3}) "
                    details="${details:+${details}, }root 해시: 안전(${root_hash:0:3})"
                    raw_output="${raw_output}${newline}[/etc/shadow] root hash prefix: ${root_hash:0:3}"
                    ;;
                '$1$'*)
                    weak_findings="${weak_findings}shadow(root: MD5 해시) "
                    details="${details:+${details}, }root 해시: MD5(\$1\$)"
                    raw_output="${raw_output}${newline}[/etc/shadow] root hash prefix: \$1\$ (MD5)"
                    ;;
                '$'*)
                    raw_output="${raw_output}${newline}[/etc/shadow] root hash prefix: ${root_hash:0:3} (판정 보류)"
                    ;;
                *)
                    weak_findings="${weak_findings}shadow(root: DES 추정 해시) "
                    details="${details:+${details}, }root 해시: DES 추정(\$ 접두사 없음)"
                    raw_output="${raw_output}${newline}[/etc/shadow] root hash: \$ 접두사 없음 (DES 추정)"
                    ;;
            esac
        fi
    fi

    command_executed="grep '^ENCRYPT_METHOD' /etc/login.defs; grep pam_unix.so /etc/pam.d/common-password; awk -F: '\$1==\"root\"{print \$2}' /etc/shadow"

    # 최종 판정 (worst-of: 약한 지표 우선)
    if [ -n "$weak_findings" ]; then
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="약한 비밀번호 암호화 알고리즘 지표 발견: ${weak_findings% }${details:+ (${details})}"
        command_result="${raw_output}"
    elif [ -n "$good_findings" ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="안전한 비밀번호 암호화 알고리즘 사용됨 (${details})"
        command_result="${raw_output}"
    elif [ "$evidence_available" = false ]; then
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="비밀번호 암호화 알고리즘 설정 증거 수집 불가 - /etc/login.defs, /etc/pam.d/common-password, /etc/shadow를 수동으로 확인 필요"
        command_result="${raw_output}"
    else
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="비밀번호 암호화 알고리즘 미설정 (login.defs ENCRYPT_METHOD 및 PAM 해시 옵션 부재, 안전 해시 증거 없음)"
        command_result="${raw_output}"
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
