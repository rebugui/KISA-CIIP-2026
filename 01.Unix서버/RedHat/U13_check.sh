#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-04-20
# ============================================================================
# [점검 항목 상세]
# @ID          : U-13
# @Category    : UNIX > 1. 계정 관리
# @Platform    : RedHat
# @Severity    : 중
# @Title       : 안전한 비밀번호 암호화 알고리즘 사용
# @Description : 안전한 비밀번호 암호화 알고리즘을 사용 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../../lib"

source "${LIB_DIR}/common.sh"
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

diagnose() {
    local status="양호"
    diagnosis_result="GOOD"
    local inspection_summary="SHA-2 이상의 안전한 암호화 알고리즘이 설정되어 있습니다."
    local command_result=""
    local command_executed="grep ENCRYPT_METHOD /etc/login.defs; grep pam_unix.so /etc/pam.d/system-auth; grep '^root:' /etc/shadow"

    # 1. 실제 데이터 추출: login.defs / PAM(system-auth, password-auth) / shadow root 해시
    local encrypt_method=$(grep "^ENCRYPT_METHOD" /etc/login.defs 2>/dev/null | awk '{print $2}' || echo "")
    [ -z "$encrypt_method" ] && encrypt_method="미설정"
    local root_hash=$(grep "^root:" /etc/shadow 2>/dev/null | cut -d: -f2 || echo "")
    local pam_lines=$(grep -hE '^[[:space:]]*password[^#]*pam_unix\.so' /etc/pam.d/system-auth /etc/pam.d/password-auth 2>/dev/null || echo "")

    # 2. 판정 로직 (worst-of): 약한 지표가 하나라도 있으면 취약
    local weak_findings=""
    local good_findings=""

    # [Leg 1] login.defs ENCRYPT_METHOD
    case "$encrypt_method" in
        SHA512|sha512|SHA256|sha256|YESCRYPT|yescrypt)
            good_findings="${good_findings}login.defs(${encrypt_method}) " ;;
        MD5|md5|DES|des|CRYPT|crypt|BIGCRYPT|bigcrypt)
            weak_findings="${weak_findings}login.defs(${encrypt_method}) " ;;
    esac

    # [Leg 2] PAM system-auth/password-auth의 pam_unix.so 해시 옵션
    if [ -n "$pam_lines" ]; then
        if echo "$pam_lines" | grep -qwE '(md5|des|bigcrypt)'; then
            weak_findings="${weak_findings}pam_unix(약한 해시 옵션) "
        elif echo "$pam_lines" | grep -qwE '(sha512|sha256|yescrypt)'; then
            good_findings="${good_findings}pam_unix(안전 해시 옵션) "
        fi
    fi

    # [Leg 3] /etc/shadow root 실해시 접두사 ($y$=yescrypt도 안전 인정)
    local shadow_summary="판정 제외"
    case "$root_hash" in
        ''|'!'*|'*'*)
            shadow_summary="잠금/없음(판정 제외)" ;;
        '$6$'*|'$5$'*|'$y$'*|'$7$'*)
            good_findings="${good_findings}shadow(root ${root_hash:0:3}) "
            shadow_summary="안전(${root_hash:0:3})" ;;
        '$1$'*)
            weak_findings="${weak_findings}shadow(root MD5) "
            shadow_summary="MD5(\$1\$)" ;;
        '$'*)
            shadow_summary="기타(${root_hash:0:3}, 판정 보류)" ;;
        *)
            weak_findings="${weak_findings}shadow(root DES 추정) "
            shadow_summary="DES 추정(\$ 접두사 없음)" ;;
    esac

    if [ -n "$weak_findings" ]; then
        status="취약"
        diagnosis_result="VULNERABLE"
        inspection_summary="안전하지 않은 비밀번호 암호화 지표 발견: ${weak_findings% }"
    elif [ -z "$good_findings" ]; then
        if [ ! -r /etc/login.defs ] && [ ! -r /etc/shadow ] && [ -z "$pam_lines" ]; then
            status="수동진단"
            diagnosis_result="MANUAL"
            inspection_summary="암호화 알고리즘 설정 증거 수집 불가 - /etc/login.defs, /etc/pam.d/system-auth, /etc/shadow 수동 확인 필요"
        else
            status="취약"
            diagnosis_result="VULNERABLE"
            inspection_summary="비밀번호 암호화 알고리즘 미설정 (ENCRYPT_METHOD/PAM 해시 옵션/안전 해시 증거 없음)"
        fi
    fi

    # 3. command_result에 실제 데이터 기록 (해시 원문 미노출)
    command_result="ENCRYPT_METHOD: [ ${encrypt_method} ] | PAM pam_unix: [ $(echo "${pam_lines:-없음}" | tr '\n' ' ') ] | Shadow(root): [ ${shadow_summary} ]"

    save_dual_result \
        "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" \
        "${inspection_summary}" "${command_result}" "${command_executed}" \
        "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" \
        "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
    
    verify_result_saved "${ITEM_ID}"
    return 0
}

main() {
    show_diagnosis_start "${ITEM_ID}" "${ITEM_NAME}"
    [ "$EUID" -ne 0 ] && { echo "root 권한이 필요합니다."; exit 1; }
    diagnose
    show_diagnosis_complete "${ITEM_ID}" "${diagnosis_result}"
    exit 0
}

main "$@"
