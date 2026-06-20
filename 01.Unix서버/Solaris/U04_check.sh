#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-18
# ============================================================================
# [점검 항목 상세]
# @ID          : U-04
# @Category    : Unix Server
# @Platform    : Solaris
# @Severity    : 상
# @Title       : 비밀번호 파일 보호
# @Description : /etc/passwd 비밀번호 필드 보호 확인 (Shadow)
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

ITEM_ID="U-04"
ITEM_NAME="비밀번호 파일 보호"
SEVERITY="상"

# 가이드라인 정보
GUIDELINE_PURPOSE="일부 오래된 시스템의 경우 /etc/passwd 파일에 비밀번호가 평문으로 저장되므로 사용자 계정 비밀번호가 암호화되어 저장되어 있는지 점검하여 비인가자의 비밀번호 파일 접근 시에도 사용자 계정 비밀번호가 안전하게 관리되고 있는지 확인하기 위함"
GUIDELINE_THREAT="사용자 계정 비밀번호가 저장된 파일이 유출 또는 탈취 시 평문으로 저장된 비밀번호 정보가 노출 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="쉐도우 비밀번호를 사용하거나, 비밀번호를 암호화하여 저장하는 경우"
GUIDELINE_CRITERIA_BAD="쉐도우 비밀번호를 사용하지 않고, 비밀번호를 암호화하여 저장하지 않는 경우"
GUIDELINE_REMEDIATION="비밀번호 암호화 저장· 관리 설정"

# ============================================================================
# 진단 함수
# ============================================================================

diagnose() {
    diagnosis_result="unknown"
    local status="미진단"
    local inspection_summary=""
    local command_result=""
    local command_executed=""
    local newline=$'\n'

    # 진단 로직 구현
    # Solaris uses /etc/shadow
    
    local shadow_file="/etc/shadow"
    local passwd_file="/etc/passwd"
    local shadow_exists=false
    local all_users_shadow=true
    local non_shadow_users=""

    # 1) /etc/shadow 파일 존재 확인
    if [ -f "$shadow_file" ]; then
        shadow_exists=true
    fi

    # 2) Check /etc/passwd fields (Solaris: field 2 should be 'x')
    while IFS=: read -r username password uid uid_number gid gecos home shell; do
        if [ -n "$password" ] && [ "$password" != "x" ] && [ "$password" != "*" ]; then
             all_users_shadow=false
             non_shadow_users="${non_shadow_users}${username}, "
        fi
    done < "$passwd_file"

    # --- 명령어 실행 및 원본 출력 캡처 ---
    # 실제 ls -l 명령 실행 결과 캡처
    local ls_shadow_output=""
    if [ -f "$shadow_file" ]; then
        ls_shadow_output=$(ls -l "$shadow_file" 2>/dev/null)
    else
        ls_shadow_output="[FILE NOT FOUND: ${shadow_file}]"
    fi

    # /etc/passwd 상위 5개 라인 (비밀번호 필드만 확인)
    local passwd_sample=$(awk -F: '{print $1 ":" $2 ":..."}' "$passwd_file" | head -5)

    command_result="${ls_shadow_output}${newline}${newline}[FILE: ${passwd_file} (Top 5 entries)]${newline}${passwd_sample}"
    command_executed="ls -l ${shadow_file}; awk -F: '{print \$1 \":\" \$2 \":...\"}' ${passwd_file} | head -5"

    if [ -n "$non_shadow_users" ]; then
         command_result="${command_result}${newline}${newline}[Warning: Non-Shadow Users]${newline}${non_shadow_users%, }"
    fi

    # 최종 판정
    if [ "$shadow_exists" = true ] && [ "$all_users_shadow" = true ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="쉐도우 비밀번호를 사용하고 있으며, /etc/passwd 보호됨"
    else
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="쉐도우 비밀번호 미사용 또는 /etc/passwd 평문 노출"
    fi

    # 결과 저장 (통합형 인자 사용)
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
    show_diagnosis_start "${ITEM_ID}" "${ITEM_NAME}"
    check_disk_space
    diagnose
    show_diagnosis_complete "${ITEM_ID}" "${diagnosis_result:-UNKNOWN}"
    return 0
}

if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi
