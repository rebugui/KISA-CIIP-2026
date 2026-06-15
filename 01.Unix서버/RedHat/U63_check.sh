#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-04-20
# ============================================================================
# [점검 항목 상세]
# @ID          : U-63
# @Category    : UNIX > 1. 계정 관리
# @Platform    : RedHat
# @Severity    : 중
# @Title       : sudo 명령어 접근 관리
# @Description : sudoers 파일 권한 및 소유자 설정 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/metadata_parser.sh"

ITEM_ID="U-63"
ITEM_NAME="sudo 명령어 접근 관리"
SEVERITY="중"

GUIDELINE_PURPOSE="비인가자가 관리자 권한을 남용하여 시스템 손상, 악성 코드 실행, 민감한 데이터 유출 등의 보안 위협을 방지하기 위함"
GUIDELINE_THREAT="sudo 명령어 접근을 제한하지 않을 경우, 비인가자가 관리자 권한으로 허가되지 않은 명령어를 사용하여 루트 권한 오용, 악성 코드 실행, 데이터 유출 등의 시도를 할 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="/etc/sudoers 파일 소유자가 root이고, 파일 권한이 640인 경우"
GUIDELINE_CRITERIA_BAD="/etc/sudoers 파일 소유자가 root가 아니거나, 파일 권한이 640을 초과하는 경우"
GUIDELINE_REMEDIATION="/etc/sudoers 파일 소유자 및 권한 변경 설정"

diagnose() {
    local status="양호"
    diagnosis_result="GOOD"
    local inspection_summary=""
    local command_result=""
    local command_executed="stat -c '%a %U:%G' /etc/sudoers /etc/sudoers.d/* 2>/dev/null"

    local newline=$'\n'
    local issues=""

    # ==========================================================================
    # 1. sudo 설치 여부 확인
    # ==========================================================================
    if ! command -v sudo >/dev/null 2>&1; then
        status="양호"
        diagnosis_result="GOOD"
        inspection_summary="sudo가 설치되어 있지 않습니다."
        command_result="sudo: [not installed]"

        save_dual_result \
            "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" \
            "${inspection_summary}" "${command_result}" "${command_executed}" \
            "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" \
            "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"

        verify_result_saved "${ITEM_ID}"
        return 0
    fi

    # ==========================================================================
    # 2. /etc/sudoers 파일 권한 및 소유자 확인
    # ==========================================================================
    local sudoers_file="/etc/sudoers"
    if [ -f "$sudoers_file" ]; then
        local perm=$(stat -c "%a" "$sudoers_file" 2>/dev/null || echo "000")
        local owner=$(stat -c "%U" "$sudoers_file" 2>/dev/null || echo "unknown")
        local group=$(stat -c "%G" "$sudoers_file" 2>/dev/null || echo "unknown")

        # 권한이 640 초과인지 확인 (640을 넘는 비트가 있으면 취약)
        if ! [[ "$perm" =~ ^[0-7]{3,4}$ ]] || [ "$(( 8#$perm & ~8#640 & 07777 ))" -ne 0 ] 2>/dev/null; then
            issues="${issues}/etc/sudoers 권한 ${perm} (640 이하 권장). "
            status="취약"
            diagnosis_result="VULNERABLE"
        fi

        # 소유자가 root인지 확인
        if [ "$owner" != "root" ]; then
            issues="${issues}/etc/sudoers 소유자 ${owner} (root 권장). "
            status="취약"
            diagnosis_result="VULNERABLE"
        fi

        command_result="/etc/sudoers: ${perm} ${owner}:${group}"
    else
        # sudo가 설치되어 있는데 /etc/sudoers가 없는 비정상 구성 → 수동 확인 필요
        status="수동진단"
        diagnosis_result="MANUAL"
        inspection_summary="sudo가 설치되어 있으나 /etc/sudoers 파일이 존재하지 않습니다. sudo 권한 구성을 수동으로 확인하십시오."
        command_result="/etc/sudoers: 파일 없음"
    fi

    # ==========================================================================
    # 3. /etc/sudoers.d/ 파일들 확인
    # ==========================================================================
    if [ -d /etc/sudoers.d ]; then
        for f in /etc/sudoers.d/*; do
            [ -f "$f" ] || continue
            local perm=$(stat -c "%a" "$f" 2>/dev/null || echo "000")
            local owner=$(stat -c "%U" "$f" 2>/dev/null || echo "unknown")

            if ! [[ "$perm" =~ ^[0-7]{3,4}$ ]] || [ "$(( 8#$perm & ~8#640 & 07777 ))" -ne 0 ] 2>/dev/null; then
                issues="${issues}${f} 권한 ${perm} (640 이하 권장). "
                status="취약"
                diagnosis_result="VULNERABLE"
            fi

            if [ "$owner" != "root" ]; then
                issues="${issues}${f} 소유자 ${owner} (root 권장). "
                status="취약"
                diagnosis_result="VULNERABLE"
            fi

            command_result="${command_result}${newline}${f}: ${perm} ${owner}"
        done || true
    fi

    # ==========================================================================
    # 4. 판정
    # ==========================================================================
    if [ "$diagnosis_result" = "GOOD" ]; then
        inspection_summary="/etc/sudoers 파일 소유자가 root이고 권한이 640 이하입니다."
    elif [ "$diagnosis_result" = "VULNERABLE" ]; then
        inspection_summary="sudoers 파일 설정 문제: ${issues}"
    fi

    command_result=$(echo "$command_result" | tr -d '\n\r')

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
