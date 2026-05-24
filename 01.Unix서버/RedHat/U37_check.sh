#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-04-20
# ============================================================================
# [점검 항목 상세]
# @ID          : U-37
# @Category    : UNIX > 3. 서비스 관리
# @Platform    : SOLARIS, LINUX, AIX, HP-UX 등
# @Severity    : (상)
# @Title       : crontab 설정파일 권한 설정 미흡
# @Description : crontab 관련 파일(crontab, cron.allow/deny, at.allow/deny)의 권한 설정 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/metadata_parser.sh"

ITEM_ID="U-37"
ITEM_NAME="crontab 설정파일 권한 설정 미흡"
SEVERITY="상"

GUIDELINE_PURPOSE="관리자 외에는 서비스를 사용할 수 없도록 설정하고 있는지 점검하기 위함"
GUIDELINE_THREAT="일반 사용자가 crontab 및 at 서비스를 사용할 수 있을 경우, 고의 또는 실수로 불법적인 예약 파일 실행으로 시스템 피해를 일으킬 수 있는 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="crontab 및 at 명령어에 일반 사용자 실행 권한이 제거되어 있으며, cron 및 at 관련 파일 권한이 640 이하인 경우"
GUIDELINE_CRITERIA_BAD="crontab 및 at 명령어에 일반 사용자 실행 권한이 부여되어 있으며, cron 및 at 관련 파일 권한이 640을 초과하는 경우"
GUIDELINE_REMEDIATION="crontab 및 at 명령어 파일 권한 750 이하, cron 및 at 관련 파일 소유자 및 파일 권한 640 이하 설정"

diagnose() {
    local status="양호"
    diagnosis_result="GOOD"
    local inspection_summary=""
    local command_result=""
    local command_executed="ls -l /etc/crontab /etc/cron.allow /etc/cron.deny /etc/at.allow /etc/at.deny 2>/dev/null; stat -c '%a %U' /usr/bin/crontab /usr/bin/at 2>/dev/null"

    local issues=""
    local evidence=""

    # ==========================================================================
    # 1. /etc/crontab 파일 권한 확인
    # ==========================================================================
    local cron_file="/etc/crontab"
    if [ -f "$cron_file" ]; then
        local perm=$(stat -c "%a" "$cron_file" 2>/dev/null || echo "000")
        local owner=$(stat -c "%U" "$cron_file" 2>/dev/null || echo "unknown")
        evidence="${evidence}/etc/crontab: ${perm} ${owner}. "

        if [ "$owner" != "root" ]; then
            issues="${issues}/etc/crontab 소유자 ${owner}. "
            status="취약"
            diagnosis_result="VULNERABLE"
        fi
        if [ "$perm" -gt 640 ] 2>/dev/null; then
            issues="${issues}/etc/crontab 권한 ${perm} (640 이하 권장). "
            status="취약"
            diagnosis_result="VULNERABLE"
        fi
    fi

    # ==========================================================================
    # 2. cron.allow / cron.deny 파일 권한 확인
    # ==========================================================================
    for cron_ctrl in /etc/cron.allow /etc/cron.deny; do
        if [ -f "$cron_ctrl" ]; then
            local perm=$(stat -c "%a" "$cron_ctrl" 2>/dev/null || echo "000")
            local owner=$(stat -c "%U" "$cron_ctrl" 2>/dev/null || echo "unknown")
            evidence="${evidence}${cron_ctrl}: ${perm} ${owner}. "

            if [ "$owner" != "root" ]; then
                issues="${issues}${cron_ctrl} 소유자 ${owner}. "
                status="취약"
                diagnosis_result="VULNERABLE"
            fi
            if [ "$perm" -gt 640 ] 2>/dev/null; then
                issues="${issues}${cron_ctrl} 권한 ${perm} (640 이하 권장). "
                status="취약"
                diagnosis_result="VULNERABLE"
            fi
        fi
    done

    # ==========================================================================
    # 3. at.allow / at.deny 파일 권한 확인
    # ==========================================================================
    for at_ctrl in /etc/at.allow /etc/at.deny; do
        if [ -f "$at_ctrl" ]; then
            local perm=$(stat -c "%a" "$at_ctrl" 2>/dev/null || echo "000")
            local owner=$(stat -c "%U" "$at_ctrl" 2>/dev/null || echo "unknown")
            evidence="${evidence}${at_ctrl}: ${perm} ${owner}. "

            if [ "$owner" != "root" ]; then
                issues="${issues}${at_ctrl} 소유자 ${owner}. "
                status="취약"
                diagnosis_result="VULNERABLE"
            fi
            if [ "$perm" -gt 640 ] 2>/dev/null; then
                issues="${issues}${at_ctrl} 권한 ${perm} (640 이하 권장). "
                status="취약"
                diagnosis_result="VULNERABLE"
            fi
        fi
    done

    # ==========================================================================
    # 4. crontab / at 명령어 파일 권한 확인
    # ==========================================================================
    for cmd in /usr/bin/crontab /usr/bin/at /usr/bin/atq /usr/bin/atrm /usr/bin/batch; do
        if [ -f "$cmd" ]; then
            local perm=$(stat -c "%a" "$cmd" 2>/dev/null || echo "000")
            evidence="${evidence}${cmd}: ${perm}. "

            if [ "$perm" -gt 750 ] 2>/dev/null; then
                issues="${issues}${cmd} 권한 ${perm} (750 이하 권장). "
                status="취약"
                diagnosis_result="VULNERABLE"
            fi
        fi
    done

    # ==========================================================================
    # 5. 판정
    # ==========================================================================
    if [ "$diagnosis_result" = "GOOD" ]; then
        inspection_summary="crontab 관련 파일의 권한 및 소유자 설정이 적절합니다."
    else
        inspection_summary="crontab 관련 파일 권한 문제: ${issues}"
    fi

    command_result="${evidence:-검사 대상 없음}"
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
