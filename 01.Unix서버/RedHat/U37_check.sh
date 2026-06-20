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
# @Platform    : RedHat
# @Severity    : 상
# @Title       : crontab 설정 파일 권한 설정 미흡
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
ITEM_NAME="crontab 설정 파일 권한 설정 미흡"
SEVERITY="상"

GUIDELINE_PURPOSE="관리자 외에는 서비스를 사용할 수 없도록 설정하고 있는지 점검하기 위함"
GUIDELINE_THREAT="일반 사용자가 crontab 및 at 서비스를 사용할 수 있을 경우, 고의 또는 실수로 불법적인 예약 파일 실행으로 시스템 피해를 일으킬 수 있는 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="crontab 및 at 명령어에 일반 사용자 실행 권한이 제거되어 있으며,cron 및 at 관련 파일 권한이 640 이하인 경우"
GUIDELINE_CRITERIA_BAD="crontab 및 at 명령어에 일반 사용자 실행 권한이 부여되어 있으며,cron 및 at 관련 파일 권한이 640 이상인 경우"
GUIDELINE_REMEDIATION="crontab 및 at 명령어 파일 권한 750 이하,cron 및 at 관련 파일 소유자 및 파일 권한 640 이하 설정"

# 권한에 640(rw-r-----) 초과 비트가 있는지 비트 단위 검사 (10진 비교 아님)
perm_exceeds_640() {
    local p="$1"
    while [ "${#p}" -lt 3 ]; do p="0${p}"; done
    p="${p: -3}"
    local o="${p:0:1}" g="${p:1:1}" t="${p:2:1}"
    case "$o" in 1|3|5|7) return 0 ;; esac
    case "$g" in 1|2|3|5|6|7) return 0 ;; esac
    if [ "$t" != "0" ]; then
        return 0
    fi
    return 1
}

# 권한에 750(rwxr-x---) 초과 비트가 있는지 비트 단위 검사 (crontab/at 명령어용)
perm_exceeds_750() {
    local p="$1"
    while [ "${#p}" -lt 3 ]; do p="0${p}"; done
    p="${p: -3}"
    local g="${p:1:1}" t="${p:2:1}"
    case "$g" in 2|3|6|7) return 0 ;; esac
    if [ "$t" != "0" ]; then
        return 0
    fi
    return 1
}

diagnose() {
    local status="양호"
    diagnosis_result="GOOD"
    local inspection_summary=""
    local command_result=""
    local command_executed="ls -l /etc/crontab /etc/cron.allow /etc/cron.deny /etc/at.allow /etc/at.deny 2>/dev/null; stat -c '%a %U' /usr/bin/crontab /usr/bin/at 2>/dev/null; find /etc/cron.d /var/spool/cron -type f -exec stat -c '%n %a %U' {} \\; 2>/dev/null"

    local issues=""
    local evidence=""
    local checked_any=false

    # ==========================================================================
    # 1. /etc/crontab 파일 권한 확인
    # ==========================================================================
    local cron_file="/etc/crontab"
    if [ -f "$cron_file" ]; then
        checked_any=true
        local perm=$(stat -c "%a" "$cron_file" 2>/dev/null || echo "000")
        local owner=$(stat -c "%U" "$cron_file" 2>/dev/null || echo "unknown")
        evidence="${evidence}/etc/crontab: ${perm} ${owner}. "

        if [ "$owner" != "root" ]; then
            issues="${issues}/etc/crontab 소유자 ${owner}. "
            status="취약"
            diagnosis_result="VULNERABLE"
        fi
        if perm_exceeds_640 "$perm"; then
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
            checked_any=true
            local perm=$(stat -c "%a" "$cron_ctrl" 2>/dev/null || echo "000")
            local owner=$(stat -c "%U" "$cron_ctrl" 2>/dev/null || echo "unknown")
            evidence="${evidence}${cron_ctrl}: ${perm} ${owner}. "

            if [ "$owner" != "root" ]; then
                issues="${issues}${cron_ctrl} 소유자 ${owner}. "
                status="취약"
                diagnosis_result="VULNERABLE"
            fi
            if perm_exceeds_640 "$perm"; then
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
            checked_any=true
            local perm=$(stat -c "%a" "$at_ctrl" 2>/dev/null || echo "000")
            local owner=$(stat -c "%U" "$at_ctrl" 2>/dev/null || echo "unknown")
            evidence="${evidence}${at_ctrl}: ${perm} ${owner}. "

            if [ "$owner" != "root" ]; then
                issues="${issues}${at_ctrl} 소유자 ${owner}. "
                status="취약"
                diagnosis_result="VULNERABLE"
            fi
            if perm_exceeds_640 "$perm"; then
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
            checked_any=true
            local perm=$(stat -c "%a" "$cmd" 2>/dev/null || echo "000")
            evidence="${evidence}${cmd}: ${perm}. "

            if perm_exceeds_750 "$perm"; then
                issues="${issues}${cmd} 권한 ${perm} (750 이하 권장). "
                status="취약"
                diagnosis_result="VULNERABLE"
            fi
        fi
    done

    # ==========================================================================
    # 5. /etc/cron.d 및 /var/spool/cron 내 파일 권한 확인 (640 이하)
    # ==========================================================================
    local scan_dir=""
    for scan_dir in /etc/cron.d /var/spool/cron; do
        if [ -d "$scan_dir" ]; then
            local scan_file=""
            while IFS= read -r scan_file; do
                if [ ! -f "$scan_file" ]; then
                    continue
                fi
                checked_any=true
                local perm=$(stat -c "%a" "$scan_file" 2>/dev/null || echo "000")
                local owner=$(stat -c "%U" "$scan_file" 2>/dev/null || echo "unknown")
                evidence="${evidence}${scan_file}: ${perm} ${owner}. "

                if perm_exceeds_640 "$perm"; then
                    issues="${issues}${scan_file} 권한 ${perm} (640 이하 권장). "
                    status="취약"
                    diagnosis_result="VULNERABLE"
                fi
            done < <(find "$scan_dir" -type f 2>/dev/null | head -200) || true
        fi
    done

    # ==========================================================================
    # 6. 판정
    # ==========================================================================
    if [ "$diagnosis_result" = "GOOD" ] && [ "$checked_any" = false ]; then
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="cron/at 관련 파일 및 명령어가 모두 존재하지 않아 점검 불가 - 수동 점검 필요"
    elif [ "$diagnosis_result" = "GOOD" ]; then
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
