#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-04-20
# ============================================================================
# [점검 항목 상세]
# @ID          : U-07
# @Category    : UNIX > 1. 계정 관리
# @Platform    : RedHat
# @Severity    : 하
# @Title       : 불필요한 계정 제거
# @Description : 불필요한 기본 계정 및 장기 미사용 계정(90일 이상) 존재 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/metadata_parser.sh"

ITEM_ID="U-07"
ITEM_NAME="불필요한 계정 제거"
SEVERITY="하"

# 가이드라인 정보
GUIDELINE_PURPOSE="불필요한 계정이 존재하는지 점검하여 관리되지 않은 계정에 의한 침입에 대비하는지 확인하기 위함"
GUIDELINE_THREAT="로그인이 가능하고 현재 사용하지 않는 불필요한 계정은 사용 중인 계정보다 상대적으로 관리가 취약하여 공격자의 목표가 되어 계정이 탈취될 수 있는 위험이 존재함(퇴직, 전직, 휴직 등의 사유 발생 시 즉시 권한을 회수하는 것을 권고 함)"
GUIDELINE_CRITERIA_GOOD="불필요한 계정이 존재하지 않는 경우"
GUIDELINE_CRITERIA_BAD="불필요한 계정이 존재하는 경우"
GUIDELINE_REMEDIATION="시스템에 존재하는 계정 확인 후 불필요한 계정 제거하도록 설정"

diagnose() {
    local status="미진단"
    diagnosis_result="unknown"
    local inspection_summary=""
    local command_result=""
    local command_executed="awk -F: /etc/passwd; awk -F: /etc/shadow; lastlog -b 90"
    local newline=$'\n'

    local inactive_threshold_days=90

    # 점검 축(leg) 상태: GOOD / VULNERABLE / MANUAL
    local default_leg="GOOD"
    local inactive_leg="GOOD"
    local vulnerable_defaults=""
    local locked_defaults=""
    local undetermined_defaults=""
    local stale_accounts=""
    local undetermined_accounts=""

    # ------------------------------------------------------------------
    # [Leg 1] 불필요한 기본 계정(lp, uucp, nuucp) 존재 및 잠금 여부
    # 단순 존재만으로 취약 판정하지 않고, 로그인 가능(미잠금) 여부 확인
    # ------------------------------------------------------------------
    local account entry shell lock_state pw_field
    for account in lp uucp nuucp; do
        entry=$(awk -F: -v u="$account" '$1 == u { print $0; exit }' /etc/passwd 2>/dev/null || true)
        [ -z "$entry" ] && continue
        shell=$(echo "$entry" | awk -F: '{ print $NF }')

        lock_state="unknown"
        case "$shell" in
            */nologin|*/false)
                lock_state="locked"
                ;;
        esac

        if [ "$lock_state" = "unknown" ]; then
            pw_field=$(echo "$entry" | awk -F: '{ print $2 }')
            if [ "$pw_field" = "x" ]; then
                if [ -r /etc/shadow ]; then
                    pw_field=$(awk -F: -v u="$account" '$1 == u { print $2; exit }' /etc/shadow 2>/dev/null || true)
                else
                    pw_field="__UNREADABLE__"
                fi
            fi
            case "$pw_field" in
                '!'*|'*'*)      lock_state="locked" ;;
                __UNREADABLE__) lock_state="unknown" ;;
                *)              lock_state="unlocked" ;;
            esac
        fi

        case "$lock_state" in
            locked)   locked_defaults="${locked_defaults}${account} " ;;
            unlocked) vulnerable_defaults="${vulnerable_defaults}${account} " ;;
            *)        undetermined_defaults="${undetermined_defaults}${account} " ;;
        esac
    done

    if [ -n "$vulnerable_defaults" ]; then
        default_leg="VULNERABLE"
    elif [ -n "$undetermined_defaults" ]; then
        default_leg="MANUAL"
    fi

    # ------------------------------------------------------------------
    # [Leg 2] 장기 미사용(90일 이상) 계정 점검 - lastlog -b 90
    # (90일 이전 로그인 또는 로그인 이력 없는 계정 목록)
    # ------------------------------------------------------------------
    local checkable_accounts=""
    if [ -f /etc/passwd ]; then
        checkable_accounts=$(awk -F: '$3 >= 1000 && $7 !~ /nologin|false/ {print $1}' /etc/passwd 2>/dev/null || true)
    fi

    if [ -n "$checkable_accounts" ]; then
        if command -v lastlog >/dev/null 2>&1; then
            # lastlog 실행 실패(rc!=0, 예: /var/log/lastlog 미존재/읽기 불가)는
            # '미사용 계정 없음'과 구분하여 수동진단으로 처리 (증적 실패 → GOOD 방지)
            local stale_candidates=""
            local lastlog_rc=0
            stale_candidates=$(set -o pipefail; lastlog -b "$inactive_threshold_days" 2>/dev/null | awk 'NR > 1 { print $1 }' | sort -u) || lastlog_rc=$?

            if [ "$lastlog_rc" -ne 0 ]; then
                inactive_leg="MANUAL"
                undetermined_accounts=$(echo "$checkable_accounts" | tr '\n' ' ')
            else
                while IFS= read -r account; do
                    [ -z "$account" ] && continue
                    if [ -n "$stale_candidates" ] && echo "$stale_candidates" | grep -qx "$account"; then
                        stale_accounts="${stale_accounts}${account} "
                    fi
                done <<< "$checkable_accounts"

                if [ -n "$stale_accounts" ]; then
                    inactive_leg="VULNERABLE"
                fi
            fi
        else
            # lastlog 미지원 환경: 90일 기준 자동 판정 불가 → 수동진단
            inactive_leg="MANUAL"
            undetermined_accounts=$(echo "$checkable_accounts" | tr '\n' ' ')
        fi
    fi

    # ------------------------------------------------------------------
    # 증적 구성
    # ------------------------------------------------------------------
    local default_check_output="기본 계정(lp, uucp, nuucp) 점검:"
    [ -n "$vulnerable_defaults" ] && default_check_output="${default_check_output}${newline}로그인 가능(미잠금) 기본 계정: ${vulnerable_defaults}"
    [ -n "$locked_defaults" ] && default_check_output="${default_check_output}${newline}잠금/로그인 불가 기본 계정: ${locked_defaults}"
    [ -n "$undetermined_defaults" ] && default_check_output="${default_check_output}${newline}잠금 여부 확인 불가 기본 계정(수동 확인 필요): ${undetermined_defaults}"
    if [ -z "$vulnerable_defaults" ] && [ -z "$locked_defaults" ] && [ -z "$undetermined_defaults" ]; then
        default_check_output="${default_check_output}${newline}해당 기본 계정 없음"
    fi

    local inactive_check_output="장기 미사용(${inactive_threshold_days}일) 점검 대상 (UID>=1000, 로그인 가능):"
    if [ -n "$checkable_accounts" ]; then
        inactive_check_output="${inactive_check_output}${newline}$(echo "$checkable_accounts" | tr '\n' ' ')"
    else
        inactive_check_output="${inactive_check_output}${newline}없음"
    fi
    [ -n "$stale_accounts" ] && inactive_check_output="${inactive_check_output}${newline}${inactive_threshold_days}일 이상 미사용(또는 이력 없음) 계정: ${stale_accounts}"
    [ -n "$undetermined_accounts" ] && inactive_check_output="${inactive_check_output}${newline}lastlog 미지원 또는 실행 실패 - 수동 확인 필요: ${undetermined_accounts}"

    command_result="[Check 1: 기본 계정 존재/잠금 여부]${newline}${default_check_output}${newline}${newline}[Check 2: lastlog -b ${inactive_threshold_days} 기반 미사용 점검]${newline}${inactive_check_output}"

    # ------------------------------------------------------------------
    # 판정 병합: 취약 leg 존재 → 취약, 미확정 leg 존재 → 수동진단, 모두 양호 → 양호
    # ------------------------------------------------------------------
    if [ "$default_leg" = "VULNERABLE" ] || [ "$inactive_leg" = "VULNERABLE" ]; then
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="불필요한 계정 발견:"
        [ -n "$vulnerable_defaults" ] && inspection_summary="${inspection_summary} 미잠금 기본 계정(${vulnerable_defaults% })"
        [ -n "$stale_accounts" ] && inspection_summary="${inspection_summary} ${inactive_threshold_days}일 이상 미사용 계정(${stale_accounts% })"
    elif [ "$default_leg" = "MANUAL" ] || [ "$inactive_leg" = "MANUAL" ]; then
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="자동 판정 불가 항목 존재 - 기본 계정 잠금 여부 또는 마지막 로그인 시각을 수동으로 확인 필요"
        [ -n "$undetermined_defaults" ] && inspection_summary="${inspection_summary} (잠금 확인 불가: ${undetermined_defaults% })"
        [ -n "$undetermined_accounts" ] && inspection_summary="${inspection_summary} (로그인 이력 확인 불가: ${undetermined_accounts% })"
    else
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="미잠금 기본 계정(lp, uucp, nuucp) 및 ${inactive_threshold_days}일 이상 미사용 계정 없음"
    fi

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
