#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.1.0
# @Last Updated: 2026-02-24
# ============================================================================
# [점검 항목 상세]
# @ID          : U-07
# @Category    : Unix Server
# @Platform    : AIX
# @Severity    : 하
# @Title       : 불필요한 계정 제거
# @Description : 불필요한 기본 계정 및 장기 미사용 계정(90일 이상) 존재 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/command_validator.sh"
source "${LIB_DIR}/timeout_handler.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/metadata_parser.sh"

ITEM_ID="U-07"
ITEM_NAME="불필요한 계정 제거"
SEVERITY="하"

GUIDELINE_PURPOSE="불필요한 계정이 존재하는지 점검하여 관리되지 않은 계정에 의한 침입에 대비하는지 확인하기 위함"
GUIDELINE_THREAT="로그인이 가능하고 현재 사용하지 않는 불필요한 계정은 사용 중인 계정보다 상대적으로 관리가 취약하여 공격자의 목표가 되어 계정이 탈취될 수 있는 위험이 존재함(퇴직, 전직, 휴직 등의 사유 발생 시 즉시 권한을 회수하는 것을 권고 함)"
GUIDELINE_CRITERIA_GOOD="불필요한 계정이 존재하지 않는 경우"
GUIDELINE_CRITERIA_BAD="불필요한 계정이 존재하는 경우"
GUIDELINE_REMEDIATION="시스템에 존재하는 계정 확인 후 불필요한 계정 제거하도록 설정"

diagnose() {
    diagnosis_result="unknown"
    local status="미진단"
    local inspection_summary=""
    local command_result=""
    local command_executed=""
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
            if command -v lsuser >/dev/null 2>&1 && \
               lsuser -a account_locked "$account" 2>/dev/null | grep -q 'account_locked=true'; then
                lock_state="locked"
            elif [ -r /etc/security/passwd ]; then
                pw_field=$(awk -v u="$account" '$0 ~ "^"u":" { f = 1; next } f && /password[ \t]*=/ { print $3; exit } f && /^[^ \t]/ { exit }' /etc/security/passwd 2>/dev/null || true)
                if [ "$pw_field" = "*" ] || [ "$pw_field" = "!" ]; then
                    lock_state="locked"
                else
                    lock_state="unlocked"
                fi
            fi
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
    # [Leg 2] 장기 미사용(90일 이상) 계정 점검
    # AIX는 last -s 옵션을 지원하지 않으므로 lsuser time_last_login(epoch) 사용
    # ------------------------------------------------------------------
    local checkable_accounts=""
    if [ -f /etc/passwd ]; then
        # AIX mkuser 기본 일반계정 대역은 UID 200부터 시작하므로 200 이상을 점검 대상에 포함
        checkable_accounts=$(awk -F: '$3 >= 200 && $7 !~ /nologin|false/ {print $1}' /etc/passwd 2>/dev/null || true)
    fi

    local now_epoch=""
    now_epoch=$(date +%s 2>/dev/null || true)
    case "$now_epoch" in
        ''|*[!0-9]*) now_epoch="" ;;
    esac

    local lsuser_output=""
    if command -v lsuser >/dev/null 2>&1; then
        lsuser_output=$(lsuser -a time_last_login ALL 2>/dev/null || true)
    fi

    if [ -n "$checkable_accounts" ]; then
        if [ -n "$lsuser_output" ] && [ -n "$now_epoch" ]; then
            local cutoff_epoch=$(( now_epoch - inactive_threshold_days * 86400 ))
            local login_epoch
            while IFS= read -r account; do
                [ -z "$account" ] && continue
                login_epoch=$(echo "$lsuser_output" | awk -v u="$account" '$1 == u { for (i = 2; i <= NF; i++) if ($i ~ /^time_last_login=/) { split($i, a, "="); print a[2]; exit } }' || true)
                case "$login_epoch" in
                    ''|*[!0-9]*)
                        # 로그인 이력 자체가 없는 계정 = 미사용 계정
                        stale_accounts="${stale_accounts}${account}(이력없음) "
                        ;;
                    *)
                        if [ "$login_epoch" -lt "$cutoff_epoch" ]; then
                            stale_accounts="${stale_accounts}${account} "
                        fi
                        ;;
                esac
            done <<< "$checkable_accounts"

            if [ -n "$stale_accounts" ]; then
                inactive_leg="VULNERABLE"
            fi
        else
            # lsuser/epoch 미지원 환경: 90일 기준 자동 판정 불가 → 수동진단
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
    if [ "$inactive_leg" = "MANUAL" ]; then
        inactive_check_output="${inactive_check_output}${newline}lsuser time_last_login 확인 불가(AIX last -s 미지원) → 마지막 로그인 시각 수동 확인 필요: ${undetermined_accounts}"
    elif [ -n "$stale_accounts" ]; then
        inactive_check_output="${inactive_check_output}${newline}${inactive_threshold_days}일 이상 미사용(또는 이력 없음) 계정: ${stale_accounts}"
    fi

    command_result="[Check 1: 기본 계정 존재/잠금 여부]${newline}${default_check_output}${newline}${newline}[Check 2: lsuser time_last_login 기반 ${inactive_threshold_days}일 미사용 점검]${newline}${inactive_check_output}"
    command_executed="awk -F: /etc/passwd; lsuser -a account_locked lp uucp nuucp; lsuser -a time_last_login ALL"

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

    verify_result_saved "${ITEM_ID}"
    return 0
}

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
