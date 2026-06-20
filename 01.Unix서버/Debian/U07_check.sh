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
# @Platform    : Debian
# @Severity    : 하
# @Title       : 불필요한 계정 제거
# @Description : 불필요한 기본 계정 및 장기 미사용 계정(90일 이상) 존재 여부 점검
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

ITEM_ID="U-07"
ITEM_NAME="불필요한 계정 제거"
SEVERITY="하"

# 가이드라인 정보
GUIDELINE_PURPOSE="불필요한 계정이 존재하는지 점검하여 관리되지 않은 계정에 의한 침입에 대비하는지 확인하기 위함"
GUIDELINE_THREAT="로그인이 가능하고 현재 사용하지 않는 불필요한 계정은 사용 중인 계정보다 상대적으로 관리가 취약하여 공격자의 목표가 되어 계정이 탈취될 수 있는 위험이 존재함(퇴직, 전직, 휴직 등의 사유 발생 시 즉시 권한을 회수하는 것을 권고 함)"
GUIDELINE_CRITERIA_GOOD="불필요한 계정이 존재하지 않는 경우"
GUIDELINE_CRITERIA_BAD="불필요한 계정이 존재하는 경우"
GUIDELINE_REMEDIATION="시스템에 존재하는 계정 확인 후 불필요한 계정 제거하도록 설정"

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

    # 점검 축(leg) 상태: GOOD / VULNERABLE / MANUAL
    local default_leg="GOOD"
    local inactive_leg="GOOD"
    local vulnerable_defaults=""
    local locked_defaults=""
    local undetermined_defaults=""
    local unused_accounts=""
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
    # [Leg 2] 장기 미사용(90일 이상) 계정 점검 - lastlog -t 90 교차 검증
    # ------------------------------------------------------------------
    # 1단계: /etc/passwd에서 점검 대상 계정 추출
    # - UID >= 1000 (일반 사용자, 시스템 계정 제외)
    # - 쉘이 nologin/false가 아님 (로그인 가능)
    local checkable_accounts=""
    if [ -f /etc/passwd ]; then
        checkable_accounts=$(awk -F: '$3 >= 1000 && $7 !~ /nologin|false/ {print $1}' /etc/passwd 2>/dev/null || echo "")
    fi

    # 2단계: lastlog로 90일 내 로그인 이력 확인
    # - lastlog -t 90: 90일 내 로그인한 계정 표시
    # - 이 목록에 없는 계정 = 90일 이상 미사용
    local recent_login_accounts=""
    local lastlog_rc=0
    if command -v lastlog >/dev/null 2>&1; then
        recent_login_accounts=$(lastlog -t 90 2>/dev/null | awk 'NR>1 {print $1}' | sort -u) || lastlog_rc=$?
    fi

    # 3단계: 교차 검증 - 점검 대상 계정 중 90일 이상 미사용 계정 식별
    if [ -n "$checkable_accounts" ]; then
        if command -v lastlog >/dev/null 2>&1; then
            if [ "$lastlog_rc" -ne 0 ]; then
                # lastlog 실행 실패 (예: /var/log/lastlog 없음): 90일 기준 자동 판정 불가 → 수동진단
                inactive_leg="MANUAL"
                undetermined_accounts=$(echo "$checkable_accounts" | tr '\n' ' ')
            elif [ -z "$recent_login_accounts" ]; then
                # lastlog rc=0 이지만 출력이 비어있음: /var/log/lastlog 가 비어/희소 파일이거나
                # PAM 스택이 pam_lastlog 를 호출하지 않는 환경(예: 기본 Debian 12 + SSH-key/cron)
                # → 모든 UID>=1000 계정이 거짓-미사용으로 보일 수 있으므로 자동 판정 불가 → 수동진단
                inactive_leg="MANUAL"
                undetermined_accounts=$(echo "$checkable_accounts" | tr '\n' ' ')
            else
                while IFS= read -r account; do
                    # 빈 계정명 건너뜀
                    [ -z "$account" ] && continue

                    # recent_login_accounts에 없으면 90일 이상 미사용
                    if ! echo "$recent_login_accounts" | grep -qx "$account"; then
                        unused_accounts="${unused_accounts}${account} "
                    fi
                done <<< "$checkable_accounts"

                if [ -n "$unused_accounts" ]; then
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

    local passwd_check_output="점검 대상 계정 (UID>=1000, 로그인 가능):"
    if [ -n "$checkable_accounts" ]; then
        passwd_check_output="${passwd_check_output}${newline}$(echo "$checkable_accounts" | tr '\n' ' ')"
    else
        passwd_check_output="${passwd_check_output}${newline}없음"
    fi

    local lastlog_check_output=""
    if command -v lastlog >/dev/null 2>&1; then
        lastlog_check_output="최근 90일 내 로그인 계정:"
        if [ -n "$recent_login_accounts" ]; then
            lastlog_check_output="${lastlog_check_output}${newline}$(echo "$recent_login_accounts" | tr '\n' ' ')"
        else
            lastlog_check_output="${lastlog_check_output}${newline}없음"
        fi
    else
        lastlog_check_output="lastlog 명령어 없음 - 수동 확인 필요"
    fi

    command_result="[Check 1: 기본 계정 존재/잠금 여부]${newline}${default_check_output}${newline}${newline}[Check 2: /etc/passwd 필터링]${newline}${passwd_check_output}${newline}${newline}[Check 3: lastlog -t 90]${newline}${lastlog_check_output}"
    command_executed="awk -F: /etc/passwd; awk -F: /etc/shadow; lastlog -t 90"

    # ------------------------------------------------------------------
    # 판정 병합: 취약 leg 존재 → 취약, 미확정 leg 존재 → 수동진단, 모두 양호 → 양호
    # ------------------------------------------------------------------
    if [ "$default_leg" = "VULNERABLE" ] || [ "$inactive_leg" = "VULNERABLE" ]; then
        diagnosis_result="VULNERABLE"
        status="취약"
        unused_accounts=$(echo "$unused_accounts" | tr -s ' ' | sed 's/^ *//;s/ *$//')
        inspection_summary="불필요한 계정 발견:"
        [ -n "$vulnerable_defaults" ] && inspection_summary="${inspection_summary} 미잠금 기본 계정(${vulnerable_defaults% })"
        [ -n "$unused_accounts" ] && inspection_summary="${inspection_summary} 90일 이상 미사용 계정(${unused_accounts})"
    elif [ "$default_leg" = "MANUAL" ] || [ "$inactive_leg" = "MANUAL" ]; then
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="자동 판정 불가 항목 존재 - 기본 계정 잠금 여부 또는 마지막 로그인 시각을 수동으로 확인 필요"
        [ -n "$undetermined_defaults" ] && inspection_summary="${inspection_summary} (잠금 확인 불가: ${undetermined_defaults% })"
        [ -n "$undetermined_accounts" ] && inspection_summary="${inspection_summary} (로그인 이력 확인 불가: ${undetermined_accounts% })"
    else
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="미잠금 기본 계정(lp, uucp, nuucp) 및 90일 이상 미사용 계정 없음 (시스템 계정 및 로그인 불가 계정은 미사용 점검 대상에서 제외됨)"
    fi

    # 결과 저장
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
