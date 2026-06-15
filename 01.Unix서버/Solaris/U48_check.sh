#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-04-20
# ============================================================================
# [점검 항목 상세]
# @ID          : U-48
# @Category    : UNIX > 3. 서비스 관리
# @Platform    : Solaris
# @Severity    : 중
# @Title       : expn, vrfy 명령어 제한
# @Description : SMTP 서버의 EXPN 및 VRFY 명령어 비활성화 여부 점검
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

ITEM_ID="U-48"
ITEM_NAME="expn, vrfy 명령어 제한"
SEVERITY="중"

# 가이드라인 정보
GUIDELINE_PURPOSE="SMTP 서비스의 expn,vrfy 명령을 통한 정보 유출을 방지하기 위함"
GUIDELINE_THREAT="expn, vrfy 명령어를 통하여 특정 사용자 계정의 존재 여부를 알 수 있고, 사용자의 정보를 외부로 유출할 수 있는 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="noexpn, novrfy 옵션이 설정된 경우"
GUIDELINE_CRITERIA_BAD="noexpn, novrfy 옵션이 설정되어 있지 않은 경우"
GUIDELINE_REMEDIATION="메일 서비스를 사용하지 않는 경우 서비스 중지 및 비활성화 설정 메일 서비스 사용 시 메일 서비스 설정 파일에 noexpn,novrfy 또는 goaway 옵션 추가 설정"

diagnose() {
    diagnosis_result="unknown"
    local status="미진단"
    local inspection_summary=""
    local command_result=""
    local command_executed=""
    local newline=$'\n'

    # ==========================================================================
    # 1. 메일 서비스(MTA) 사용 여부 확인 (Solaris SMF + 설정 파일 + 프로세스)
    # ==========================================================================
    local sendmail_conf=""
    if [ -f /etc/mail/sendmail.cf ]; then
        sendmail_conf="/etc/mail/sendmail.cf"
    elif [ -f /etc/sendmail.cf ]; then
        sendmail_conf="/etc/sendmail.cf"
    fi

    local postfix_present=false
    if command -v postconf >/dev/null 2>&1 || [ -f /etc/postfix/main.cf ]; then
        postfix_present=true
    fi

    local sendmail_running=false
    local postfix_running=false
    if svcs sendmail 2>/dev/null | grep -q "online"; then
        sendmail_running=true
    fi
    if svcs postfix 2>/dev/null | grep -q "online"; then
        postfix_running=true
    fi
    local smtp_daemon=""
    smtp_daemon=$(ps -ef 2>/dev/null | grep -E '[s]endmail|[p]ostfix/master' || true)
    if echo "$smtp_daemon" | grep -q "endmail"; then
        sendmail_running=true
    fi
    if echo "$smtp_daemon" | grep -q "ostfix"; then
        postfix_running=true
    fi

    command_executed="svcs sendmail postfix; ps -ef | grep -E 'sendmail|postfix'; grep -E '^[[:space:]]*O[[:space:]]*PrivacyOptions' /etc/mail/sendmail.cf; postconf -h disable_vrfy_command"

    # ==========================================================================
    # 2. 메일 서비스 미사용 시 양호
    # ==========================================================================
    if [ -z "$sendmail_conf" ] && [ "$postfix_present" = false ] && \
       [ "$sendmail_running" = false ] && [ "$postfix_running" = false ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="메일 서비스(SMTP)를 사용하지 않습니다. (sendmail/postfix 설정 및 데몬 없음)"
        command_result="sendmail.cf: 없음 / postfix: 없음 / SMTP 데몬: 미실행"

        save_dual_result \
            "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" \
            "${inspection_summary}" "${command_result}" "${command_executed}" \
            "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" \
            "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"

        verify_result_saved "${ITEM_ID}"
        return 0
    fi

    # ==========================================================================
    # 3. 사용 중인 MTA별 expn/vrfy 제한 설정 확인
    # ==========================================================================
    local leg_vulnerable=false
    local details=""

    # 3-1. Sendmail: PrivacyOptions에 (noexpn AND novrfy) 또는 goaway 필요
    if [ -n "$sendmail_conf" ] || [ "$sendmail_running" = true ]; then
        local privacy_opts=""
        if [ -n "$sendmail_conf" ]; then
            privacy_opts=$(grep -E '^[[:space:]]*O[[:space:]]*PrivacyOptions' "$sendmail_conf" 2>/dev/null | tail -1 | sed 's/^[^=]*=//' || true)
        fi
        local sm_expn=false
        local sm_vrfy=false
        if echo "$privacy_opts" | grep -qi "goaway"; then
            sm_expn=true
            sm_vrfy=true
        fi
        if echo "$privacy_opts" | grep -qi "noexpn"; then
            sm_expn=true
        fi
        if echo "$privacy_opts" | grep -qi "novrfy"; then
            sm_vrfy=true
        fi
        if [ "$sm_expn" = true ] && [ "$sm_vrfy" = true ]; then
            details="${details}[Sendmail] PrivacyOptions 제한 설정됨 (${privacy_opts}); "
        else
            leg_vulnerable=true
            details="${details}[Sendmail] PrivacyOptions에 noexpn/novrfy(또는 goaway) 미설정 (현재: ${privacy_opts:-미설정}); "
        fi
    fi

    # 3-2. Postfix: disable_vrfy_command=yes 필요 (expn은 Postfix 기본 미지원)
    if [ "$postfix_present" = true ] || [ "$postfix_running" = true ]; then
        local disable_vrfy=""
        if command -v postconf >/dev/null 2>&1; then
            disable_vrfy=$(postconf -h disable_vrfy_command 2>/dev/null | tr -d '[:space:]' || true)
        fi
        if [ -z "$disable_vrfy" ] && [ -f /etc/postfix/main.cf ]; then
            disable_vrfy=$(grep -E '^[[:space:]]*disable_vrfy_command[[:space:]]*=' /etc/postfix/main.cf 2>/dev/null | tail -1 | cut -d= -f2- | tr -d '[:space:]' || true)
        fi
        if [ "$disable_vrfy" = "yes" ]; then
            details="${details}[Postfix] disable_vrfy_command=yes (expn 기본 미지원); "
        else
            leg_vulnerable=true
            details="${details}[Postfix] disable_vrfy_command=${disable_vrfy:-no(기본값)} - vrfy 명령 허용 상태; "
        fi
    fi

    # ==========================================================================
    # 4. 판정
    # ==========================================================================
    if [ "$leg_vulnerable" = false ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="사용 중인 SMTP 서비스의 expn, vrfy 명령어가 제한되어 있습니다. (${details})"
    else
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="사용 중인 SMTP 서비스에서 expn/vrfy 명령어 제한 설정이 미흡합니다. (${details})"
    fi

    command_result="${details}"
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
    check_disk_space
    diagnose
    show_diagnosis_complete "${ITEM_ID}" "${diagnosis_result:-UNKNOWN}"
    return 0
}

if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi
