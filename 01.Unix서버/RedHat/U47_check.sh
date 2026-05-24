#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-28
# ============================================================================
# [점검 항목 상세]
# @ID          : U-47
# @Category    : UNIX > 3. 서비스 관리
# @Platform    : RedHat
# @Severity    : 상
# @Title       : 스팸메일 릴레이 제한
# @Description : SMTP 서버의 메일 릴레이 기능을 제한하여 스팸 메일 경유지로 악용되는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

set -euo pipefail

# 스크립트 디렉토리 설정
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../../lib"

# 필수 라이브러리 로드
source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/metadata_parser.sh"

ITEM_ID="U-47"
ITEM_NAME="스팸메일 릴레이 제한"
SEVERITY="상"

# 가이드라인 정보
GUIDELINE_PURPOSE="스팸메일 서버로의 악용 방지 및 서버 과부하를 방지하기 위함"
GUIDELINE_THREAT="SMTP 서버의 릴레이 기능을 제한하지 않을 경우, 악의적인 사용 목적을 가진 사용자들이 스팸 메일 서버로 사용하거나 DoS 공격의 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="릴레이 제한이 설정된 경우"
GUIDELINE_CRITERIA_BAD="릴레이 제한이 설정되어 있지 않은 경우"
GUIDELINE_REMEDIATION="메일 서비스를 사용하지 않는 경우 서비스 중지 및 비활성화 설정 메일 서비스 사용 시 릴레이 방지 설정 또는 릴레이 대상 접근 제어 설정"

diagnose() {
    local status="미진단"
    diagnosis_result="unknown"
    local inspection_summary=""
    local command_result=""
    local command_executed=""
    local newline=$'\n'

    # 스팸 메일 릴레이 제한 확인
    local mail_running=false
    local relay_restricted=false
    local relay_info=""

    # 0) 메일 서비스 실행 여부 확인
    if systemctl is-active --quiet sendmail 2>/dev/null; then
        mail_running=true
    fi
    if systemctl is-active --quiet postfix 2>/dev/null; then
        mail_running=true
    fi
    if command -v sendmail &>/dev/null || command -v postconf &>/dev/null; then
        mail_running=true
    fi

    # 메일 서비스 미설치 시 양호
    if [ "$mail_running" = false ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="메일 서비스 미설치됨"
        local svc_check=$(systemctl is-active --quiet sendmail 2>/dev/null && echo "Sendmail: active" || echo "Sendmail: inactive"; systemctl is-active --quiet postfix 2>/dev/null && echo "Postfix: active" || echo "Postfix: inactive")
        command_result="[Command: systemctl is-active mail services]${newline}${svc_check}"
        command_executed="systemctl is-active --quiet sendmail postfix; command -v sendmail postconf"
    else
        # 1) Sendmail 릴레이 제한 확인
        if [ -f /etc/mail/sendmail.cf ] || [ -f /etc/sendmail.cf ]; then
            local conf_file="/etc/mail/sendmail.cf"
            [ ! -f "$conf_file" ] && conf_file="/etc/sendmail.cf"

            # PrivacyOptions 확인
            local privacy_options=$(grep -i "^O PrivacyOptions" "$conf_file" | grep -v "^#" || echo "")
            relay_info="${relay_info}Sendmail PrivacyOptions:\\n${privacy_options}\\n"

            if echo "$privacy_options" | grep -qi "goaway"; then
                relay_restricted=true
                relay_info="${relay_info}goaway 옵션으로 릴레이 제한됨\\n"
            fi

            # access.db 파일 확인
            if [ -f /etc/mail/access.db ] || [ -f /etc/mail/access ]; then
                relay_restricted=true
                relay_info="${relay_info}Sendmail access DB 존재\\n"
            fi
        fi

        # 2) Postfix 릴레이 제한 확인
        if command -v postconf &>/dev/null; then
            # smtpd_relay_restrictions 확인
            local relay_restrictions=$(postconf smtpd_relay_restrictions 2>/dev/null | grep "smtpd_relay_restrictions")
            relay_info="${relay_info}Postfix smtpd_relay_restrictions:\\n${relay_restrictions}\\n"

            if echo "$relay_restrictions" | grep -q "permit_mynetworks"; then
                relay_restricted=true
                relay_info="${relay_info}permit_mynetworks로 제한됨\\n"
            fi

            if echo "$relay_restrictions" | grep -q "reject_unauth_destination"; then
                relay_restricted=true
                relay_info="${relay_info}reject_unauth_destination로 제한됨\\n"
            fi

            # smtpd_recipient_restrictions 확인 (구버전)
            local recipient_restrictions=$(postconf smtpd_recipient_restrictions 2>/dev/null | grep "smtpd_recipient_restrictions")
            relay_info="${relay_info}smtpd_recipient_restrictions:\\n${recipient_restrictions}\\n"

            # mynetworks 설정 확인
            local mynetworks=$(postconf mynetworks 2>/dev/null | grep "mynetworks" | awk '{print $3}')
            relay_info="${relay_info}mynetworks: ${mynetworks}\\n"

            # relay_domains 확인
            local relay_domains=$(postconf relay_domains 2>/dev/null | grep "relay_domains" | awk '{print $3}')
            relay_info="${relay_info}relay_domains: ${relay_domains}\\n"
        fi

        # 3) open relay 테스트 (기본 확인만)
        if command -v nc &>/dev/null; then
            relay_info="${relay_info}open relay 테스트는 수동으로 수행 필요\\n"
        fi

        # 최종 판정
        if [ "$relay_restricted" = true ]; then
            diagnosis_result="GOOD"
            status="양호"
            inspection_summary="메일 릴레이 제한 설정됨"
            command_result="${relay_info}"
            command_executed="postconf smtpd_relay_restrictions smtpd_recipient_restrictions mynetworks relay_domains"
        else
            diagnosis_result="VULNERABLE"
            status="취약"
            inspection_summary="메일 릴레이 제한 미흡 - open relay 가능성"
            command_result="${relay_info}"
            command_executed="postconf smtpd_relay_restrictions; grep -i 'PrivacyOptions' /etc/mail/sendmail.cf 2>/dev/null"
        fi
    fi

    save_dual_result \
        "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" \
        "${inspection_summary}" "${command_result}" "${command_executed}" \
        "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" \
        "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" \
        "${GUIDELINE_REMEDIATION}"

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
