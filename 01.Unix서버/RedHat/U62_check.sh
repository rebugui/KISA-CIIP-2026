#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-28
# ============================================================================
# [점검 항목 상세]
# @ID          : U-62
# @Category    : UNIX > 6. 로그 관리
# @Platform    : RedHat
# @Severity    : 하
# @Title       : 로그인 시 경고 메시지 설정
# @Description : 서버 접속 시 법적 책임 및 경고 문구가 포함된 배너 출력 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/metadata_parser.sh"

ITEM_ID="U-62"
ITEM_NAME="로그인 시 경고 메시지 설정"
SEVERITY="하"

GUIDELINE_PURPOSE="비인가자들에게 서버에 대한 불필요한 정보를 제공하지 않고, 서버 접속 시 관계자만 접속해야한다는 경각심을 심어 주기 위함"
GUIDELINE_THREAT="로그온 시 경고 메시지가 설정되어 있지 않을 경우, 기본 설정 값엔 서버 OS 버전 및 서비스 버전이 비인가자에게 노출되어 해당 정보를 통해 서비스의 취약점을 이용하여 공격을 시도할 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="서버 및 Telnet,FTP,SMTP,DNS 서비스에 로그온 시 경고 메시지가 설정된 경우"
GUIDELINE_CRITERIA_BAD="서버 및 Telnet,FTP,SMTP,DNS 서비스에 로그 온 시 경고 메시지가 설정되어 있지 않은 경우"
GUIDELINE_REMEDIATION="Telnet,FTP,SMTP,DNS 서비스를 사용하는 경우 설정 파일을 통해 로그온 시 경고 메시지 설정"

diagnose() {
    local status="양호"
    diagnosis_result="GOOD"
    local inspection_summary="로그인 경고 메시지가 적절하게 설정되어 있습니다."
    local command_result=""
    local command_executed="cat /etc/motd /etc/issue /etc/issue.net; grep ftpd_banner /etc/vsftpd/vsftpd.conf; grep smtpd_banner /etc/postfix/main.cf; grep version /etc/named.conf"

    local warn_regex="warning|unauthorized|access|prohibited|경고|무단|접속금지"
    local motd_content=$(cat /etc/motd 2>/dev/null | xargs || echo "")
    local issue_content=$(cat /etc/issue.net 2>/dev/null | xargs || echo "")
    local issue_local_content=$(cat /etc/issue 2>/dev/null | xargs || echo "")

    local missing=""

    # 1. 서버(로컬 로그인) 배너: /etc/motd 또는 /etc/issue 에 경고 문구 필요
    local server_warning=false
    if [ -n "$motd_content" ] && echo "$motd_content" | grep -qiE "$warn_regex"; then
        server_warning=true
    fi
    if [ -n "$issue_local_content" ] && echo "$issue_local_content" | grep -qiE "$warn_regex"; then
        server_warning=true
    fi
    [ "$server_warning" = false ] && missing="${missing}[서버: /etc/motd,/etc/issue 경고 문구 없음] "

    # 2. Telnet 사용 시: /etc/issue.net 자체에 경고 문구 필요 (motd로 대체 불가,
    #    기본 issue.net은 \S, \r, \m 등 OS 정보를 노출)
    local telnet_active=false
    if systemctl is-active --quiet telnet.socket 2>/dev/null || systemctl is-active --quiet telnetd 2>/dev/null; then
        telnet_active=true
    elif ps aux 2>/dev/null | grep -E "in\.telnetd|[t]elnetd" | grep -v grep >/dev/null 2>&1; then
        telnet_active=true
    elif [ -f /etc/xinetd.d/telnet ] && ! grep -qiE '^[[:space:]]*disable[[:space:]]*=[[:space:]]*yes' /etc/xinetd.d/telnet 2>/dev/null; then
        telnet_active=true
    fi
    if [ "$telnet_active" = true ]; then
        if [ -z "$issue_content" ] || ! echo "$issue_content" | grep -qiE "$warn_regex"; then
            missing="${missing}[Telnet: /etc/issue.net 경고 문구 없음] "
        fi
    fi

    # 3. FTP(vsftpd) 사용 시: ftpd_banner 또는 banner_file 설정 필요
    if pgrep -x vsftpd >/dev/null 2>&1; then
        local vsftpd_conf=""
        local vc
        for vc in /etc/vsftpd/vsftpd.conf /etc/vsftpd.conf; do
            if [ -f "$vc" ]; then
                vsftpd_conf="$vc"
                break
            fi
        done
        if [ -z "$vsftpd_conf" ] || ! grep -qE '^[[:space:]]*(ftpd_banner|banner_file)=' "$vsftpd_conf" 2>/dev/null; then
            missing="${missing}[FTP: vsftpd ftpd_banner/banner_file 미설정] "
        fi
    fi

    # 3b. FTP(proftpd) 사용 시: DisplayLogin 설정 필요
    if pgrep -x proftpd >/dev/null 2>&1; then
        local proftpd_conf=""
        local pc
        for pc in /etc/proftpd/proftpd.conf /etc/proftpd.conf; do
            if [ -f "$pc" ]; then
                proftpd_conf="$pc"
                break
            fi
        done
        if [ -z "$proftpd_conf" ] || ! grep -qiE '^[[:space:]]*DisplayLogin' "$proftpd_conf" 2>/dev/null; then
            missing="${missing}[FTP: proftpd DisplayLogin 미설정] "
        fi
    fi

    # 4. SMTP 사용 시: postfix smtpd_banner / sendmail SmtpGreetingMessage 설정 필요 (값에 경고 문구 포함 확인)
    if pgrep -x master >/dev/null 2>&1 && [ -f /etc/postfix/main.cf ]; then
        if grep -qE '^[[:space:]]*smtpd_banner[[:space:]]*=' /etc/postfix/main.cf 2>/dev/null; then
            local banner_val
            banner_val=$(grep -E '^[[:space:]]*smtpd_banner[[:space:]]*=' /etc/postfix/main.cf 2>/dev/null | tail -1 | sed 's/^[[:space:]]*smtpd_banner[[:space:]]*=[[:space:]]*//; s/[[:space:]]*#.*$//' || true)
            if ! echo "$banner_val" | grep -qiE "$warn_regex"; then
                missing="${missing}[SMTP: postfix smtpd_banner 경고 문구 없음 (${banner_val})] "
            fi
        else
            missing="${missing}[SMTP: postfix smtpd_banner 미설정] "
        fi
    fi
    if pgrep -x sendmail >/dev/null 2>&1 && [ -f /etc/mail/sendmail.cf ]; then
        if grep -qE '^O[[:space:]]*SmtpGreetingMessage' /etc/mail/sendmail.cf 2>/dev/null; then
            local greeting_val
            greeting_val=$(grep -E '^O[[:space:]]*SmtpGreetingMessage' /etc/mail/sendmail.cf 2>/dev/null | tail -1 | sed 's/^O[[:space:]]*SmtpGreetingMessage[[:space:]]*=[[:space:]]*//; s/[[:space:]]*#.*$//' || true)
            if ! echo "$greeting_val" | grep -qiE "$warn_regex"; then
                missing="${missing}[SMTP: sendmail SmtpGreetingMessage 경고 문구 없음 (${greeting_val})] "
            fi
        else
            missing="${missing}[SMTP: sendmail SmtpGreetingMessage 미설정] "
        fi
    fi

    # 5. DNS(named) 사용 시: version 문자열 숨김 설정 필요
    if pgrep -x named >/dev/null 2>&1; then
        if ! grep -v '^[[:space:]]*//' /etc/named.conf 2>/dev/null | grep -qE '^[^#]*version[[:space:]]+"' ; then
            missing="${missing}[DNS: named.conf version 숨김 미설정] "
        fi
    fi

    if [ -n "$missing" ]; then
        status="취약"
        diagnosis_result="VULNERABLE"
        if [ -z "$motd_content" ] && [ -z "$issue_content" ] && [ -z "$issue_local_content" ]; then
            inspection_summary="서버 접속 시 출력되는 경고 메시지(배너)가 설정되지 않았습니다. 미흡 항목: ${missing}"
        else
            inspection_summary="서버 또는 사용 중인 서비스(Telnet/FTP/SMTP/DNS)에 경고 메시지가 설정되어 있지 않습니다. 미흡 항목: ${missing}"
        fi
    fi
    command_result=$(echo "motd: [ ${motd_content:-empty} ], issue: [ ${issue_local_content:-empty} ], issue.net: [ ${issue_content:-empty} ], 미흡: [ ${missing:-없음} ]" | tr -d '\n\r')

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
