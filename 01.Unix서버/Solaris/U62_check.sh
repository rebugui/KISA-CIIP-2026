#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : U-62
# @Category    : Unix Server
# @Platform    : Solaris
# @Severity    : 하
# @Title       : 로그인 시 경고 메시지 설정
# @Description : /etc/issue, /etc/issue.net 설정 확인
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


ITEM_ID="U-62"
ITEM_NAME="로그인 시 경고 메시지 설정"
SEVERITY="하"

# 가이드라인 정보
GUIDELINE_PURPOSE="비인가자들에게 서버에 대한 불필요한 정보를 제공하지 않고, 서버 접속 시 관계자만 접속해야한다는 경각심을 심어 주기 위함"
GUIDELINE_THREAT="로그온 시 경고 메시지가 설정되어 있지 않을 경우, 기본 설정 값엔 서버 OS 버전 및 서비스 버전이 비인가자에게 노출되어 해당 정보를 통해 서비스의 취약점을 이용하여 공격을 시도할 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="서버 및 Telnet,FTP,SMTP,DNS 서비스에 로그온 시 경고 메시지가 설정된 경우"
GUIDELINE_CRITERIA_BAD="서버 및 Telnet,FTP,SMTP,DNS 서비스에 로그 온 시 경고 메시지가 설정되어 있지 않은 경우"
GUIDELINE_REMEDIATION="Telnet,FTP,SMTP,DNS 서비스를 사용하는 경우 설정 파일을 통해 로그온 시 경고 메시지 설정"

# ============================================================================
# 진단 함수
# ============================================================================

# 진단 수행
diagnose() {


    diagnosis_result="unknown"
    local status="미진단"
    local inspection_summary=""
    local command_result=""
    local command_executed=""
    local newline=$'\n'

    # 진단 로직 구현
    # 로그인 시 경고 메시지 설정 확인

    local issue_file=""
    local issue_net_file=""
    local has_warning=false
    local warning_details=""
    local raw_output=""

    # 1) /etc/issue 파일 확인 (로컬 로그인 시 경고 메시지)
    if [ -f /etc/issue ]; then
        local issue_content=$(cat /etc/issue 2>/dev/null)
        if [ -n "$issue_content" ]; then
            # 경고 메시지 키워드 확인
            if echo "$issue_content" | grep -qiE "warning|unauthorized|access|prohibited|경고|무단|접속금지"; then
                has_warning=true
                issue_file="존재함 (경고 메시지 포함)"
            else
                issue_file="존재함 (경고 메시지 없음)"
            fi
        else
            issue_file="비어있음"
        fi
    else
        issue_file="없음"
    fi

    # 2) /etc/issue.net 파일 확인 (원격 SSH 로그인 시 경고 메시지)
    if [ -f /etc/issue.net ]; then
        local issue_net_content=$(cat /etc/issue.net 2>/dev/null)
        if [ -n "$issue_net_content" ]; then
            # 경고 메시지 키워드 확인
            if echo "$issue_net_content" | grep -qiE "warning|unauthorized|access|prohibited|경고|무단|접속금지"; then
                has_warning=true
                issue_net_file="존재함 (경고 메시지 포함)"
            else
                issue_net_file="존재함 (경고 메시지 없음)"
            fi
        else
            issue_net_file="비어있음"
        fi
    else
        issue_net_file="없음"
    fi

    # 2b) /etc/motd 파일 확인 (로그인 시 공지/경고 메시지)
    local motd_file=""
    if [ -f /etc/motd ]; then
        local motd_content=$(cat /etc/motd 2>/dev/null)
        if [ -n "$motd_content" ] && echo "$motd_content" | grep -qiE "warning|unauthorized|access|prohibited|경고|무단|접속금지"; then
            has_warning=true
            motd_file="존재함 (경고 메시지 포함)"
        else
            motd_file="경고 메시지 없음"
        fi
    else
        motd_file="없음"
    fi

    # 3) SSH Banner 설정 확인 (SSH를 통한 로그인 시)
    local ssh_banner=""
    if [ -f /etc/ssh/sshd_config ]; then
        ssh_banner=$(grep -E "^[[:space:]]*Banner" /etc/ssh/sshd_config 2>/dev/null | grep -v "^[[:space:]]*#" | awk '{print $2}' || true)
        if [ -n "$ssh_banner" ]; then
            if [ -f "$ssh_banner" ]; then
                # 배너 파일 존재만으로 양호 처리하지 않고, 실제 경고 메시지 내용 확인
                if grep -qiE "warning|unauthorized|access|prohibited|경고|무단|접속금지" "$ssh_banner" 2>/dev/null; then
                    has_warning=true
                    ssh_banner="설정됨 (${ssh_banner}, 경고 메시지 포함)"
                else
                    ssh_banner="설정됨 (${ssh_banner}, 경고 메시지 없음)"
                fi
            else
                ssh_banner="설정됨 (파일 없음: ${ssh_banner})"
            fi
        else
            ssh_banner="설정 안됨"
        fi
    fi

    # 4) 사용 중인 서비스(Telnet/FTP/SMTP)별 배너 설정 확인 (Solaris)
    local svc_missing=""
    local svc_evidence=""

    # 4-1) Telnet: /etc/default/telnetd BANNER
    local telnet_on=false
    if svcs -H -o state svc:/network/telnet:default 2>/dev/null | grep -q online; then
        telnet_on=true
    elif grep -qE '^[[:space:]]*telnet[[:space:]]' /etc/inetd.conf 2>/dev/null; then
        telnet_on=true
    fi
    if [ "$telnet_on" = true ]; then
        local telnet_banner=$(grep -E '^[[:space:]]*BANNER=' /etc/default/telnetd 2>/dev/null | tail -1 || true)
        svc_evidence="${svc_evidence}[/etc/default/telnetd BANNER] ${telnet_banner:-미설정}${newline}"
        if [ -z "$telnet_banner" ] || ! echo "$telnet_banner" | grep -qiE "warning|unauthorized|access|prohibited|경고|무단|접속금지"; then
            svc_missing="${svc_missing}Telnet(/etc/default/telnetd BANNER) "
        fi
    fi

    # 4-2) FTP: /etc/default/ftpd BANNER
    local ftp_on=false
    if svcs -H -o state svc:/network/ftp:default 2>/dev/null | grep -q online; then
        ftp_on=true
    elif grep -qE '^[[:space:]]*ftp[[:space:]]' /etc/inetd.conf 2>/dev/null; then
        ftp_on=true
    fi
    if [ "$ftp_on" = true ]; then
        local ftp_banner=$(grep -E '^[[:space:]]*BANNER=' /etc/default/ftpd 2>/dev/null | tail -1 || true)
        svc_evidence="${svc_evidence}[/etc/default/ftpd BANNER] ${ftp_banner:-미설정}${newline}"
        if [ -z "$ftp_banner" ] || ! echo "$ftp_banner" | grep -qiE "warning|unauthorized|access|prohibited|경고|무단|접속금지"; then
            svc_missing="${svc_missing}FTP(/etc/default/ftpd BANNER) "
        fi
    fi

    # 4-3) SMTP(sendmail): SmtpGreetingMessage 설정 (버전 노출 매크로 $v 미사용)
    local smtp_on=false
    if svcs -H -o state svc:/network/smtp:sendmail 2>/dev/null | grep -q online; then
        smtp_on=true
    elif ps -ef 2>/dev/null | grep -q "[s]endmail"; then
        smtp_on=true
    fi
    if [ "$smtp_on" = true ] && [ -f /etc/mail/sendmail.cf ]; then
        local smtp_greeting=$(grep -E '^O[[:space:]]*SmtpGreetingMessage' /etc/mail/sendmail.cf 2>/dev/null | tail -1 || true)
        svc_evidence="${svc_evidence}[sendmail SmtpGreetingMessage] ${smtp_greeting:-미설정}${newline}"
        if [ -z "$smtp_greeting" ] || echo "$smtp_greeting" | grep -q '\$v'; then
            svc_missing="${svc_missing}SMTP(sendmail.cf SmtpGreetingMessage 미설정 또는 버전 노출) "
        fi
    fi

    # 4-4) DNS(named/BIND): named 실행 중이면 named.conf의 version 디렉티브로 버전 은닉 확인
    #      (가이드 U-62 DNS: /etc/named.conf 또는 /etc/bind/named.conf.options 의 version "..."; 설정)
    local dns_on=false
    if svcs -H -o state svc:/network/dns/server:default 2>/dev/null | grep -q online; then
        dns_on=true
    elif ps -ef 2>/dev/null | grep -q "[n]amed"; then
        dns_on=true
    fi
    if [ "$dns_on" = true ]; then
        local named_version_ok=false
        local named_conf
        for named_conf in /etc/named.conf /etc/bind/named.conf.options /etc/bind/named.conf; do
            [ -f "$named_conf" ] || continue
            if grep -E '^[[:space:]]*version[[:space:]]+["'\'']?[^;]+' "$named_conf" 2>/dev/null | grep -v '^[[:space:]]*//' >/dev/null 2>&1; then
                named_version_ok=true
                svc_evidence="${svc_evidence}[DNS] ${named_conf} version 디렉티브 설정됨${newline}"
                break
            fi
        done
        if [ "$named_version_ok" = false ]; then
            svc_missing="${svc_missing}DNS(named.conf version 은닉 미설정) "
        fi
    fi

    # Capture raw command output
    raw_output=$(
        echo "=== /etc/issue ==="
        cat /etc/issue 2>/dev/null
        echo ""
        echo "=== /etc/issue.net ==="
        cat /etc/issue.net 2>/dev/null
        echo ""
        echo "=== /etc/motd ==="
        cat /etc/motd 2>/dev/null
        echo ""
        echo "=== SSH Banner ==="
        grep -E "^[[:space:]]*Banner" /etc/ssh/sshd_config 2>/dev/null | grep -v "^[[:space:]]*#" || echo "No banner configured"
    )
    raw_output="${raw_output}${newline}${svc_evidence}"

    # 최종 판정
    warning_details="/etc/issue: ${issue_file}, /etc/issue.net: ${issue_net_file}, /etc/motd: ${motd_file}"
    [ -n "$ssh_banner" ] && warning_details="${warning_details}, SSH Banner: ${ssh_banner}"
    if [ -n "$svc_missing" ]; then
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="사용 중인 서비스에 로그온 경고 메시지 미설정: ${svc_missing%% }(일반 배너: ${warning_details})"
        command_result="${raw_output}"
        command_executed="cat /etc/issue /etc/issue.net /etc/motd 2>/dev/null; grep '^Banner' /etc/ssh/sshd_config 2>/dev/null; grep BANNER /etc/default/telnetd /etc/default/ftpd 2>/dev/null; grep SmtpGreetingMessage /etc/mail/sendmail.cf 2>/dev/null"
    elif [ "$has_warning" = true ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="로그인 경고 메시지가 설정됨: ${warning_details}"
        command_result="${raw_output}"
        command_executed="cat /etc/issue /etc/issue.net /etc/motd 2>/dev/null; grep '^Banner' /etc/ssh/sshd_config 2>/dev/null; grep BANNER /etc/default/telnetd /etc/default/ftpd 2>/dev/null; grep SmtpGreetingMessage /etc/mail/sendmail.cf 2>/dev/null"
    else
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="로그인 경고 메시지가 설정되지 않음: ${warning_details}"
        command_result="${raw_output}"
        command_executed="cat /etc/issue /etc/issue.net /etc/motd 2>/dev/null; grep '^Banner' /etc/ssh/sshd_config 2>/dev/null; grep BANNER /etc/default/telnetd /etc/default/ftpd 2>/dev/null; grep SmtpGreetingMessage /etc/mail/sendmail.cf 2>/dev/null"
    fi

    # echo ""
    # echo "진단 결과: ${status}"
    # echo "판정: ${diagnosis_result}"
    # echo "설명: ${inspection_summary}"
    # echo ""

    # 결과 생성 (PC 패턴: 스크립트에서 모드 확인 후 처리)
    # Run-all 모드 확인
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
    # 진단 시작 표시
    show_diagnosis_start "${ITEM_ID}" "${ITEM_NAME}"

    # 디스크 공간 확인
    check_disk_space

    # 진단 수행
    diagnose

    # 진단 완료 표시
    show_diagnosis_complete "${ITEM_ID}" "${diagnosis_result:-UNKNOWN}"

    return 0
}

# 스크립트 직접 실행 시에만 진단 수행
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi
