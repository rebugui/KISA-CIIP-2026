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
# @Platform    : Debian
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
    local motd_file=""
    local has_warning=false
    local warning_details=""
    local raw_output=""

    # 0) /etc/motd 파일 확인 (서버 로그온 메시지)
    if [ -f /etc/motd ]; then
        local motd_content=$(cat /etc/motd 2>/dev/null || true)
        if [ -n "$motd_content" ] && echo "$motd_content" | grep -qiE "warning|unauthorized|access|prohibited|경고|무단|접속금지"; then
            has_warning=true
            motd_file="존재함 (경고 메시지 포함)"
        else
            motd_file="경고 메시지 없음"
        fi
    else
        motd_file="없음"
    fi

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

    # 3) SSH Banner 설정 확인 (SSH를 통한 로그인 시)
    local ssh_banner=""
    if [ -f /etc/ssh/sshd_config ]; then
        ssh_banner=$(grep -E "^[\s]*Banner" /etc/ssh/sshd_config 2>/dev/null | grep -v "^#" | awk '{print $2}' || true)
        if [ -n "$ssh_banner" ]; then
            local banner_path="$ssh_banner"
            if [ -f "$banner_path" ]; then
                if grep -qiE "warning|unauthorized|access|prohibited|경고|무단|접속금지" "$banner_path" 2>/dev/null; then
                    has_warning=true
                    ssh_banner="설정됨, 경고 메시지 포함 (${banner_path})"
                else
                    ssh_banner="설정됨, 경고 메시지 없음 (${banner_path})"
                fi
            else
                ssh_banner="설정됨 (파일 없음: ${banner_path})"
            fi
        else
            ssh_banner="설정 안됨"
        fi
    fi

    # 4) 사용 중인 Telnet/FTP/SMTP/DNS 서비스별 경고 메시지(배너) 확인
    local svc_issues=""
    local svc_manual=""
    local svc_info=""
    local proc_list=$(ps -ef 2>/dev/null || true)

    # [Telnet] in.telnetd 사용 시 /etc/issue.net 경고 메시지 필요
    if echo "$proc_list" | grep -wE "in\.telnetd|telnetd" | grep -v grep >/dev/null; then
        if [ -f /etc/issue.net ] && grep -qiE "warning|unauthorized|access|prohibited|경고|무단|접속금지" /etc/issue.net 2>/dev/null; then
            svc_info="${svc_info}Telnet: /etc/issue.net 경고 메시지 설정됨. "
        else
            svc_issues="${svc_issues}Telnet 사용 중이나 /etc/issue.net 경고 메시지 미설정. "
        fi
    fi

    # [FTP] vsFTP: ftpd_banner/banner_file 설정 확인
    if echo "$proc_list" | grep -w "vsftpd" | grep -v grep >/dev/null; then
        local ftp_conf=""
        if [ -f /etc/vsftpd.conf ]; then
            ftp_conf="/etc/vsftpd.conf"
        elif [ -f /etc/vsftpd/vsftpd.conf ]; then
            ftp_conf="/etc/vsftpd/vsftpd.conf"
        fi
        if [ -z "$ftp_conf" ]; then
            svc_manual="${svc_manual}vsFTP 사용 중이나 설정 파일을 찾지 못해 배너 수동 확인 필요. "
        elif grep -qE "^[[:space:]]*(ftpd_banner|banner_file)[[:space:]]*=" "$ftp_conf" 2>/dev/null; then
            svc_info="${svc_info}vsFTP: 배너 설정됨(${ftp_conf}). "
        else
            svc_issues="${svc_issues}vsFTP 사용 중이나 ftpd_banner 미설정(${ftp_conf}). "
        fi
    fi

    # [FTP] ProFTP: DisplayLogin 설정 확인
    if echo "$proc_list" | grep -w "proftpd" | grep -v grep >/dev/null; then
        local pro_conf=""
        if [ -f /etc/proftpd/proftpd.conf ]; then
            pro_conf="/etc/proftpd/proftpd.conf"
        elif [ -f /etc/proftpd.conf ]; then
            pro_conf="/etc/proftpd.conf"
        fi
        if [ -z "$pro_conf" ]; then
            svc_manual="${svc_manual}ProFTP 사용 중이나 설정 파일을 찾지 못해 배너 수동 확인 필요. "
        elif grep -qiE "^[[:space:]]*DisplayLogin" "$pro_conf" 2>/dev/null; then
            svc_info="${svc_info}ProFTP: DisplayLogin 설정됨(${pro_conf}). "
        else
            svc_issues="${svc_issues}ProFTP 사용 중이나 DisplayLogin 미설정(${pro_conf}). "
        fi
    fi

    # [SMTP] Postfix: smtpd_banner 설정 확인
    if echo "$proc_list" | grep "postfix" | grep -v grep >/dev/null; then
        if [ ! -f /etc/postfix/main.cf ]; then
            svc_manual="${svc_manual}Postfix(SMTP) 사용 중이나 main.cf를 찾지 못해 배너 수동 확인 필요. "
        elif grep -qE "^[[:space:]]*smtpd_banner[[:space:]]*=" /etc/postfix/main.cf 2>/dev/null; then
            svc_info="${svc_info}Postfix: smtpd_banner 설정됨. "
        else
            svc_issues="${svc_issues}Postfix(SMTP) 사용 중이나 smtpd_banner 미설정. "
        fi
    fi

    # [SMTP] Sendmail: SmtpGreetingMessage 설정 확인
    if echo "$proc_list" | grep -w "sendmail" | grep -v grep >/dev/null; then
        if [ ! -f /etc/mail/sendmail.cf ]; then
            svc_manual="${svc_manual}Sendmail(SMTP) 사용 중이나 sendmail.cf를 찾지 못해 배너 수동 확인 필요. "
        elif grep -qi "GreetingMessage" /etc/mail/sendmail.cf 2>/dev/null; then
            svc_info="${svc_info}Sendmail: SmtpGreetingMessage 설정됨. "
        else
            svc_issues="${svc_issues}Sendmail(SMTP) 사용 중이나 SmtpGreetingMessage 미설정. "
        fi
    fi

    # [DNS] BIND: version 지시자로 버전 정보 차단 여부 확인
    if echo "$proc_list" | grep -wE "named|bind9" | grep -v grep >/dev/null; then
        local dns_conf=""
        if [ -f /etc/bind/named.conf.options ]; then
            dns_conf="/etc/bind/named.conf.options"
        elif [ -f /etc/named.conf ]; then
            dns_conf="/etc/named.conf"
        fi
        if [ -z "$dns_conf" ]; then
            svc_manual="${svc_manual}DNS(BIND) 사용 중이나 설정 파일을 찾지 못해 version 지시자 수동 확인 필요. "
        elif grep -qE '^[[:space:]]*version[[:space:]]+"' "$dns_conf" 2>/dev/null; then
            svc_info="${svc_info}DNS: version 지시자 설정됨(${dns_conf}). "
        else
            svc_issues="${svc_issues}DNS(BIND) 사용 중이나 version 지시자 미설정(${dns_conf}). "
        fi
    fi

    # Capture raw command output
    raw_output="=== /etc/motd ===${newline}$(cat /etc/motd 2>/dev/null || echo "(없음)")${newline}=== /etc/issue ===${newline}$(cat /etc/issue 2>/dev/null || echo "(없음)")${newline}=== /etc/issue.net ===${newline}$(cat /etc/issue.net 2>/dev/null || echo "(없음)")${newline}=== SSH Banner ===${newline}$(grep -E "^[[:space:]]*Banner" /etc/ssh/sshd_config 2>/dev/null | grep -v "^#" || echo "No banner configured")${newline}=== 서비스 배너 점검 ===${newline}${svc_info:-사용 중인 Telnet/FTP/SMTP/DNS 서비스 없음 또는 미설정}${svc_issues}${svc_manual}"

    # 최종 판정 (양호: 서버(motd/issue) 및 사용 중인 Telnet/FTP/SMTP/DNS 서비스 모두 경고 메시지 설정)
    warning_details="/etc/motd: ${motd_file}, /etc/issue: ${issue_file}, /etc/issue.net: ${issue_net_file}"
    if [ -n "$ssh_banner" ]; then
        warning_details="${warning_details}, SSH Banner: ${ssh_banner}"
    fi
    if [ -n "$svc_info" ]; then
        warning_details="${warning_details}, 서비스: ${svc_info}"
    fi
    command_executed="cat /etc/motd /etc/issue /etc/issue.net 2>/dev/null; grep '^Banner' /etc/ssh/sshd_config 2>/dev/null; ps -ef | grep -E 'telnetd|vsftpd|proftpd|postfix|sendmail|named'; grep -E 'ftpd_banner|banner_file' /etc/vsftpd.conf 2>/dev/null; grep -i DisplayLogin /etc/proftpd/proftpd.conf 2>/dev/null; grep smtpd_banner /etc/postfix/main.cf 2>/dev/null; grep -i GreetingMessage /etc/mail/sendmail.cf 2>/dev/null; grep version /etc/bind/named.conf.options 2>/dev/null"

    if [ "$has_warning" != true ]; then
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="서버 로그인 경고 메시지가 설정되지 않음: ${warning_details}"
        command_result="${raw_output}"
    elif [ -n "$svc_issues" ]; then
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="사용 중인 서비스에 로그온 경고 메시지 미설정: ${svc_issues}(서버: ${warning_details})"
        command_result="${raw_output}"
    elif [ -n "$svc_manual" ]; then
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="서버 경고 메시지는 설정되었으나 일부 서비스 배너는 수동 확인 필요: ${svc_manual}"
        command_result="${raw_output}"
    else
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="로그인 경고 메시지가 설정됨: ${warning_details}"
        command_result="${raw_output}"
    fi

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
