#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-04-20
# ============================================================================
# [점검 항목 상세]
# @ID          : U-56
# @Category    : UNIX > 2. 서비스 관리
# @Platform    : RedHat
# @Severity    : 하
# @Title       : FTP 서비스 접근 제어 설정
# @Description : FTP 서비스의 접근 제어 설정 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/metadata_parser.sh"

ITEM_ID="U-56"
ITEM_NAME="FTP 서비스 접근 제어 설정"
SEVERITY="하"

GUIDELINE_PURPOSE="접근 권한이 없는 비인가자의 접근을 통제하기 위함"
GUIDELINE_THREAT="FTP 서비스의 접근 제한 설정이 적절하지 않을 경우, 인증 절차 없이 비인가자가 디렉터리나 파일에 접근할 수 있어 중요 파일 변조 및 유출을 시도할 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="특정 IP 주소 또는 호스트에서만 FTP 서버에 접속할 수 있도록 접근 제어 설정을 적용한 경우"
GUIDELINE_CRITERIA_BAD="FTP 서버에 접근 제어 설정을 적용하지 않은 경우"
GUIDELINE_REMEDIATION="FTP 서비스를 사용하지 않는 경우 서비스 중지 및 비활성화 설정 FTP 서비스 사용 시 접근 제어 설정"

diagnose() {
    local status="양호"
    diagnosis_result="GOOD"
    local inspection_summary="FTP 서비스 접근 제어가 적절합니다."
    local command_result=""
    local command_executed="grep -E 'userlist|tcp_wrappers' /etc/vsftpd/vsftpd.conf; cat /etc/hosts.allow /etc/hosts.deny 2>/dev/null"

    local ftp_installed=false
    local access_configured=false
    local details=""

    # ==========================================================================
    # 1. FTP 서비스 설치 여부 확인
    # ==========================================================================
    if rpm -qa 2>/dev/null | grep -q "vsftpd\|proftpd\|pure-ftpd"; then
        ftp_installed=true
    fi

    if [ "$ftp_installed" = false ]; then
        status="양호"
        diagnosis_result="GOOD"
        inspection_summary="FTP 서비스가 설치되어 있지 않습니다."
        command_result="FTP: [not installed]"
        command_executed="rpm -qa | grep -E 'vsftpd|proftpd|pure-ftpd'"

        save_dual_result \
            "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" \
            "${inspection_summary}" "${command_result}" "${command_executed}" \
            "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" \
            "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"

        verify_result_saved "${ITEM_ID}"
        return 0
    fi

    # ==========================================================================
    # 2. vsftpd 접근 제어 확인
    # ==========================================================================
    if [ -f /etc/vsftpd/vsftpd.conf ] || [ -f /etc/vsftpd.conf ]; then
        local vsftpd_conf="/etc/vsftpd/vsftpd.conf"
        [ ! -f "$vsftpd_conf" ] && vsftpd_conf="/etc/vsftpd.conf"

        # userlist_enable 확인 (user_list에 실제 항목이 있어야 접근 제어로 인정)
        if grep -q "^userlist_enable=YES" "$vsftpd_conf" 2>/dev/null; then
            local userlist_file=$(grep "^userlist_file" "$vsftpd_conf" 2>/dev/null | head -1 | cut -d= -f2 | tr -d '[:space:]')
            [ -z "$userlist_file" ] && userlist_file="/etc/vsftpd/user_list"
            local userlist_count=0
            if [ -f "$userlist_file" ]; then
                userlist_count=$(grep -v "^#" "$userlist_file" 2>/dev/null | grep -v "^$" | wc -l) || true
            fi
            if [ "$userlist_count" -gt 0 ]; then
                access_configured=true
                details="${details}[vsftpd] userlist 활성화 (${userlist_file}: ${userlist_count}개 계정). "
            else
                details="${details}[vsftpd] userlist_enable=YES (user_list 항목 없음). "
            fi
        fi

        # tcp_wrappers 확인
        if grep -q "^tcp_wrappers=YES" "$vsftpd_conf" 2>/dev/null; then
            if [ -f /etc/hosts.allow ] || [ -f /etc/hosts.deny ]; then
                local hosts_allow=$(grep -v "^#" /etc/hosts.allow 2>/dev/null | grep -v "^$" | grep -i "vsftpd" || true)
                local hosts_deny=$(grep -v "^#" /etc/hosts.deny 2>/dev/null | grep -v "^$" | grep -i "vsftpd" || true)
                if [ -n "$hosts_allow" ] || [ -n "$hosts_deny" ]; then
                    access_configured=true
                    details="${details}[vsftpd] tcp_wrappers 설정됨. "
                fi
            fi
        fi
    fi

    # ==========================================================================
    # 3. proftpd 접근 제어 확인
    # ==========================================================================
    if [ -f /etc/proftpd.conf ] || [ -f /etc/proftpd/proftpd.conf ]; then
        local proftpd_conf="/etc/proftpd.conf"
        [ ! -f "$proftpd_conf" ] && proftpd_conf="/etc/proftpd/proftpd.conf"

        if grep -qE "^[\s]*<Limit.*LOGIN>" "$proftpd_conf" 2>/dev/null; then
            access_configured=true
            details="${details}[proftpd] <Limit LOGIN> 설정됨. "
        fi

        if grep -qE "^[\s]*<Limit.*ALL>" "$proftpd_conf" 2>/dev/null; then
            access_configured=true
            details="${details}[proftpd] <Limit ALL> 설정됨. "
        fi
    fi

    # ==========================================================================
    # 4. /etc/hosts.allow / hosts.deny 확인 (일반적)
    # ==========================================================================
    if [ -f /etc/hosts.allow ]; then
        local ftp_rules=$(grep -v "^#" /etc/hosts.allow 2>/dev/null | grep -v "^$" | grep -iE "ftp|vsftpd|proftpd" || true)
        if [ -n "$ftp_rules" ]; then
            access_configured=true
            details="${details}[hosts.allow] FTP 관련 규칙 존재. "
        fi
    fi

    # ==========================================================================
    # 5. 판정
    # ==========================================================================
    if [ "$access_configured" = true ]; then
        status="양호"
        diagnosis_result="GOOD"
        inspection_summary="FTP 접근 제어가 설정되어 있습니다. (${details})"
    else
        status="취약"
        diagnosis_result="VULNERABLE"
        inspection_summary="FTP 접근 제어가 설정되지 않았습니다."
    fi

    command_result="${details:-FTP 접근 제어 미설정}"
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
