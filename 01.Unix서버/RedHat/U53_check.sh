#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-04-20
# ============================================================================
# [점검 항목 상세]
# @ID          : U-53
# @Category    : UNIX > 3. FTP 서비스 관리
# @Platform    : RedHat
# @Severity    : 하
# @Title       : FTP 서비스 정보 노출 제한
# @Description : FTP 배너 정보 제거 확인
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/metadata_parser.sh"

ITEM_ID="U-53"
ITEM_NAME="FTP 서비스 정보 노출 제한"
SEVERITY="하"

# 가이드라인 정보
GUIDELINE_PURPOSE="FTP 서비스 접속 배너를 통한 불필요한 정보 노출을 방지하기 위함"
GUIDELINE_THREAT="서비스 접속 배너가 차단되지 않을 경우, 비인가자가 FTP 접속 시도 시 노출되는 접속 배너 정보를 수집하여 악의적인 공격에 이용할 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="FTP 접속 배너에 노출되는 정보가 없는 경우"
GUIDELINE_CRITERIA_BAD="FTP 접속 배너에 노출되는 정보가 있는 경우"
GUIDELINE_REMEDIATION="FTP 서비스를 사용하지 않는 경우 서비스 중지 및 비활성화 설정 FTP 서비스 사용 시 FTP 설정 파일을 통해 접속 배너 설정 ※ 접속 배너에 서비스 이름이나 버전 정보를 노출하지 않는 것을 권고"

diagnose() {
    diagnosis_result="unknown"
    local status="미진단"
    local inspection_summary=""
    local command_result=""
    local command_executed=""
    local newline=$'\n'

    local ftp_banner_issue=false
    local banner_details=""
    local ftp_config_files=()
    local raw_output=""

    # FTP 설정 파일 검색 (RedHat 표준 경로)
    if [ -f /etc/vsftpd/vsftpd.conf ]; then
        ftp_config_files+=("/etc/vsftpd/vsftpd.conf")
    fi
    if [ -f /etc/vsftpd.conf ]; then
        ftp_config_files+=("/etc/vsftpd.conf")
    fi
    if [ -f /etc/proftpd.conf ]; then
        ftp_config_files+=("/etc/proftpd.conf")
    fi
    if [ -f /etc/proftpd/proftpd.conf ]; then
        ftp_config_files+=("/etc/proftpd/proftpd.conf")
    fi

    # 각 설정 파일에서 배너 정보 확인
    for config_file in "${ftp_config_files[@]}"; do
        local banner_value=""

        # Capture raw grep output for each config file
        local grep_output=$(grep -E "ftpd_banner|ServerIdent|banner_file" "$config_file" 2>/dev/null | grep -v "^#" || echo "")
        if [ -n "$grep_output" ]; then
            raw_output="${raw_output}[${config_file}]${newline}${grep_output}${newline}"
        fi

        # vsftpd 배너 설정 확인
        if [[ "$config_file" == *"vsftpd"* ]]; then
            banner_value=$(grep -E "^[\s]*ftpd_banner|^[\s]*banner_file" "$config_file" 2>/dev/null | grep -v "^#" | head -1)
            if [ -n "$banner_value" ]; then
                # 배너에 버전 정보가 포함되어 있는지 확인
                if echo "$banner_value" | grep -qiE "version|vsftpd|proftpd"; then
                    ftp_banner_issue=true
                    banner_details="${banner_details}${config_file}: ${banner_value}, "
                fi
            fi
        fi

        # proftpd 배너 설정 확인
        if [[ "$config_file" == *"proftpd"* ]]; then
            banner_value=$(grep -E "^[\s]*ServerIdent" "$config_file" 2>/dev/null | grep -v "^#" | head -1)
            if [ -n "$banner_value" ]; then
                if echo "$banner_value" | grep -qiE "On|PROFTPD"; then
                    ftp_banner_issue=true
                    banner_details="${banner_details}${config_file}: ${banner_value}, "
                fi
            fi
        fi
    done || true

    if [ "$ftp_banner_issue" = true ]; then
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="FTP 배너에 버전/시스템 정보 노출: ${banner_details%, }"
        command_result="${raw_output}"
        command_executed="grep -E 'ftpd_banner|ServerIdent' /etc/vsftpd/vsftpd.conf /etc/vsftpd.conf /etc/proftpd/proftpd.conf 2>/dev/null"
    else
        # FTP 서비스가 설치되지 않았거나 배너가 적절하게 설정됨
        local ftp_installed=false
        for config_file in "${ftp_config_files[@]}"; do
            ftp_installed=true
            break
        done || true

        if [ "$ftp_installed" = true ]; then
            diagnosis_result="GOOD"
            status="양호"
            inspection_summary="FTP 배너 정보가 제거되거나 적절하게 설정됨"
            command_result="${raw_output:-No banner settings found}"
            command_executed="grep -E 'ftpd_banner|ServerIdent' /etc/vsftpd/vsftpd.conf /etc/vsftpd.conf /etc/proftpd/proftpd.conf 2>/dev/null"
        else
            diagnosis_result="GOOD"
            status="양호"
            inspection_summary="FTP 서비스가 설치되지 않음"
            command_result="FTP: [not installed]"
            command_executed="ls /etc/vsftpd/vsftpd.conf /etc/vsftpd.conf /etc/proftpd/proftpd.conf 2>/dev/null"
        fi
    fi

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
