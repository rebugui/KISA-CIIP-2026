#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-04-20
# ============================================================================
# [점검 항목 상세]
# @ID          : U-57
# @Category    : UNIX > 2. 서비스 관리
# @Platform    : RedHat
# @Severity    : 중
# @Title       : Ftpusers 파일 설정
# @Description : ftpusers 파일에 root 계정 등 시스템 계정 접근 제한 설정 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/metadata_parser.sh"

ITEM_ID="U-57"
ITEM_NAME="Ftpusers 파일 설정"
SEVERITY="중"

GUIDELINE_PURPOSE="root 계정의 FTP 직접 접속을 제한하여 root 비밀번호 정보 노출을 방지하기 위함"
GUIDELINE_THREAT="FTP 서비스에 root 계정으로 접근할 경우, 데이터가 평문으로 전송되어 비인가자가 스니핑을 통해 관리자 계정 및 중요 정보를 외부로 유출할 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="root 계정 접속을 차단한 경우"
GUIDELINE_CRITERIA_BAD="root 계정 접속을 허용한 경우"
GUIDELINE_REMEDIATION="FTP 서비스를 사용하지 않는 경우 서비스 중지 및 비활성화 설정 FTP 서비스 사용 시 root 계정으로 직접 접속할 수 없도록 설정"

diagnose() {
    local status="양호"
    diagnosis_result="GOOD"
    local inspection_summary="ftpusers 파일 설정이 적절합니다."
    local command_result=""
    local command_executed="cat /etc/ftpusers 2>/dev/null; cat /etc/vsftpd/ftpusers 2>/dev/null"

    # ==========================================================================
    # 1. FTP 서비스 설치 여부 확인 (효력 있는 파일 선택을 위해 먼저 수행)
    # ==========================================================================
    local ftp_installed=false
    local vsftpd_detected=false
    if rpm -qa 2>/dev/null | grep -q "vsftpd\|proftpd\|pure-ftpd"; then
        ftp_installed=true
    fi
    if rpm -qa 2>/dev/null | grep -q "vsftpd"; then
        vsftpd_detected=true
    fi

    # ==========================================================================
    # 2. ProFTPD 설정 확인 (UseFtpUsers / RootLogin)
    # ==========================================================================
    local proftpd_conf=""
    local proftpd_root_login=""
    local proftpd_use_ftpusers=""
    for pconf in /etc/proftpd.conf /etc/proftpd/proftpd.conf; do
        if [ -f "$pconf" ]; then
            proftpd_conf="$pconf"
            proftpd_root_login=$(grep -iE '^[[:space:]]*RootLogin[[:space:]]' "$pconf" 2>/dev/null | tail -1 | awk '{print tolower($2)}') || true
            proftpd_use_ftpusers=$(grep -iE '^[[:space:]]*UseFtpUsers[[:space:]]' "$pconf" 2>/dev/null | tail -1 | awk '{print tolower($2)}') || true
            break
        fi
    done || true

    if [ -n "$proftpd_conf" ] && { [ "$proftpd_root_login" = "on" ] || [ "$proftpd_use_ftpusers" = "off" ]; }; then
        if [ "$proftpd_root_login" = "on" ]; then
            # RootLogin on이면 ftpusers와 무관하게 root 접속 허용 상태
            status="취약"
            diagnosis_result="VULNERABLE"
            inspection_summary="proftpd 설정에서 RootLogin on으로 root FTP 접속이 허용되어 있습니다(${proftpd_conf})."
        elif [ "$proftpd_root_login" = "off" ]; then
            status="양호"
            diagnosis_result="GOOD"
            inspection_summary="proftpd UseFtpUsers off 설정이나 RootLogin off로 root FTP 접속이 차단되어 있습니다(${proftpd_conf})."
        else
            # UseFtpUsers off + RootLogin 미설정 → ftpusers 미적용, 다른 차단 수단 없음
            status="취약"
            diagnosis_result="VULNERABLE"
            inspection_summary="proftpd UseFtpUsers off 설정으로 ftpusers 파일이 적용되지 않으며, RootLogin 차단 설정이 없습니다(${proftpd_conf})."
        fi
        command_result="proftpd_conf: ${proftpd_conf}, RootLogin: ${proftpd_root_login:-unset}, UseFtpUsers: ${proftpd_use_ftpusers:-on(default)}"
        command_executed="grep -iE 'RootLogin|UseFtpUsers' ${proftpd_conf}"

        save_dual_result \
            "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" \
            "${inspection_summary}" "${command_result}" "${command_executed}" \
            "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" \
            "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"

        verify_result_saved "${ITEM_ID}"
        return 0
    fi

    # ==========================================================================
    # 2-b. ProFTPD RootLogin off 단독 차단 처리 (UseFtpUsers 미설정/on 포함)
    #      RootLogin off는 ftpusers 적용 여부와 무관하게 root FTP 접속을 차단함
    # ==========================================================================
    if [ -n "$proftpd_conf" ] && [ "$proftpd_root_login" = "off" ]; then
        status="양호"
        diagnosis_result="GOOD"
        inspection_summary="proftpd RootLogin off 설정으로 root FTP 접속이 차단되어 있습니다(${proftpd_conf})."
        command_result="proftpd_conf: ${proftpd_conf}, RootLogin: off, UseFtpUsers: ${proftpd_use_ftpusers:-on(default)}"
        command_executed="grep -iE 'RootLogin|UseFtpUsers' ${proftpd_conf}"

        save_dual_result \
            "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" \
            "${inspection_summary}" "${command_result}" "${command_executed}" \
            "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" \
            "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"

        verify_result_saved "${ITEM_ID}"
        return 0
    fi

    # ==========================================================================
    # 3. ftpusers 파일 위치 확인 (vsftpd 사용 시 PAM 적용 파일을 우선 선택)
    # ==========================================================================
    local ftpusers_files=("/etc/ftpusers" "/etc/vsftpd/ftpusers" "/etc/proftpd/ftpusers")
    if [ "$vsftpd_detected" = true ]; then
        ftpusers_files=("/etc/vsftpd/ftpusers" "/etc/vsftpd/user_list" "/etc/ftpusers" "/etc/proftpd/ftpusers")
    fi
    local found_file=""
    local file_content=""

    for file in "${ftpusers_files[@]}"; do
        if [ -f "$file" ]; then
            found_file="$file"
            file_content=$(cat "$file" 2>/dev/null || echo "")
            break
        fi
    done || true

    # ==========================================================================
    # 4. ftpusers 파일 부재 시 처리
    # ==========================================================================
    if [ -z "$found_file" ]; then
        if [ "$ftp_installed" = true ]; then
            status="취약"
            diagnosis_result="VULNERABLE"
            inspection_summary="ftpusers 파일이 존재하지 않습니다. FTP 서비스가 설치되어 있으므로 ftpusers 파일을 생성해야 합니다."
            command_result="ftpusers 파일 없음 (검색 경로: ${ftpusers_files[*]})"
        else
            status="양호"
            diagnosis_result="GOOD"
            inspection_summary="FTP 서비스가 설치되어 있지 않습니다."
            command_result="FTP: [not installed], ftpusers: [not found]"
        fi

        save_dual_result \
            "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" \
            "${inspection_summary}" "${command_result}" "${command_executed}" \
            "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" \
            "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"

        verify_result_saved "${ITEM_ID}"
        return 0
    fi

    # ==========================================================================
    # 5. 파일 내용 분석
    # ==========================================================================
    local active_lines=$(echo "$file_content" | grep -v "^#" | grep -v "^$" || true)

    # vsftpd user_list 의미 판별: userlist_deny=NO이면 허용 목록(allow-list)으로 동작
    local list_semantics="deny"
    if [ "$found_file" = "/etc/vsftpd/user_list" ]; then
        local vsftpd_conf=""
        local vc
        for vc in /etc/vsftpd/vsftpd.conf /etc/vsftpd.conf; do
            if [ -f "$vc" ]; then
                vsftpd_conf="$vc"
                break
            fi
        done
        local userlist_deny=""
        if [ -n "$vsftpd_conf" ]; then
            userlist_deny=$(grep -iE '^userlist_deny=' "$vsftpd_conf" 2>/dev/null | tail -1 | cut -d= -f2 | tr -d '[:space:]' | tr '[:lower:]' '[:upper:]') || true
        fi
        [ "$userlist_deny" = "NO" ] && list_semantics="allow"
    fi

    if [ "$list_semantics" = "allow" ]; then
        # 허용 목록: root가 목록에 있으면 root FTP 접속이 허용됨 → 취약
        if [ -n "$active_lines" ] && echo "$active_lines" | grep -qx "root"; then
            status="취약"
            diagnosis_result="VULNERABLE"
            inspection_summary="vsftpd userlist_deny=NO 환경에서 user_list에 root가 등록되어 root FTP 접속이 허용됩니다 (${found_file})."
            command_result="File: ${found_file} (allow-list, userlist_deny=NO), root: [ALLOWED]"
        else
            status="양호"
            diagnosis_result="GOOD"
            inspection_summary="vsftpd userlist_deny=NO 환경에서 user_list에 root가 등록되어 있지 않아 root FTP 접속이 차단됩니다 (${found_file})."
            command_result="File: ${found_file} (allow-list, userlist_deny=NO), root: [blocked]"
        fi
    elif [ -z "$active_lines" ]; then
        status="취약"
        diagnosis_result="VULNERABLE"
        inspection_summary="ftpusers 파일이 비어있습니다 (${found_file}). root 등 시스템 계정을 등록해야 합니다."
        command_result="File: ${found_file}, Content: [empty]"
    else
        # root 계정이 등록되어 있는지 확인 (핵심 검사)
        if echo "$active_lines" | grep -qx "root"; then
            status="양호"
            diagnosis_result="GOOD"
            local total_accounts=$(echo "$active_lines" | wc -l)
            inspection_summary="ftpusers 파일에 root 계정이 등록되어 있습니다 (${found_file}, ${total_accounts}개 계정)."
            command_result="File: ${found_file}, Accounts: ${total_accounts}, root: [blocked]"
        else
            status="취약"
            diagnosis_result="VULNERABLE"
            inspection_summary="ftpusers 파일에 root 계정이 등록되어 있지 않습니다 (${found_file})."
            command_result="File: ${found_file}, root: [NOT blocked]"
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
