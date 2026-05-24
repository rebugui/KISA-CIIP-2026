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
    # 1. ftpusers 파일 위치 확인
    # ==========================================================================
    local ftpusers_files=("/etc/ftpusers" "/etc/vsftpd/ftpusers" "/etc/proftpd/ftpusers")
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
    # 2. FTP 서비스 설치 여부 확인
    # ==========================================================================
    local ftp_installed=false
    if rpm -qa 2>/dev/null | grep -q "vsftpd\|proftpd\|pure-ftpd"; then
        ftp_installed=true
    fi

    # ==========================================================================
    # 3. ftpusers 파일 부재 시 처리
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
    # 4. 파일 내용 분석
    # ==========================================================================
    local active_lines=$(echo "$file_content" | grep -v "^#" | grep -v "^$" || true)

    if [ -z "$active_lines" ]; then
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
