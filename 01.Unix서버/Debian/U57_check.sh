#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : U-57
# @Category    : Unix Server
# @Platform    : Debian
# @Severity    : 중
# @Title       : Ftpusers 파일 설정
# @Description : ftpusers 파일에 불필요한 계정 제한 설정 여부 확인
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


ITEM_ID="U-57"
ITEM_NAME="Ftpusers 파일 설정"
SEVERITY="중"

# 가이드라인 정보
GUIDELINE_PURPOSE="root 계정의 FTP 직접 접속을 제한하여 root 비밀번호 정보 노출을 방지하기 위함"
GUIDELINE_THREAT="FTP 서비스에 root 계정으로 접근할 경우, 데이터가 평문으로 전송되어 비인가자가 스니핑을 통해 관리자 계정 및 중요 정보를 외부로 유출할 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="root 계정 접속을 차단한 경우"
GUIDELINE_CRITERIA_BAD="root 계정 접속을 허용한 경우"
GUIDELINE_REMEDIATION="FTP 서비스를 사용하지 않는 경우 서비스 중지 및 비활성화 설정 FTP 서비스 사용 시 root 계정으로 직접 접속할 수 없도록 설정"

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
    # ftpusers 파일 설정 확인

    # 시스템 계정 목록 (FTP 접속이 제한되어야 할 계정)
    local system_accounts=("root" "bin" "daemon" "adm" "lp" "sync" "shutdown" "halt" "mail" "news" "uucp" "operator" "games" "gopher" "ftp" "nobody" "sys")

    # ftpusers 파일 위치 확인 (다양한 경로 지원)
    local ftpusers_files=("/etc/ftpusers" "/etc/vsftpd/ftpusers" "/etc/pure-ftpd/ftpusers" "/etc/proftpd/ftpusers")
    local found_file=""
    local file_content=""

    for file in "${ftpusers_files[@]}"; do
        if [ -f "$file" ]; then
            found_file="$file"
            file_content=$(cat "$file" 2>/dev/null || echo "")
            break
        fi
    done || true

    command_executed="ls -la /etc/ftpusers /etc/vsftpd/ftpusers /etc/pure-ftpd/ftpusers 2>/dev/null"

    # vsftpd 설정 파일 확인 (userlist_deny=NO allow-list 모드 감지용)
    local vsftpd_conf_found=""
    for vconf in /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf; do
        if [ -f "$vconf" ]; then
            vsftpd_conf_found="$vconf"
            break
        fi
    done || true

    # ProFTPD 설정 확인 (UseFtpUsers / RootLogin)
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

    # 최종 판정
    if [ -n "$proftpd_conf" ] && [ "$proftpd_root_login" = "on" ]; then
        # proftpd RootLogin on이면 ftpusers와 무관하게 root 접속 허용 상태
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="proftpd 설정에서 RootLogin on으로 root FTP 접속이 허용되어 있습니다(${proftpd_conf})."
        command_result="[Command: grep -iE 'RootLogin|UseFtpUsers' ${proftpd_conf}]${newline}RootLogin: ${proftpd_root_login}, UseFtpUsers: ${proftpd_use_ftpusers:-on(기본값)}"
    elif [ -n "$proftpd_conf" ] && [ "$proftpd_root_login" = "off" ]; then
        # proftpd RootLogin off는 ftpusers/UseFtpUsers와 무관하게 root FTP 접속을 차단함
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="proftpd RootLogin off 설정으로 root FTP 접속이 차단되어 있습니다(${proftpd_conf})."
        command_result="[Command: grep -iE 'RootLogin|UseFtpUsers' ${proftpd_conf}]${newline}RootLogin: ${proftpd_root_login}, UseFtpUsers: ${proftpd_use_ftpusers:-미설정}"
    elif [ -n "$proftpd_conf" ] && [ "$proftpd_use_ftpusers" = "off" ]; then
        # UseFtpUsers off이면 ftpusers 파일이 적용되지 않음 → RootLogin 차단 설정이 없으면 취약
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="proftpd UseFtpUsers off 설정으로 ftpusers 파일이 적용되지 않으며, RootLogin 차단 설정이 없습니다(${proftpd_conf})."
        command_result="[Command: grep -iE 'RootLogin|UseFtpUsers' ${proftpd_conf}]${newline}RootLogin: ${proftpd_root_login:-미설정}, UseFtpUsers: ${proftpd_use_ftpusers}"
    elif [ -n "$vsftpd_conf_found" ] && grep -qiE '^[[:space:]]*userlist_deny[[:space:]]*=[[:space:]]*NO' "$vsftpd_conf_found" 2>/dev/null; then
        # vsftpd allow-list 모드(userlist_deny=NO): user_list가 허용 목록으로 동작하여
        # ftpusers 기반 자동 판정이 유효하지 않으므로 수동 진단
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="vsftpd가 allow-list 모드(userlist_deny=NO)로 동작 중입니다(${vsftpd_conf_found}). user_list 및 PAM 설정에서 root 접속 차단 여부를 수동으로 확인하세요."
        command_result="[Command: grep -i userlist ${vsftpd_conf_found}]${newline}$(grep -i userlist "$vsftpd_conf_found" 2>/dev/null || echo '확인 불가')"
    elif [ -z "$found_file" ]; then
        # ftpusers 파일이 존재하지 않음
        # FTP 서비스가 설치/실행되어 있는지 확인 (systemd 외 ps/inetd 환경 포함)
        local ftp_present=false
        if systemctl list-unit-files 2>/dev/null | grep -qE "vsftpd|proftpd|pure-ftpd|ftpd.service"; then
            ftp_present=true
        elif ps -ef 2>/dev/null | grep -v grep | grep -qE '(vsftpd|proftpd|pure-ftpd|in\.ftpd)'; then
            ftp_present=true
        elif [ -f /etc/inetd.conf ] && grep -vE '^[[:space:]]*#' /etc/inetd.conf 2>/dev/null | grep -qw "ftp"; then
            ftp_present=true
        fi
        if [ "$ftp_present" = true ]; then
            diagnosis_result="VULNERABLE"
            status="취약"
            inspection_summary="ftpusers 파일이 존재하지 않습니다. FTP 서비스가 실행 중이므로 ftpusers 파일을 생성하고 시스템 계정을 등록하세요."
            command_result="[FILE NOT FOUND: ftpusers] (searched paths: ${ftpusers_files[*]})"
        else
            diagnosis_result="GOOD"
            status="양호"
            inspection_summary="FTP 서비스가 설치되어 있지 않음 (ftpusers 불필요)"
            command_result="FTP Service: [not installed], ftpusers: [FILE NOT FOUND]"
        fi
    elif [ -z "$file_content" ] || [ $(echo "$file_content" | grep -v "^#" | grep -v "^$" | wc -l) -eq 0 ]; then
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="ftpusers 파일이 비어있습니다(${found_file}). 시스템 계정(root, bin, daemon 등)을 등록하세요."
        command_result="File: ${found_file}, Content: [empty] or only comments"
    else
        # 파일이 존재하고 내용이 있는 경우
        # 가이드라인 기준은 root 계정 접속 차단 여부이므로 root 등록 여부로 판정
        # (주석/공백 라인을 제외한 활성 라인에 root가 있으면 차단된 것으로 본다)
        local active_lines=""
        active_lines=$(echo "$file_content" | grep -v "^[[:space:]]*#" | grep -v "^[[:space:]]*$") || true

        # 참고용: 등록된 주요 시스템 계정 목록 구성(판정에는 영향 없음)
        local registered_accounts=""
        for account in "${system_accounts[@]}"; do
            # /etc/passwd에 계정이 존재하는지 먼저 확인
            if grep -q "^${account}:" /etc/passwd 2>/dev/null; then
                # ftpusers 파일에 등록되어 있는지 확인
                if echo "$active_lines" | grep -qx "${account}"; then
                    registered_accounts="${registered_accounts}${account} "
                fi
            fi
        done || true

        command_result="File: ${found_file}${newline}Registered accounts: ${registered_accounts:-[none]}"

        if echo "$active_lines" | grep -qx "root"; then
            diagnosis_result="GOOD"
            status="양호"
            inspection_summary="ftpusers 파일에 root 계정이 등록되어 root FTP 접속이 차단되어 있습니다(${found_file})."
            command_result="${command_result}${newline}root: [blocked]"
        else
            diagnosis_result="VULNERABLE"
            status="취약"
            inspection_summary="ftpusers 파일에 root 계정이 등록되어 있지 않아 root FTP 접속이 허용됩니다(${found_file})."
            command_result="${command_result}${newline}root: [NOT blocked]"
        fi
    fi

    # 결과 생성
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
