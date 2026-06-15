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
# @Platform    : HP-UX
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

    # ftpusers 파일 위치 확인 (HP-UX ftpd는 /etc/ftpd/ftpusers 우선)
    local ftpusers_files=("/etc/ftpd/ftpusers" "/etc/ftpusers" "/etc/vsftpd/ftpusers" "/etc/pure-ftpd/ftpusers" "/etc/proftpd/ftpusers")
    local found_file=""
    local file_content=""

    for file in "${ftpusers_files[@]}"; do
        if [ -f "$file" ]; then
            found_file="$file"
            file_content=$(cat "$file" 2>/dev/null || echo "")
            break
        fi
    done || true

    command_executed="ls -la /etc/ftpd/ftpusers /etc/ftpusers /etc/vsftpd/ftpusers /etc/pure-ftpd/ftpusers 2>/dev/null"

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
    elif [ -n "$proftpd_conf" ] && [ "$proftpd_use_ftpusers" = "off" ]; then
        # UseFtpUsers off이면 ftpusers 파일이 적용되지 않음 → 다른 차단 수단(RootLogin off) 필요
        if [ "$proftpd_root_login" = "off" ]; then
            diagnosis_result="GOOD"
            status="양호"
            inspection_summary="proftpd UseFtpUsers off 설정이나 RootLogin off로 root FTP 접속이 차단되어 있습니다(${proftpd_conf})."
        else
            diagnosis_result="VULNERABLE"
            status="취약"
            inspection_summary="proftpd UseFtpUsers off 설정으로 ftpusers 파일이 적용되지 않으며, RootLogin 차단 설정이 없습니다(${proftpd_conf})."
        fi
        command_result="[Command: grep -iE 'RootLogin|UseFtpUsers' ${proftpd_conf}]${newline}RootLogin: ${proftpd_root_login:-미설정}, UseFtpUsers: ${proftpd_use_ftpusers}"
    elif [ -z "$found_file" ]; then
        # ftpusers 파일이 존재하지 않음
        # FTP 서비스가 동작 중인지 확인 (HP-UX: inetd.conf 우선, init.d 보조)
        local ftp_found=false
        if grep -qE '^ftp[[:space:]]' /etc/inetd.conf 2>/dev/null; then
            ftp_found=true
        else
            for ftpsvc in vsftpd proftpd pure-ftpd ftpd; do
                if [ -f /sbin/init.d/"$ftpsvc" ]; then
                    ftp_found=true
                    break
                fi
            done
        fi

        if [ "$ftp_found" = true ]; then
            diagnosis_result="VULNERABLE"
            status="취약"
            inspection_summary="ftpusers 파일이 존재하지 않습니다. FTP 서비스가 실행 중이므로 ftpusers 파일을 생성하고 시스템 계정을 등록하세요."
            local ftpusers_check=$(ls -la /etc/ftpusers /etc/vsftpd/ftpusers /etc/pure-ftpd/ftpusers 2>/dev/null || echo "No ftpusers files found")
            command_result="${ftpusers_check}"
        else
            diagnosis_result="N/A"
            status="N/A"
            inspection_summary="FTP 서비스가 설치되어 있지 않습니다."
            local ftp_service_check=$(ls /sbin/init.d/vsftpd /sbin/init.d/proftpd 2>/dev/null; ls /etc/ftpusers 2>/dev/null || echo "FTP service not installed")
            command_result="${ftp_service_check}"
        fi
    elif [ -z "$file_content" ] || [ $(echo "$file_content" | grep -v "^#" | grep -v "^$" | wc -l) -eq 0 ]; then
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="ftpusers 파일이 비어있습니다(${found_file}). 시스템 계정(root, bin, daemon 등)을 등록하세요."
        local empty_check=$(cat "${found_file}" 2>/dev/null | head -5 || echo "File empty or comments only")
        command_result="${empty_check}"
    else
        # 파일이 존재하고 내용이 있는 경우
        # U-57 판정 기준: root 계정의 FTP 접속 차단 여부 (root 등록 여부만 확인)
        local accounts_check=$(cat "${found_file}" 2>/dev/null | grep -v '^#' | grep -v '^$' | head -10 || echo "No registered accounts")
        command_result="File: ${found_file}\n${accounts_check}"

        # ftpusers 파일에 root 계정이 등록되어 있는지 확인 (주석 처리된 #root는 차단으로 보지 않음)
        if echo "$file_content" | grep -qx "root"; then
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
