#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : U-56
# @Category    : Unix Server
# @Platform    : Debian
# @Severity    : 하
# @Title       : FTP 서비스 접근 제어 설정
# @Description : /etc/ftpusers 설정 확인
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


ITEM_ID="U-56"
ITEM_NAME="FTP 서비스 접근 제어 설정"
SEVERITY="하"

# 가이드라인 정보
GUIDELINE_PURPOSE="접근 권한이 없는 비인가자의 접근을 통제하기 위함"
GUIDELINE_THREAT="FTP 서비스의 접근 제한 설정이 적절하지 않을 경우, 인증 절차 없이 비인가자가 디렉터리나 파일에 접근할 수 있어 중요 파일 변조 및 유출을 시도할 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="특정 IP 주소 또는 호스트에서만 FTP 서버에 접속할 수 있도록 접근 제어 설정을 적용한 경우"
GUIDELINE_CRITERIA_BAD="FTP 서버에 접근 제어 설정을 적용하지 않은 경우"
GUIDELINE_REMEDIATION="FTP 서비스를 사용하지 않는 경우 서비스 중지 및 비활성화 설정 FTP 서비스 사용 시 접근 제어 설정"

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
    # FTP 서비스 접근 제어 설정 확인

    local ftp_installed=false
    local access_configured=false
    local access_details=""
    local config_files=""
    local raw_output=""

    # Capture raw output from FTP config files
    raw_output=$(cat /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf /etc/proftpd/proftpd.conf /etc/ftpusers /etc/ftpdusers 2>/dev/null || echo "No FTP config files found")

    # FTP 설정 파일 확인
    if [ -f /etc/vsftpd.conf ] || [ -f /etc/vsftpd/vsftpd.conf ]; then
        ftp_installed=true
        local vsftpd_conf="/etc/vsftpd.conf"
        [ ! -f "$vsftpd_conf" ] && vsftpd_conf="/etc/vsftpd/vsftpd.conf"

        # vsftpd 접근 제어 확인
        # 1) /etc/ftpusers 또는 /etc/vsftpd.ftpusers 확인 (주석/공백 라인 제외)
        if [ -f /etc/ftpusers ]; then
            local blocked_users=$(grep -vE '^[[:space:]]*#|^[[:space:]]*$' /etc/ftpusers 2>/dev/null | wc -l)
            if [ "$blocked_users" -gt 0 ]; then
                access_configured=true
                access_details="/etc/ftpusers에 ${blocked_users}개 차단된 사용자"
                config_files="${config_files}/etc/ftpusers "
            fi
        fi

        # 2) vsftpd.conf에서 userlist_enable, userlist_file 확인
        # userlist_enable=YES만으로는 접근 제어로 인정하지 않고, 실제 리스트
        # 파일에 유효 항목(주석/공백 제외)이 있어야 설정된 것으로 판정
        if grep -q "^userlist_enable=YES" "$vsftpd_conf" 2>/dev/null; then
            local userlist_file=$(grep "^userlist_file" "$vsftpd_conf" 2>/dev/null | awk -F= '{print $2}' | head -1 | tr -d '[:space:]')
            if [ -z "$userlist_file" ]; then
                # vsftpd 기본 리스트 파일 경로
                if [ -f /etc/vsftpd.user_list ]; then
                    userlist_file="/etc/vsftpd.user_list"
                elif [ -f /etc/vsftpd/user_list ]; then
                    userlist_file="/etc/vsftpd/user_list"
                fi
            fi
            if [ -n "$userlist_file" ] && [ -f "$userlist_file" ]; then
                local userlist_count=$(grep -vcE '^[[:space:]]*#|^[[:space:]]*$' "$userlist_file" 2>/dev/null || true)
                if [ "$userlist_count" -gt 0 ] 2>/dev/null; then
                    access_configured=true
                    access_details="${access_details}, ${userlist_file}에 ${userlist_count}개 사용자"
                    config_files="${config_files}${vsftpd_conf} "
                fi
            fi
        fi
    fi

    if [ -f /etc/proftpd/proftpd.conf ]; then
        ftp_installed=true
        # proftpd 접근 제어 확인
        if grep -qE "^[\s]*<Limit.*LOGIN>" /etc/proftpd/proftpd.conf 2>/dev/null; then
            access_configured=true
            access_details="${access_details}, proftpd <Limit LOGIN> 설정됨"
        fi
        config_files="${config_files}/etc/proftpd/proftpd.conf "
    fi

    # /etc/ftpusers 또는 /etc/ftpdusers 확인 (일반적인 FTP 차단 파일)
    for users_file in /etc/ftpusers /etc/ftpdusers; do
        if [ -f "$users_file" ]; then
            ftp_installed=true
            local user_count=$(grep -vE '^[[:space:]]*#|^[[:space:]]*$' "$users_file" 2>/dev/null | wc -l)
            if [ "$user_count" -gt 0 ]; then
                access_configured=true
                access_details="${access_details}, ${users_file}에 ${user_count}개 차단 사용자"
                config_files="${config_files}${users_file} "
            fi
        fi
    done || true

    # 실행 중인 FTP 데몬 확인 (설정 파일이 없어도 서비스가 동작할 수 있음)
    local ftp_running=false
    local running_detail=""
    if systemctl is-active vsftpd >/dev/null 2>&1 || systemctl is-active proftpd >/dev/null 2>&1 || systemctl is-active pure-ftpd >/dev/null 2>&1; then
        ftp_running=true
        running_detail="systemctl: vsftpd/proftpd/pure-ftpd active"
    elif ps -ef 2>/dev/null | grep -v grep | grep -qE '(vsftpd|proftpd|pure-ftpd|in\.ftpd)'; then
        ftp_running=true
        running_detail="ps에서 FTP 데몬 프로세스 확인"
    fi
    if [ "$ftp_running" = true ]; then
        ftp_installed=true
    fi

    if [ "$ftp_installed" = false ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="FTP 서비스가 설치되지 않음"
        command_result="FTP: [not installed]"
        command_executed="ls /etc/{vsftpd*,proftpd*,ftpusers} 2>/dev/null"
    elif [ "$access_configured" = true ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="FTP 접근 제어가 설정됨: ${access_details#, }"
        command_result="${raw_output}"
        command_executed="cat ${config_files} 2>/dev/null | grep -E 'userlist|ftpusers'"
    else
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="FTP 접근 제어가 설정되지 않음 (root 등 관리자 계정 접근 가능)"
        command_result="${raw_output}"
        if [ -n "$running_detail" ]; then
            command_result="${command_result}${newline}[FTP daemon: ${running_detail}]"
        fi
        command_executed="cat /etc/{vsftpd*,proftpd*,ftpusers,ftpdusers} 2>/dev/null"
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
