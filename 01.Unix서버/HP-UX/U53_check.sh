#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : U-53
# @Category    : Unix Server
# @Platform    : HP-UX
# @Severity    : 하
# @Title       : FTP 서비스 정보 노출 제한
# @Description : FTP 배너 정보 제거 확인
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


ITEM_ID="U-53"
ITEM_NAME="FTP 서비스 정보 노출 제한"
SEVERITY="하"

# 가이드라인 정보
GUIDELINE_PURPOSE="FTP 서비스 접속 배너를 통한 불필요한 정보 노출을 방지하기 위함"
GUIDELINE_THREAT="서비스 접속 배너가 차단되지 않을 경우, 비인가자가 FTP 접속 시도 시 노출되는 접속 배너 정보를 수집하여 악의적인 공격에 이용할 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="FTP 접속 배너에 노출되는 정보가 없는 경우"
GUIDELINE_CRITERIA_BAD="FTP 접속 배너에 노출되는 정보가 있는 경우"
GUIDELINE_REMEDIATION="FTP 서비스를 사용하지 않는 경우 서비스 중지 및 비활성화 설정 FTP 서비스 사용 시 FTP 설정 파일을 통해 접속 배너 설정 ※ 접속 배너에 서비스 이름이나 버전 정보를 노출하지 않는 것을 권고"

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
    # FTP 배너 정보 제거 확인

    local ftp_banner_issue=false
    local banner_details=""
    local ftp_config_files=()
    local manual_needed=false
    local manual_details=""
    local ident_quote_re="[\"']([^\"']*)[\"']"

    # FTP 설정 파일 검색
    if [ -f /etc/proftpd/proftpd.conf ]; then
        ftp_config_files+=("/etc/proftpd/proftpd.conf")
    fi
    if [ -f /etc/vsftpd.conf ]; then
        ftp_config_files+=("/etc/vsftpd.conf")
    fi
    if [ -f /etc/vsftpd/vsftpd.conf ]; then
        ftp_config_files+=("/etc/vsftpd/vsftpd.conf")
    fi
    if [ -f /etc/pure-ftpd/conf/DisplayLogin ]; then
        ftp_config_files+=("/etc/pure-ftpd/conf/DisplayLogin")
    fi
    if [ -f /etc/pure-ftpd/conf/FortunesFile ]; then
        ftp_config_files+=("/etc/pure-ftpd/conf/FortunesFile")
    fi

    # 각 설정 파일에서 배너 정보 확인
    # (빈 배열 확장은 bash 4.3 이하 set -u에서 unbound 오류 → ${arr[@]+...} 가드 필수)
    for config_file in ${ftp_config_files[@]+"${ftp_config_files[@]}"}; do
        local banner_value=""
        local banner_text=""
        local custom_banner=""

        # vsftpd 배너 설정 확인
        if [[ "$config_file" == *"vsftpd"* ]]; then
            if [ ! -r "$config_file" ]; then
                manual_needed=true
                manual_details="${manual_details}${config_file}: 설정 파일 읽기 불가, "
            else
                banner_value=$(grep -E "^[[:space:]]*(ftpd_banner|banner_file)" "$config_file" 2>/dev/null | grep -v "^[[:space:]]*#" | head -1 || true)
                if [ -z "$banner_value" ]; then
                    # 배너 지시자 미설정 시 기본 배너가 vsFTPd 이름/버전 정보를 노출함
                    ftp_banner_issue=true
                    banner_details="${banner_details}${config_file}: ftpd_banner/banner_file 미설정(기본 배너 노출), "
                elif [[ "$banner_value" == *"banner_file"* ]]; then
                    # banner_file 지정 시 참조 파일 내용을 읽어 서비스 이름/버전/호스트명 노출 여부 검사
                    local banner_file_path="${banner_value#*=}"
                    banner_file_path="$(echo "$banner_file_path" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
                    if [ -z "$banner_file_path" ] || [ ! -f "$banner_file_path" ]; then
                        manual_needed=true
                        manual_details="${manual_details}${config_file}: banner_file(${banner_file_path:-경로 미지정}) 파일 없음, "
                    elif [ ! -r "$banner_file_path" ]; then
                        manual_needed=true
                        manual_details="${manual_details}${config_file}: banner_file(${banner_file_path}) 읽기 불가, "
                    else
                        local banner_file_content
                        banner_file_content=$(cat "$banner_file_path" 2>/dev/null || echo "")
                        local expose_pattern="version|vsftpd|proftpd|wu-ftpd|[0-9]+\.[0-9]"
                        local host_name os_name
                        host_name="$(hostname 2>/dev/null || true)"
                        os_name="$(uname -s 2>/dev/null || true)"
                        [ -n "$host_name" ] && expose_pattern="${expose_pattern}|$host_name"
                        [ -n "$os_name" ] && expose_pattern="${expose_pattern}|$os_name"
                        if echo "$banner_file_content" | grep -qiE "$expose_pattern"; then
                            ftp_banner_issue=true
                            banner_details="${banner_details}${config_file}: banner_file(${banner_file_path})에 서비스/버전/호스트명 정보 노출, "
                        fi
                    fi
                else
                    # ftpd_banner 값에 서비스 이름/버전 정보가 포함되어 있는지 확인
                    banner_text="${banner_value#*=}"
                    if echo "$banner_text" | grep -qiE "version|vsftpd|proftpd|wu-ftpd|[0-9]+\.[0-9]"; then
                        ftp_banner_issue=true
                        banner_details="${banner_details}${config_file}: ${banner_value}, "
                    fi
                fi
            fi
        fi

        # proftpd 배너 설정 확인
        if [[ "$config_file" == *"proftpd"* ]]; then
            if [ ! -r "$config_file" ]; then
                manual_needed=true
                manual_details="${manual_details}${config_file}: 설정 파일 읽기 불가, "
            else
                banner_value=$(grep -E "^[[:space:]]*ServerIdent" "$config_file" 2>/dev/null | grep -v "^[[:space:]]*#" | head -1 || true)
                if [ -z "$banner_value" ]; then
                    # ServerIdent 미설정 시 기본 배너가 ProFTPD 이름/버전 정보를 노출함
                    ftp_banner_issue=true
                    banner_details="${banner_details}${config_file}: ServerIdent 미설정(기본 배너 노출), "
                elif echo "$banner_value" | grep -qiE "^[[:space:]]*ServerIdent[[:space:]]+off"; then
                    : # ServerIdent off → 배너 정보 미노출(양호)
                else
                    # ServerIdent on: 따옴표 안 사용자 배너 텍스트만 검사
                    custom_banner=""
                    if [[ "$banner_value" =~ $ident_quote_re ]]; then
                        custom_banner="${BASH_REMATCH[1]}"
                    fi
                    if [ -z "$custom_banner" ]; then
                        ftp_banner_issue=true
                        banner_details="${banner_details}${config_file}: ${banner_value} (사용자 배너 미지정), "
                    elif echo "$custom_banner" | grep -qiE "version|proftpd|vsftpd|wu-ftpd|[0-9]+\.[0-9]"; then
                        ftp_banner_issue=true
                        banner_details="${banner_details}${config_file}: ${banner_value}, "
                    fi
                fi
            fi
        fi

        # pure-ftpd 배너 설정 확인
        if [[ "$config_file" == *"pure-ftpd"* ]]; then
            banner_value=$(cat "$config_file" 2>/dev/null)
            if [ -n "$banner_value" ]; then
                if echo "$banner_value" | grep -qiE "version|Welcome|FTP"; then
                    ftp_banner_issue=true
                    banner_details="${banner_details}${config_file}: 배너 설정됨, "
                fi
            fi
        fi
    done || true

    # 기본 배너 메시지 파일 확인
    if [ -f /etc/ftpwelcome ]; then
        local ftpwelcome_content=$(cat /etc/ftpwelcome 2>/dev/null)
        if [ -n "$ftpwelcome_content" ]; then
            ftp_banner_issue=true
            banner_details="${banner_details}/etc/ftpwelcome 파일 존재, "
        fi
    fi

    if [ "$ftp_banner_issue" = true ]; then
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="FTP 배너에 버전/시스템 정보 노출: ${banner_details%, }"
        command_result="${banner_details%, }"
        command_executed="grep -E 'ftpd_banner|ServerIdent' /etc/{vsftpd,vsftpd/vsftpd,proftpd/proftpd}.conf 2>/dev/null"
    elif [ "$manual_needed" = true ]; then
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="FTP 배너 설정 수동 확인 필요: ${manual_details%, }"
        command_result="${manual_details%, }"
        command_executed="grep -E 'ftpd_banner|ServerIdent' /etc/{vsftpd,vsftpd/vsftpd,proftpd/proftpd}.conf 2>/dev/null"
    else
        # FTP 서비스가 설치되지 않았거나 배너가 적절하게 설정됨
        # (배열 길이 검사는 set -u에서도 안전)
        local ftp_installed=false
        if [ ${#ftp_config_files[@]} -gt 0 ]; then
            ftp_installed=true
        fi

        if [ "$ftp_installed" = true ]; then
            diagnosis_result="GOOD"
            status="양호"
            inspection_summary="FTP 배너 정보가 제거되거나 적절하게 설정됨"
            local banner_check=$(grep -E 'ftpd_banner|ServerIdent' /etc/vsftpd.conf /etc/proftpd/proftpd.conf 2>/dev/null | head -5 || echo "No banner settings found")
            command_result="${banner_check}"
            command_executed="grep -E 'ftpd_banner|ServerIdent' /etc/{vsftpd,vsftpd/vsftpd,proftpd/proftpd}.conf 2>/dev/null"
        else
            local ftp_check=$(ls /etc/vsftpd.conf /etc/proftpd/proftpd.conf 2>/dev/null || echo "FTP config files not found")
            local inetd_ftp=$(grep -E "^[[:space:]]*ftp[[:space:]]" /etc/inetd.conf 2>/dev/null | head -1 || true)
            if [ -n "$inetd_ftp" ]; then
                # HP-UX 기본 ftpd(inetd) 사용 중: ftpaccess 배너 설정은 자동 판독 불가 → 수동진단
                diagnosis_result="MANUAL"
                status="수동진단"
                inspection_summary="HP-UX 기본 ftpd 서비스 사용 중(inetd): FTP 접속 배너(ftpaccess) 설정 수동 확인 필요"
                command_result="[Command: grep ftp /etc/inetd.conf]${newline}${inetd_ftp}"
                command_executed="grep -E '^ftp' /etc/inetd.conf"
            else
                diagnosis_result="GOOD"
                status="양호"
                inspection_summary="FTP 서비스가 설치되지 않음"
                command_result="${ftp_check}"
                command_executed="ls /etc/{vsftpd.conf,proftpd/proftpd.conf} 2>/dev/null"
            fi
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
