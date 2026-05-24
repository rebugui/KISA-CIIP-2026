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

    # 최종 판정
    if [ -z "$found_file" ]; then
        # ftpusers 파일이 존재하지 않음
        # FTP 서비스가 설치되어 있는지 확인
        if systemctl list-unit-files | grep -qE "vsftpd|proftpd|pure-ftpd|ftpd.service" 2>/dev/null; then
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
        # 주요 시스템 계정이 등록되어 있는지 확인
        local missing_accounts=()
        local registered_accounts=""

        for account in "${system_accounts[@]}"; do
            # /etc/passwd에 계정이 존재하는지 먼저 확인
            if grep -q "^${account}:" /etc/passwd 2>/dev/null; then
                # ftpusers 파일에 등록되어 있는지 확인
                if echo "$file_content" | grep -qx "${account}"; then
                    registered_accounts="${registered_accounts}${account} "
                else
                    missing_accounts+=("$account")
                fi
            fi
        done || true

        command_result="File: ${found_file}${newline}Registered accounts: ${registered_accounts:-[none]}"

        if [ ${#missing_accounts[@]} -eq 0 ]; then
            diagnosis_result="GOOD"
            status="양호"
            inspection_summary="ftpusers 파일에 주요 시스템 계정이 적절하게 등록되어 있습니다(${found_file})."
        else
            diagnosis_result="VULNERABLE"
            status="취약"
            local missing_list=""
            for acc in "${missing_accounts[@]}"; do
                missing_list="${missing_list}${acc}, "
            done || true
            inspection_summary="ftpusers 파일에 일부 시스템 계정이 미등록되어 있습니다(${found_file}): ${missing_list%, }"
            command_result="${command_result}${newline}Unregistered accounts: ${missing_list%, }"
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
