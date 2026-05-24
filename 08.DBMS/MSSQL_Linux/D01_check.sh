#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : D-01
# @Category    : DBMS (Database Management System)
# @Platform    : MSSQL (Running on Linux/Unix)
# @Severity    : 상 (High)
# @Title       : 기본계정의 비밀번호, 정책 등을 변경하여 사용
# @Description : DBMS 초기 설치 시 생성되는 기본 계정(sa 등)의 기본 비밀번호
#                변경 여부 및 기본 권한 정책의 적절성을 점검합니다.
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../../lib"

# 라이브러리 로드
source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/command_validator.sh"
source "${LIB_DIR}/timeout_handler.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/db_connection_helpers.sh"

# Initialize MSSQL connection variables
init_mssql_vars


ITEM_ID="D-01"
ITEM_NAME="기본 계정의 비밀번호, 정책 등을 변경하여 사용"
SEVERITY="상"

GUIDELINE_PURPOSE="DBMS 기본 계정의 초기 비밀번호 및 권한 정책 변경 사용 유무를 점검하여 비인가자의 초기 비밀번호 대입 공격을 차단하고 있는지 확인하기 위함"
GUIDELINE_THREAT="DBMS 기본 계정 초기 비밀번호 및 권한 정책을 변경하지 않을 경우 비인가자가 인터넷 통해 DBMS 기본 계정의 초기 비밀번호를 획득하여 초기 비밀번호를 그대로 사용하고 있는 DB에 접근하여 기본 계정에 부여된 권한의 취약점을 이용하여 DB 정보를 유출할 수 있는 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="기본 계정의 초기 비밀번호를 변경하거나 잠금 설정한 경우"
GUIDELINE_CRITERIA_BAD="기본 계정의 초기 비밀번호를 변경하지 않거나 잠금 설정을 하지 않은 경우"
GUIDELINE_REMEDIATION="기본(관리자)계정의 초기 비밀번호 및 권한 정책 변경"

diagnose() {
    echo "진단 항목: ${ITEM_ID} - ${ITEM_NAME}"

    # FR-022: Check required tools
    if ! check_mssql_tools; then
        handle_missing_tools "mssql" "${ITEM_ID}" "${ITEM_NAME}" \
            "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" \
            "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
        return 0
    fi


    local diagnosis_result="GOOD"
    local status="양호"
    local inspection_summary=""
    local command_result=""
    local command_executed=""
    local vulnerabilities_found=0

    # MSSQL 서비스 확인 (Windows PowerShell 사용)
    if command -v powershell.exe &> /dev/null; then
        local mssql_running=$(powershell.exe -Command "Get-Service | Where-Object {\$_.Name -like '*SQL*' -and \$_.Status -eq 'Running'} | Measure-Object | Select-Object -ExpandProperty Count" 2>/dev/null || echo "0")

        if [ "$mssql_running" = "0" ]; then
            diagnosis_result="GOOD"
            status="양호"
            inspection_summary="MSSQL 서비스 미실행"
            save_dual_result "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" "${inspection_summary}" "${command_result}" "${command_executed}" "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
            verify_result_saved "${ITEM_ID}"
            return 0
        fi
    else
        inspection_summary="MSSQL 진단 스크립트는 Windows 환경에서 실행해야 합니다"
        diagnosis_result="MANUAL"
        status="수동진단"
        save_dual_result "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" "${inspection_summary}" "${command_result}" "${command_executed}" "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
        verify_result_saved "${ITEM_ID}"
        return 0
    fi

    # sqlcmd 명령 확인
    if ! command -v sqlcmd &> /dev/null; then
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="sqlcmd 도구를 찾을 수 없습니다. SQL Server Command Line Tools 설치 필요"
        save_dual_result "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" "${inspection_summary}" "${command_result}" "${command_executed}" "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
        verify_result_saved "${ITEM_ID}"
        return 0
    fi

    # 1. 게스트 사용자 계정 확인
    local guest_query="SELECT name, type_desc FROM sys.server_principals WHERE name LIKE '%guest%' AND is_disabled = 0;"
    command_executed="sqlcmd -S localhost -E -Q \"${guest_query}\""
    command_result=$(sqlcmd -S localhost -E -Q "${guest_query}" -h -1 -W 2>/dev/null || echo "")

    if [ -n "$command_result" ] && echo "$command_result" | grep -q -v "Rows affected"; then
        ((vulnerabilities_found++)) || true
        inspection_summary+="취약: 활성화된 게스트 사용자 계정 존재 - ${command_result}; "
    fi

    # 2. 기본 로그인 확인 (sa, sysadmin 등)
    local default_login_query="SELECT name, is_disabled FROM sys.server_principals WHERE type = 'S' AND name IN ('sa', 'admin', 'administrator') AND is_disabled = 0;"
    command_executed="sqlcmd -S localhost -E -Q \"${default_login_query}\""
    command_result=$(sqlcmd -S localhost -E -Q "${default_login_query}" -h -1 -W 2>/dev/null || echo "")

    if [ -n "$command_result" ] && echo "$command_result" | grep -q -v "Rows affected"; then
        # sa 계정은 비밀번호가 설정되어 있는지 확인 필요
        local sa_check=$(echo "$command_result" | grep -i "sa" || echo "")
        if [ -n "$sa_check" ]; then
            inspection_summary+="경고: sa 계정이 활성화됨 (비밀번호 설정 확인 필요); "
        fi
    fi

    # 3. 빈 비밀번호를 가진 로그인 확인 (MSSQL 2012+)
    local empty_pwd_query="SELECT name FROM sys.sql_logins WHERE is_disabled = 0 AND PWDCOMPARE('', password_hash) = 1;"
    command_executed="sqlcmd -S localhost -E -Q \"${empty_pwd_query}\""
    command_result=$(sqlcmd -S localhost -E -Q "${empty_pwd_query}" -h -1 -W 2>/dev/null || echo "")

    if [ -n "$command_result" ] && echo "$command_result" | grep -q -v "Rows affected"; then
        ((vulnerabilities_found++)) || true
        inspection_summary+="취약: 빈 비밀번호를 가진 계정 존재 - ${command_result}; "
    fi

    # 결과 판정
    if [ $vulnerabilities_found -gt 0 ]; then
        diagnosis_result="VULNERABLE"
        status="취약"
        if [ -z "$inspection_summary" ]; then
            inspection_summary="DBMS 기본 계정 보안 취약 발견"
        fi
    else
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="기본 계정이 적절히 관리됨"
    fi

    command_executed="sqlcmd -S localhost -E -Q \"MSSQL 기본 계정 점검 쿼리\""

    save_dual_result "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" "${inspection_summary}" "${command_result}" "${command_executed}" "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
    verify_result_saved "${ITEM_ID}"

    return 0
}

main() {
    diagnose
}

if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi
