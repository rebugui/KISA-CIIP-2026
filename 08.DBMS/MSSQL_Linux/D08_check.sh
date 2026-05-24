#!/bin/bash

# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : D-08
# @Category    : DBMS (Database Management System)
# @Platform    : MSSQL
# @Severity    : 상
# @Title       : 안전한암호화알고리즘사용
# @Description : 비밀번호 정책 및 설정 관리를 통한 무단 접근 방지
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/command_validator.sh"
source "${LIB_DIR}/timeout_handler.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/db_connection_helpers.sh"

# Initialize MSSQL connection variables
init_mssql_vars

ITEM_ID="D-08"
ITEM_NAME="안전한 암호화 알고리즘 사용"
SEVERITY="상"

GUIDELINE_PURPOSE="안전한 해시 알고리즘 사용으로 데이터의 기밀성 및 무결성을 보장하고, 사용자 인증을 강화하기 위함"
GUIDELINE_THREAT="SHA-1이나 MD5와 같은 오래된 알고리즘 사용 시 공격자의 무차별 대입 공격 등으로 비밀번호 유추가 가능하며, 데이터 변조 및 유출의 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="해시 알고리즘 SHA-256 이상의 암호화 알고리즘을 사용하고 있는 경우"
GUIDELINE_CRITERIA_BAD="해시 알고리즘 SHA-256 미만의 암호화 알고리즘을 사용하고 있는 경우"
GUIDELINE_REMEDIATION="SHA-256 이상의 암호화 알고리즘 적용"

diagnose() {
    echo "진단 항목: ${ITEM_ID} - ${ITEM_NAME}"

    # FR-022: Check required tools
    if ! check_mssql_tools; then
        handle_missing_tools "mssql" "${ITEM_ID}" "${ITEM_NAME}" \
            "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" \
            "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
        return 0
    fi


    local diagnosis_result="MANUAL"
    local status="수동진단"
    local inspection_summary=""
    local command_result=""
    local command_executed=""

    # MSSQL 서비스 확인
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
        inspection_summary="sqlcmd 도구를 찾을 수 없습니다. SQL Server Command Line Tools 설치 필요\n\n"
        inspection_summary+="검증 방법:\n"
        inspection_summary+="SQL Server Management Studio에서 다음 쿼리 실행:\n"
        inspection_summary+="SELECT name, password_hash FROM sys.sql_logins;"
        save_dual_result "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" "${inspection_summary}" "${command_result}" "${command_executed}" "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
        verify_result_saved "${ITEM_ID}"
        return 0
    fi

    # 비밀번호 해시 알고리즘 확인
    local hash_query="SELECT name, password_hash FROM sys.sql_logins WHERE name NOT IN ('sa', '##MS_Agent##');"
    command_executed="sqlcmd -S localhost -E -Q \"${hash_query}\""
    command_result=$(sqlcmd -S localhost -E -Q "${hash_query}" -h -1 -W 2>/dev/null || echo "")

    inspection_summary="MSSQL 암호화 알고리즘 확인\n\n"
    inspection_summary="암호화 알고리즘 정보:\n"
    inspection_summary+="- MSSQL 2012 이상: SHA-512 (32bit Salt 적용) - 양호\n"
    inspection_summary+="- MSSQL 2008: SHA-512 - 양호\n"
    inspection_summary+="- MSSQL 2005 이전: SHA-1 - 취약\n\n"
    inspection_summary+="검증 방법:\n"
    inspection_summary+="1. SQL Server 버전 확인:\n"
    inspection_summary+="   SELECT SERVERPROPERTY('productversion') AS ProductVersion;\n\n"
    inspection_summary+="2. 비밀번호 해시 확인:\n"
    inspection_summary+="   SELECT name, password_hash FROM sys.sql_logins;\n\n"
    inspection_summary+="참고: MSSQL 2012 이상에서는 기본적으로 SHA-512를 사용하므로 추가 설정 불필요"

    if [ -n "$command_result" ] && echo "$command_result" | grep -q -v "Rows affected"; then
        inspection_summary+="\n\n검증 결과:\n${command_result}"
    fi

    diagnosis_result="MANUAL"
    status="수동진단"

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
