#!/bin/bash

# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : D-06
# @Category    : DBMS (Database Management System)
# @Platform    : MSSQL_Linux
# @Severity    : 중
# @Title       : DB 사용자 계정을 개별적으로 부여하여 사용
# @Description : 불필요한 계정 관리 및 권한 제어를 통한 보안 강화
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

ITEM_ID="D-06"
ITEM_NAME="DB 사용자 계정을 개별적으로 부여하여 사용"
SEVERITY="중"

GUIDELINE_PURPOSE="사용자별 별도 DBMS 계정을 사용하여 DB에 접근하는지 점검하여 DB 계정 공유 사용으로 발생할 수 있는 로그 감사 추적 문제를 대비하고자함"
GUIDELINE_THREAT="DB 계정을 공유하여 사용할 경우 비인가자의 DB 접근 발생 시 계정 공유 사용으로 인해 로그 감사 추적의 어려움이 발생할 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="사용자별 계정을 사용하고 있는 경우"
GUIDELINE_CRITERIA_BAD="공용 계정을 사용하고 있는 경우"
GUIDELINE_REMEDIATION="사용자별 계정 생성 및 권한 부여"

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
    local shared_accounts_found=0

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
        inspection_summary+="SELECT name, type_desc, create_date FROM sys.server_principals WHERE type IN ('S', 'U') AND name NOT IN ('sa', '##MS_Agent##', '##MS_PolicyEventProcessingLogin##') ORDER BY name;"
        save_dual_result "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" "${inspection_summary}" "${command_result}" "${command_executed}" "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
        verify_result_saved "${ITEM_ID}"
        return 0
    fi

    # 1. 의심스러운 공용 계정 확인 (일반적으로 공용으로 사용되는 패턴)
    local shared_account_query="SELECT name, type_desc, create_date, modify_date FROM sys.server_principals WHERE type = 'S' AND (name LIKE '%shared%' OR name LIKE '%common%' OR name LIKE '%public%' OR name LIKE '%test%' OR name LIKE '%demo%') AND is_disabled = 0 AND name NOT IN ('sa', 'guest', 'PUBLIC');"
    command_executed="sqlcmd -S localhost -E -Q \"${shared_account_query}\""
    command_result=$(sqlcmd -S localhost -E -Q "${shared_account_query}" -h -1 -W 2>/dev/null || echo "")

    if [ -n "$command_result" ] && echo "$command_result" | grep -q -v "Rows affected"; then
        ((shared_accounts_found++)) || true
        inspection_summary="의심스러운 공용 계정 발견 - ${command_result}; "
    fi

    # 2. 다중 사용자 연결 확인 (동일한 계정에서 여러 세션)
    local multi_session_query="SELECT login_name, COUNT(*) as session_count FROM sys.dm_exec_sessions WHERE is_user_process = 1 GROUP BY login_name HAVING COUNT(*) > 5 ORDER BY session_count DESC;"
    command_executed="sqlcmd -S localhost -E -Q \"${multi_session_query}\""
    command_result=$(sqlcmd -S localhost -E -Q "${multi_session_query}" -h -1 -W 2>/dev/null || echo "")

    if [ -n "$command_result" ] && echo "$command_result" | grep -q -v "Rows affected"; then
        inspection_summary+="다중 세션 사용 계정 - ${command_result}; "
    fi

    # 결과 판정
    if [ $shared_accounts_found -gt 0 ]; then
        diagnosis_result="VULNERABLE"
        status="취약"
        if [ -z "$inspection_summary" ]; then
            inspection_summary="공용 계정 사용 확인 필요"
        fi
    else
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="공용 계정 자동 점검 완료\n\n"
        inspection_summary+="추가 검증 필요:\n"
        inspection_summary+="1. 응용 프로그램별, 사용자별 계정 분리 여부 확인\n"
        inspection_summary+="2. 공용 계정 사용 현황 수동 점검\n\n"
        inspection_summary+="검증 쿼리:\n"
        inspection_summary+="- SELECT name, type_desc FROM sys.server_principals WHERE type IN ('S', 'U') ORDER BY name;\n"
        inspection_summary+="- SELECT login_name, COUNT(*) FROM sys.dm_exec_sessions WHERE is_user_process = 1 GROUP BY login_name;\n\n"
        inspection_summary+="조치 방법:\n"
        inspection_summary+="- 사용자별, 응용 프로그램별 개별 계정 생성\n"
        inspection_summary+="- 최소 권한 원칙에 따라 권한 부여\n"
        inspection_summary+="- 불필요한 공용 계정 삭제"
    fi

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
