#!/bin/bash

# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : D-02
# @Category    : DBMS (Database Management System)
# @Platform    : MSSQL_Linux
# @Severity    : 상
# @Title       : 데이터베이스의 불필요 계정을 제거하거나, 잠금 설정 후 사용
# @Description : 불필요한 계정 관리 및 권한 제어를 통한 보안 강화
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

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


ITEM_ID="D-02"
ITEM_NAME="데이터베이스의 불필요 계정을 제거하거나, 잠금 설정 후 사용"
SEVERITY="상"

GUIDELINE_PURPOSE="불필요한 계정 존재 유무를 점검하여 불필요한 계정 정보(비밀번호)의 유출 시 발생할 수 있는 비인가자의 DB 접근에 대비되어 있는지 확인하기 위함"
GUIDELINE_THREAT="DB 관리나 운용에 사용하지 않는 불필요한 계정이 존재할 경우, 비인가자가 불필요한 계정을 이용하여 DB에 접근하여 데이터를 열람, 삭제, 수정할 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="계정 정보를 확인하여 불필요한 계정이 없는 경우"
GUIDELINE_CRITERIA_BAD="인가되지 않은 계정, 퇴직자 계정, 테스트 계정 등 불필요한 계정이 존재하는 경우"
GUIDELINE_REMEDIATION="계정별 용도를 파악한 후 불필요한 계정 삭제"

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

    # MSSQL 서비스 확인
    if command -v powershell.exe &> /dev/null; then
        local mssql_running=$(powershell.exe -Command "Get-Service | Where-Object {\$_.Name -like '*SQL*' -and \$_.Status -eq 'Running'} | Measure-Object | Select-Object -ExpandProperty Count" 2>/dev/null || echo "0")

        if [ "$mssql_running" = "0" ]; then
            diagnosis_result="MANUAL"
            status="수동진단"
            inspection_summary="MSSQL 서비스 미실행으로 불필요 계정 존재 여부를 자동 점검할 수 없습니다. 서비스 시작 후 불필요한 계정의 제거 또는 잠금 설정 여부를 수동으로 확인하세요."
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

    # 불필요 계정(비시스템 프린시펄) 열거 - D-02 기준은 불필요한 계정(테스트/퇴직자/데모 등)의 존재 여부이므로
    # 빈 비밀번호가 아닌 비시스템 프린시펄을 실제로 열거한다 (Windows 헬퍼 D-02 쿼리와 동일 기준).
    local principal_query="SET NOCOUNT ON; SELECT name FROM sys.server_principals WHERE type IN ('S','U','G') AND name NOT LIKE '##%' AND name NOT LIKE 'NT SERVICE\\%' ESCAPE '\\' AND name NOT LIKE 'NT AUTHORITY\\%' ESCAPE '\\' AND name NOT LIKE 'BUILTIN\\%' ESCAPE '\\' AND name NOT IN ('sa','public');"
    command_executed="sqlcmd -S localhost -E -Q \"${principal_query}\""
    command_result=$(sqlcmd -S localhost -E -Q "${principal_query}" -h -1 -W 2>/dev/null || echo "")

    # 결과 분석
    local principal_list
    principal_list=$(echo "$command_result" | grep -v "Rows affected" | grep -v "^[[:space:]]*$")

    if echo "$principal_list" | grep -Eiq '^[[:space:]]*(guest|test|demo|scott|adams|clark|sample)'; then
        # 명백한 불필요/데모/테스트 계정명이 존재하면 취약
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="불필요한 것으로 의심되는 계정(guest/test/demo/scott 등) 발견: $(echo "$principal_list" | head -5 | tr '\n' ', ') - criteria_bad(인가되지 않은/퇴직자/테스트 계정)에 따라 제거 또는 잠금 설정 확인 필요"
    elif [ -n "$principal_list" ]; then
        # 비시스템 프린시펄이 존재하나 각 계정의 필요성을 정적으로 증명할 수 없으므로 수동진단
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="비시스템 계정이 존재합니다. 각 계정의 용도를 수동으로 확인하여 인가되지 않은/퇴직자/테스트 등 불필요한 계정이 없는지 점검하세요: $(echo "$principal_list" | head -10 | tr '\n' ', ')"
    else
        # 반환된 비시스템 계정이 없으나 불필요 계정 부재를 정적으로 증명할 수 없으므로 수동진단
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="반환된 비시스템 계정이 없으나 불필요 계정 부재를 자동으로 증명할 수 없습니다. 인가되지 않은/퇴직자/테스트 계정이 남아 있지 않은지 수동으로 확인하세요."
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
