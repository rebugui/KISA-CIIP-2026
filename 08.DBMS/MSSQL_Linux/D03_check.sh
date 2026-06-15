#!/bin/bash

# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : D-03
# @Category    : DBMS (Database Management System)
# @Platform    : MSSQL_Linux
# @Severity    : 상
# @Title       : 비밀번호 사용 기간 및 복잡 도를 기관의 정책에 맞도록 설정
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

ITEM_ID="D-03"
ITEM_NAME="비밀번호 사용 기간 및 복잡 도를 기관의 정책에 맞도록 설정"
SEVERITY="상"

GUIDELINE_PURPOSE="비밀번호 사용 기간 및 복잡 도 설정 유무를 점검하여 비인가자의 비밀번호 추측 공격(무차별 대입 공격, 사전 대입 공격 등)에 대한 대비가 되어 있는지 확인하기 위함"
GUIDELINE_THREAT="비밀번호 사용 기간 및 복잡 도 설정이 되어 있지 않으면 비인가자가 비밀번호 추측 공격을 통해 획득한 계정의 비밀번호를 이용하여 DB에 접근할 수 있는 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="기관 정책에 맞게 비밀번호 사용 기간 및 복잡 도 설정이 적용된 경우"
GUIDELINE_CRITERIA_BAD="기관 정책에 맞게 비밀번호 사용 기간 및 복잡 도 설정이 적용되지 않은 경우"
GUIDELINE_REMEDIATION="기관 정책에 맞게 비밀번호 사용 기간 및 복잡 도 정책 설정"

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

    if command -v powershell.exe &> /dev/null; then
        local mssql_running=$(powershell.exe -Command "Get-Service | Where-Object {\$_.Name -like '*SQL*' -and \$_.Status -eq 'Running'} | Measure-Object | Select-Object -ExpandProperty Count" 2>/dev/null || echo "0")
        if [ "$mssql_running" = "0" ]; then
            diagnosis_result="MANUAL"
            status="수동진단"
            inspection_summary="MSSQL 서비스 미실행으로 비밀번호 정책을 자동 점검할 수 없습니다. 서비스 시작 후 비밀번호 사용 기간 및 복잡도 정책을 수동으로 확인하세요."
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

    if ! command -v sqlcmd &> /dev/null; then
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="sqlcmd 도구를 찾을 수 없습니다. SQL Server Command Line Tools 설치 필요"
        save_dual_result "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" "${inspection_summary}" "${command_result}" "${command_executed}" "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
        verify_result_saved "${ITEM_ID}"
        return 0
    fi

    local policy_query="SELECT name, is_policy_checked, is_expiration_checked FROM sys.sql_logins WHERE type = 'S' AND name NOT LIKE '##%';"
    command_executed="sqlcmd -S localhost -E -Q \"${policy_query}\""
    command_result=$(sqlcmd -S localhost -E -Q "${policy_query}" -h -1 -W 2>/dev/null || echo "")

    if [ -n "$command_result" ]; then
        # sqlcmd -W -h -1 emits whitespace-separated columns (no -s separator set),
        # so the two flag columns are the last two fields: $(NF-1)=is_policy_checked,
        # $NF=is_expiration_checked. Match only rows whose flag field is exactly 0
        # (digit-only guard avoids matching the trailing "(N rows affected)" line).
        local no_policy=$(echo "$command_result" | grep -vi "rows affected" | grep -v "^\s*$" | awk 'NF>=3 && $(NF-1) ~ /^[0-9]+$/ && $(NF-1)==0 {print}' || echo "")
        if [ -n "$no_policy" ]; then
            ((vulnerabilities_found++)) || true
            inspection_summary+="취약: 비밀번호 정책 비활성화된 계정 존재; "
        fi
        local no_expiration=$(echo "$command_result" | grep -vi "rows affected" | grep -v "^\s*$" | awk 'NF>=3 && $NF ~ /^[0-9]+$/ && $NF==0 {print}' || echo "")
        if [ -n "$no_expiration" ]; then
            ((vulnerabilities_found++)) || true
            inspection_summary+="취약: 비밀번호 만료 정책 비활성화된 계정 존재; "
        fi
    fi

    if [ $vulnerabilities_found -gt 0 ]; then
        diagnosis_result="VULNERABLE"
        status="취약"
    else
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="비밀번호 정책이 적절히 설정됨"
    fi

    command_executed="sqlcmd -S localhost -E -Q \"비밀번호 정책 점검\""

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
