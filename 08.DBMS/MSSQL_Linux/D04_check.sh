#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : # D-04
# @Category    : DBMS (Database Management System)
# @Platform    : MSSQL
# @Severity    : # 상
# @Title       : # 데이터베이스관리자권한을꼭필요한계정및그룹에대해서만허용
# @Description : # 관리자 권한이 필요한 계정과 그룹에만 관리자 권한을 부여하였는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

set -euo pipefail

# 스크립트 디렉토리 설정set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../../lib"
# 필수 라이브러리 로드
source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/command_validator.sh"
source "${LIB_DIR}/timeout_handler.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/db_connection_helpers.sh"
source "${LIB_DIR}/metadata_parser.sh"


# Initialize MSSQL connection variables
init_mssql_vars

ITEM_ID="D-04"
ITEM_NAME="데이터베이스 관리자 권한을 꼭 필요한 계정 및 그룹에 대해서만 허용"
SEVERITY="상"

GUIDELINE_PURPOSE="관리자 권한이 필요한 계정과 그룹에만 관리자 권한을 부여하였는지 점검하여 관리자 권한의 남용을 방지하여 계정 유출로 인한 비인가자의 DB 접근 가능성을 최소화하고자함"
GUIDELINE_THREAT="관리자 권한이 필요한 계정 및 그룹에만 관리자 권한을 부여하지 않으면 관리자 권한이 부여된 계정이 비인가자에게 유출될 경우 DB에 접근할 수 있는 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="관리자 권한이 필요한 계정 및 그룹에만 관리자 권한이 부여된 경우"
GUIDELINE_CRITERIA_BAD="관리자 권한이 필요 없는 계정 및 그룹에 관리자 권한이 부여된 경우"
GUIDELINE_REMEDIATION="관리자 권한이 필요한 계정 및 그룹에만 관리자 권한 부여"

# MSSQL 연결 정보 초기화
DB_HOST="${DB_HOST:-localhost}"
DB_PORT="${DB_PORT:-1433}"
DB_USER="${DB_USER:-sa}"
DB_PASSWORD="${DB_PASSWORD:-}"

# MSSQL 연결 프롬프트 (FR-018)
prompt_mssql_connection() {
    if [ -z "${DB_PASSWORD}" ]; then
        echo "[INFO] MSSQL 연결 정보 입력이 필요합니다."
        read -p "MSSQL Host [${DB_HOST}]: " input_host
        DB_HOST="${input_host:-$DB_HOST}"

        read -p "MSSQL Port [${DB_PORT}]: " input_port
        DB_PORT="${input_port:-$DB_PORT}"

        read -p "MSSQL Username [${DB_USER}]: " input_user
        DB_USER="${input_user:-$DB_USER}"

        read -s -p "MSSQL Password: " input_pass
        echo ""
        DB_PASSWORD="${input_pass}"
    fi

    # 3회 재시도 로직
    local retry_count=0
    local max_retries=3

    while [ $retry_count -lt $max_retries ]; do
        # sqlcmd 연결 테스트
        if sqlcmd -S "${DB_HOST},${DB_PORT}" -U "${DB_USER}" -P "${DB_PASSWORD}" -Q "SELECT 1;" -h -1 &>/dev/null; then
            echo "[INFO] MSSQL 연결 성공"
            export DB_HOST DB_PORT DB_USER DB_PASSWORD
            return 0
        fi

        ((retry_count++)) || true
        if [ $retry_count -lt $max_retries ]; then
            echo "[WARN] MSSQL 연결 실패 (${retry_count}/${max_retries}). 5초 후 재시도..."
            sleep 5
        fi
    done

    return 1
}

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
    local vulnerabilities_found=0

    # sqlcmd 존재 확인
    if ! command -v sqlcmd >/dev/null; then
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="MSSQL sqlcmd 도구가 설치되지 않았습니다. 수동으로 확인이 필요합니다."
        command_result="sqlcmd command not found"
        command_executed="command -v sqlcmd"
        save_dual_result "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" "${inspection_summary}" "${command_result}" "${command_executed}" "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
        verify_result_saved "${ITEM_ID}"
        return 0
    fi

    # MSSQL 연결 시도 (FR-018)
    if ! prompt_mssql_connection; then
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="MSSQL 연결에 실패했습니다. 3회 재시도 후 실패. 수동으로 확인이 필요합니다."
        command_result="Connection failed after 3 retries"
        command_executed="sqlcmd -S ${DB_HOST},${DB_PORT} -U ${DB_USER} -P ***"
        save_dual_result "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" "${inspection_summary}" "${command_result}" "${command_executed}" "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
        verify_result_saved "${ITEM_ID}"
        return 0
    fi

    # 1. sysadmin role members 확인 (MSSQL 2019+)
    local sysadmin_query="EXEC sp_helpsrvrolemember 'sysadmin';"
    command_executed="sqlcmd -S ${DB_HOST},${DB_PORT} -U ${DB_USER} -P *** -Q \"${sysadmin_query}\""
    command_result=$(sqlcmd -S "${DB_HOST},${DB_PORT}" -U "${DB_USER}" -P "${DB_PASSWORD}" -Q "${sysadmin_query}" -h -1 -W 2>/dev/null | grep -v "^$" || echo "")

    echo "[DEBUG] sysadmin members result:\n${command_result}"

    # sysadmin role members 수 확인 (sa는 제외)
    local sysadmin_count=$(echo "$command_result" | grep -v "^\s*sa\s*" | grep -v "^$" | wc -l)

    # 2. server_principals에서 sysadmin 권한 확인
    local sysadmin_check_query="SELECT name, type_desc FROM sys.server_principals WHERE IS_SRVROLEMEMBER('sysadmin', name) = 1 AND name NOT IN ('sa', '##MS_Agent', '##MS_PolicyEventProcessor', '##MS_PolicySqlExecution', '##MS_PolicyStoredProcUpdates', 'NT AUTHORITY\SYSTEM', 'NT SERVICE\MSSQLSERVER', 'NT SERVICE\SQLSERVERAGENT');"
    command_executed="${sysadmin_check_query}"
    command_result=$(sqlcmd -S "${DB_HOST},${DB_PORT}" -U "${DB_USER}" -P "${DB_PASSWORD}" -Q "${sysadmin_check_query}" -h -1 -W 2>/dev/null | grep -v "^$" || echo "")

    echo "[DEBUG] sysadmin check result:\n${command_result}"

    # 3. excessive admin 확인 (sa 이외에 sysadmin 권한을 가진 계정)
    if [ -n "$command_result" ] && echo "$command_result" | grep -q -v "^\s*$"; then
        ((vulnerabilities_found++)) || true
        inspection_summary+="취약: sa 이외에 sysadmin 권한을 가진 계정이 존재합니다 - ${command_result}; "
    fi

    # 4. securityadmin role members 확인
    local securityadmin_query="EXEC sp_helpsrvrolemember 'securityadmin';"
    command_executed="${securityadmin_query}"
    command_result=$(sqlcmd -S "${DB_HOST},${DB_PORT}" -U "${DB_USER}" -P "${DB_PASSWORD}" -Q "${securityadmin_query}" -h -1 -W 2>/dev/null | grep -v "^$" || echo "")

    local securityadmin_count=$(echo "$command_result" | grep -v "^\s*sa\s*" | grep -v "^$" | wc -l)

    echo "[INFO] sysadmin members (excluding sa): ${sysadmin_count}"
    echo "[INFO] securityadmin members (excluding sa): ${securityadmin_count}"

    # 결과 판정
    if [ $vulnerabilities_found -gt 0 ]; then
        diagnosis_result="VULNERABLE"
        status="취약"
        if [ -z "$inspection_summary" ]; then
            inspection_summary="데이터베이스 관리자 권한이 불필요한 계정에 부여되어 있습니다."
        fi
    else
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="데이터베이스 관리자 권한이 필요한 계정(sa)에만 부여되어 있습니다."
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
