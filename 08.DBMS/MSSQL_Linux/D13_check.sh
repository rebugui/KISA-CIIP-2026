#!/bin/bash

# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : D-13
# @Category    : DBMS (Database Management System)
# @Platform    : MSSQL_Linux
# @Severity    : 중
# @Title       : 불필요한 ODBC/OLE-DB 데이터 소스와 드라이브를 제거하여 사용
# @Description : 불필요한ODBC/OLE-DB데이터소스와드라이브를제거하여사용 관리를 통한 DBMS 보안 강화
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
ITEM_ID="D-13"
ITEM_NAME="불필요한 ODBC/OLE-DB 데이터 소스와 드라이브를 제거하여 사용"
SEVERITY="중"

# 가이드라인 정보
GUIDELINE_PURPOSE="불필요한 데이터 소스 및 드라이버를 제거함으로써 비인가자에 의한 데이터베이스 접속 및 자료 유출을 차단하기 위함"
GUIDELINE_THREAT="불필요한 ODBC/OLE-DB 데이터 소스를 통한 비인가자의 데이터베이스 접속 및 주요 정보 유출에 대한 위험이 발생할 수 있음"
GUIDELINE_CRITERIA_GOOD="불필요한 ODBC/OLE-DB가 설치되지 않은 경우"
GUIDELINE_CRITERIA_BAD="불필요한 ODBC/OLE-DB가 설치된 경우"
GUIDELINE_REMEDIATION="불필요한 ODBC/OLE-DB 제거"

# ============================================================================
# 진단 함수
# ============================================================================

diagnose() {
    echo "진단 항목: ${ITEM_ID} - ${ITEM_NAME}"

    # D-13은 Windows OS 전용 항목 — Linux 환경에서는 N/A
    local os_type=""
    if [ -f "/etc/os-release" ]; then
        os_type="Linux"
    elif [[ "$OSTYPE" == "msys" || "$OSTYPE" == "win32" ]]; then
        os_type="Windows"
    else
        os_type="Unknown"
    fi

    if [ "$os_type" = "Linux" ]; then
        diagnosis_result="N/A"
        status="N/A"
        inspection_summary="이 항목은 Windows ODBC/OLE-DB 데이터소스 점검입니다. Linux 환경에서 MSSQL을 실행 중인 경우 해당하지 않습니다. Linux의 경우 unixODBC 설정을 확인하세요 (/etc/odbc.ini, /etc/odbcinst.ini)."
        command_result="OS: Linux, ODBC Data Sources: N/A (use unixODBC)"
        command_executed="cat /etc/os-release"

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

        verify_result_saved "${ITEM_ID}"
        return 0
    fi

    # Windows 경로 — 먼저 도구 확인
    if ! check_mssql_tools; then
        handle_missing_tools "mssql" "${ITEM_ID}" "${ITEM_NAME}" \
            "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" \
            "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
        return 0
    fi

    local diagnosis_result="UNKNOWN"
    local status="미진단"
    local inspection_summary=""
    local command_result=""
    local command_executed=""

    # Windows 환경인 경우 수동 진단 유도
    diagnosis_result="MANUAL"
    status="수동진단"
    inspection_summary="ODBC/OLE-DB 데이터소스 확인이 필요합니다. Windows ODBC 데이터소스 관리자(odbcad32.exe)를 실행하여 '시스템 DSN' 탭에서 사용하지 않는 데이터소스와 드라이버를 제거하세요. 불필요한 DSN이 없으면 양호, 있으면 취약입니다."
    command_result="ODBC Data Sources: Manual check required"
    command_executed="odbcad32.exe (ODBC Data Source Administrator)"

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

    verify_result_saved "${ITEM_ID}"

    return 0
}

# ============================================================================
# 메인 실행
# ============================================================================

main() {
    show_diagnosis_start "${ITEM_ID}" "${ITEM_NAME}"
    check_disk_space
    diagnose
    show_diagnosis_complete "${ITEM_ID}" "${diagnosis_result:-UNKNOWN}"
}

if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi
