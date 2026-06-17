#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : D-24
# @Category    : DBMS (Database Management System)
# @Platform    : Oracle_Linux
# @Severity    : 상
# @Title       : Registry Procedure 권한 제한
# @Description : MSSQL 레지스트리 접근 권한 확인 (Oracle 미해당)
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
source "${LIB_DIR}/dbms_connector.sh"
source "${LIB_DIR}/db_connection_helpers.sh"

# Oracle 연결 정보 초기화 (fallback if library not loaded)
ORACLE_USER="${ORACLE_USER:-system}"
ORACLE_PASSWORD="${ORACLE_PASSWORD:-manager}"
ORACLE_HOST="${ORACLE_HOST:-localhost}"
ORACLE_PORT="${ORACLE_PORT:-1521}"
ORACLE_SID="${ORACLE_SID:-ORCL}"
ORACLE_SYSDBA="${ORACLE_SYSDBA:-sys as sysdba}"

ITEM_ID="D-24"
ITEM_NAME="Registry Procedure 권한 제한"
SEVERITY="상"

GUIDELINE_PURPOSE="불필요한 RegistryProcedure의 권한 설정을 확인하고 제한하여 시스템의 보안 및 안정성을 강화하기 위함"
GUIDELINE_THREAT="불필요한 레지스트리 접근 권한이 제한되지 않는 경우, 공격자가 시스템을 변경하거나 악성 소프트웨어를 설치하여 권한 상승, 데이터 유출, 시스템 장애를 발생시킬 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="제한이 필요한 시스템 확장 저장 프로 시저들이 DBA 외 guest/public에게 부여되지 않은 경우"
GUIDELINE_CRITERIA_BAD="제한이 필요한 시스템 확장 저장 프로 시저들이 DBA 외 guest/public에게 부여된 경우"
GUIDELINE_REMEDIATION="guest/public에게 부여된 시스템 확장 저장 프로 시저 권한 제거"

diagnose() {
    diagnosis_result="unknown"  # Global variable (not local)
    local status="수동진단"
    local inspection_summary=""
    local command_result=""
    local command_executed=""

    # Initialize Oracle connection variables (only if library function exists)
    if declare -f init_oracle_vars >/dev/null 2>&1; then
        init_oracle_vars
    fi

    echo "진단 항목: ${ITEM_ID} - ${ITEM_NAME}"


    local diagnosis_result="N/A"
    local status="N/A"
    local inspection_summary="이 항목은 MSSQL의 Windows 레지스트리 접근 권한 점검입니다. Oracle에서는 적용되지 않습니다."
    local command_result="N/A"
    local command_executed="N/A"

        if declare -f save_dual_result >/dev/null 2>&1; then
            save_dual_result "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" "${inspection_summary}" "${command_result}" "${command_executed}" "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
        fi
    if declare -f verify_result_saved >/dev/null 2>&1; then
        verify_result_saved "${ITEM_ID}"
    fi
    return 0
}

main() {
    diagnose
}

if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi
