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
# @Platform    : MSSQL_Linux
# @Severity    : 상
# @Title       : Registry Procedure 권한 제한
# @Description : DBMS 기본 포트 사용 점검 관리를 통한 DBMS 보안 강화
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

ITEM_ID="D-24"

ITEM_NAME="Registry Procedure 권한 제한"
SEVERITY="상"
GUIDELINE_PURPOSE="불필요한 RegistryProcedure의 권한 설정을 확인하고 제한하여 시스템의 보안 및 안정성을 강화하기 위함"
GUIDELINE_THREAT="불필요한 레지스트리 접근 권한이 제한되지 않는 경우, 공격자가 시스템을 변경하거나 악성 소프트웨어를 설치하여 권한 상승, 데이터 유출, 시스템 장애를 발생시킬 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="제한이 필요한 시스템 확장 저장 프로 시저들이 DBA 외 guest/public에게 부여되지 않은 경우"
GUIDELINE_CRITERIA_BAD="제한이 필요한 시스템 확장 저장 프로 시저들이 DBA 외 guest/public에게 부여된 경우"
GUIDELINE_REMEDIATION="guest/public에게 부여된 시스템 확장 저장 프로 시저 권한 제거"

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
    local status=""
    local inspection_summary=""
    local command_result=""
    local command_executed=""

    # Check if MSSQL service is running
    if command -v sc.exe &>/dev/null; then
        if ! sc.exe query MSSQLSERVER &>/dev/null && ! sc.exe query SQLServerAgent &>/dev/null; then
            diagnosis_result="MANUAL"
            status="수동진단"
            inspection_summary="MSSQL 서비스 미실행 (서비스 시작 후 수동 확인 필요)"
            save_dual_result "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" "${inspection_summary}" "${command_result}" "${command_executed}" "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
            verify_result_saved "${ITEM_ID}"
            return 0
        fi
    fi

    # D-24 판단기준: 제한이 필요한 시스템 확장 저장 프로시저(xp_regread, xp_regwrite,
    # xp_regdeletevalue, xp_regenumvalues 등)의 실행 권한이 DBA 외 guest/public에게
    # 부여되어 있는지 점검. 이는 master DB에 대한 T-SQL 연결(sys.database_permissions)을
    # 통해서만 확인 가능하며, 포트 사용 여부와는 무관함.
    # Linux 환경에서는 라이브 T-SQL 연결 없이 확장 저장 프로시저 권한을 정적으로 확인할 수
    # 없으므로 MANUAL로 판정한다 (포트 기반 GOOD 오판정 제거).
    diagnosis_result="MANUAL"
    status="수동진단"
    command_executed="SQL Server Management Studio 또는 sqlcmd로 master DB에 연결 후 확장 저장 프로시저 권한 확인"
    command_result=""
    inspection_summary="시스템 확장 저장 프로시저(xp_reg* 등)의 guest/public 권한 부여 여부는 라이브 T-SQL 연결이 필요하여 자동 점검할 수 없습니다 (수동 점검 필요).\n\n"
    inspection_summary+="판단기준:\n"
    inspection_summary+="- 양호: 제한이 필요한 시스템 확장 저장 프로시저가 DBA 외 guest/public에게 부여되지 않은 경우\n"
    inspection_summary+="- 취약: 제한이 필요한 시스템 확장 저장 프로시저가 DBA 외 guest/public에게 부여된 경우\n\n"
    inspection_summary+="점검 대상 확장 저장 프로시저(예):\n"
    inspection_summary+="- sys.xp_regread, sys.xp_regwrite, sys.xp_regdeletevalue, sys.xp_regdeletekey,\n"
    inspection_summary+="  sys.xp_regenumvalues, sys.xp_regremovemultistring, sys.xp_readdmultistring\n\n"
    inspection_summary+="검증 방법:\n"
    inspection_summary+="1. SQL Server Management Studio > 개체 탐색기 > master > 프로그래밍 기능 >\n"
    inspection_summary+="   확장 저장 프로시저 > 시스템 확장 저장 프로시저\n"
    inspection_summary+="2. 각 xp_reg* 프로시저 우클릭 > 속성 > 사용 권한에서 public 실행 권한 확인\n"
    inspection_summary+="3. 또는 다음 쿼리로 권한 확인:\n"
    inspection_summary+="   SELECT OBJECT_NAME(major_id) AS proc_name, USER_NAME(grantee_principal_id) AS grantee,\n"
    inspection_summary+="          permission_name, state_desc\n"
    inspection_summary+="   FROM master.sys.database_permissions\n"
    inspection_summary+="   WHERE OBJECT_NAME(major_id) LIKE 'xp_reg%'\n"
    inspection_summary+="     AND USER_NAME(grantee_principal_id) IN ('public', 'guest');\n\n"
    inspection_summary+="조치 방법:\n"
    inspection_summary+="- guest/public에게 부여된 시스템 확장 저장 프로시저 실행 권한 제거 (REVOKE)"

    save_dual_result "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" "${inspection_summary}" "${command_result}" "${command_executed}" "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
    verify_result_saved "${ITEM_ID}"; return 0
}

main() {
    diagnose
}

if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi
