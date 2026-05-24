#!/bin/bash

# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : D-18
# @Category    : DBMS (Database Management System)
# @Platform    : MSSQL
# @Severity    : 상
# @Title       : 응용프로그램또는DBA계정의Role이Public으로설정되지않도록조정
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
ITEM_ID="D-18"
ITEM_NAME="응용 프로그램 또는 DBA 계정의 Role이 Public으로 설정되지 않도록 조정"
SEVERITY="상"

# 가이드라인 정보
GUIDELINE_PURPOSE="응용 프로그램 또는 DBA 계정의 Role을 점검하여 일반 계정으로 응용 프로그램 테이블이나 DBA 테이블의 접근을 차단하기 위함"
GUIDELINE_THREAT="응용 프로그램 또는 DBA 계정의 Role이 Public으로 설정된 경우 일반 계정에서도 응용 프로그램 테이블 및 DBA 테이블로 접근할 수 있으므로 중요 정보 유출의 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="DBA 계정의 Role이 Public으로 설정되지 않은 경우"
GUIDELINE_CRITERIA_BAD="DBA 계정의 Role이 Public으로 설정된 경우"
GUIDELINE_REMEDIATION="DBA 계정의 Role 설정에서 Public 그룹 권한 취소"

# ============================================================================
# 진단 함수
# ============================================================================

diagnose() {
    echo "진단 항목: ${ITEM_ID} - ${ITEM_NAME}"

    # FR-022: Check required tools
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

    # D-18은 Oracle PUBLIC role 전용 항목
    # MSSQL은 public 역할이 있지만 Oracle과 다른 권한 모델을 사용하므로 N/A 처리
    # (MSSQL public 역할은 기본적으로 모든 사용자에게 부여되지만 최소 권한만 가짐)

    diagnosis_result="N/A"
    status="N/A"
    inspection_summary="이 항목은 Oracle PUBLIC role 전용 항목입니다. MSSQL은 public 역할이 존재하지만 Oracle과 다른 권한 모델을 사용합니다. MSSQL public 역할 점검: SELECT class_desc, permission_name FROM sys.server_permissions WHERE grantee_principal_id = SUSER_SID(N'public');. 불필요한 권한 제거: REVOKE [permission] TO public;. 권장: public 역할에서 CONNECT SQL만 허용하고 나머지는 제거."
    command_result="MSSQL uses 'public' role with different permission model than Oracle"
    command_executed="SELECT * FROM fn_my_permissions(NULL, 'SERVER') WHERE permission_name = 'CONNECT SQL';"

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
