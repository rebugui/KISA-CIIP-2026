#!/bin/bash

# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : D-26
# @Category    : DBMS (Database Management System)
# @Platform    : MSSQL_Linux
# @Severity    : 상
# @Title       : 데이터베이스의 접근, 변경, 삭제 등의 감사 기록이 기관의 감사 기록 정책에 적합하도록 설정
# @Description : 보안 감사 로그 기록 및 관리를 통한 추적성 확보
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

ITEM_ID="D-26"

ITEM_NAME="데이터베이스의 접근, 변경, 삭제 등의 감사 기록이 기관의 감사 기록 정책에 적합하도록 설정"
SEVERITY="상"
GUIDELINE_PURPOSE="데이터, 로그, 응용 프로그램에 대한 감사 기록 정책을 수립하고 적용하여 데이터베이스에 문제 발생 시 원활하게 대응하기 위함"
GUIDELINE_THREAT="감사 기록 정책이 설정되어 있지 않을 경우, 데이터베이스에 문제 발생 시 원인을 규명할 수 있는 자료가 존재하지 않아 이에 대한 대처 및 개선 방안 수립이 어려워 장기적으로 심각한 보안 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="DBMS의 감사 로그 저장 정책이 수립되어 있으며, 정책 설정이 적용된 경우"
GUIDELINE_CRITERIA_BAD="DBMS에 대한 감사 로그 저장을 하지 않거나, 정책 설정이 적용되지 않은 경우"
GUIDELINE_REMEDIATION="DBMS에 대한 감사 로그 저장 정책 수립, 적용"

diagnose() {
    echo "진단 항목: ${ITEM_ID} - ${ITEM_NAME}"

    # FR-022: Check required tools
    if ! check_mssql_tools; then
        handle_missing_tools "mssql" "${ITEM_ID}" "${ITEM_NAME}" \
            "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" \
            "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
        return 0
    fi

    local diagnosis_result="MANUAL" status="수동진단" inspection_summary="" command_result="" command_executed=""

    if command -v sc.exe &>/dev/null; then
        if ! sc.exe query MSSQLSERVER &>/dev/null && ! sc.exe query SQLServerAgent &>/dev/null; then
            diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="diagnosis_result="MANUAL" (서비스 시작 후 수동 확인 필요)"
            save_dual_result "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" "${inspection_summary}" "${command_result}" "${command_executed}" "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
            verify_result_saved "${ITEM_ID}"; return 0
        fi
    fi

    if command -v sqlcmd &>/dev/null; then
        command_executed="sqlcmd -Q \"SELECT name FROM sys.server_audit_specifications WHERE is_state_enabled = 1; SELECT name FROM sys.database_audit_specifications WHERE is_state_enabled = 1;\""
        inspection_summary="MSSQL 감사 로깅 확인 - 수동 확인 필요\n\n"
        inspection_summary+="검증 방법:\n"
        inspection_summary+="1. 서버 감사(Server Audit) 확인:\n"
        inspection_summary+="   SELECT name, is_state_enabled FROM sys.server_audits;\n"
        inspection_summary+="2. 서버 감사 사양 확인:\n"
        inspection_summary+="   SELECT name, is_state_enabled FROM sys.server_audit_specifications;\n"
        inspection_summary+="3. 데이터베이스 감사 사양 확인:\n"
        inspection_summary+="   SELECT name, is_state_enabled FROM sys.database_audit_specifications;\n"
        inspection_summary+="4. is_state_enabled = 1: 양호 (감사 활성화)\n"
        inspection_summary+="5. is_state_enabled = 0: 취약 (감사 비활성화)\n\n"
        inspection_summary+="조치 방법:\n"
        inspection_summary+="- 서버 감사 생성: CREATE SERVER AUDIT audit_name TO FILE (FILEPATH = 'C:\\Audit');\n"
        inspection_summary+="- 감사 활성화: ALTER SERVER AUDIT audit_name WITH (STATE = ON);\n"
        inspection_summary+="- 감사 사양 생성 및 활성화\n"
        inspection_summary+="- 주요 이벤트 감사: 로그인, 권한 변경, 스키마 변경, 데이터 조작\n"
        inspection_summary+="- 감사 로그 정기적 검토 및 보관 (1년 이상 권장)"
    else
        inspection_summary="MSSQL 감사 로깅 확인 - 수동 확인 필요\n\n"
        inspection_summary+="검증 방법:\n"
        inspection_summary+="1. SSMS 실행 > 서버 > Security > Audits\n"
        inspection_summary+="2. Audits 폴더에서 서버 감사 목록 확인\n"
        inspection_summary+="3. 감사 우클릭 > Properties 확인\n"
        inspection_summary+="4. Server Audit Specifications 확인:\n"
        inspection_summary+="   - Security > Server Audit Specifications\n"
        inspection_summary+="5. Database Audit Specifications 확인:\n"
        inspection_summary+="   - Database > Security > Database Audit Specifications\n\n"
        inspection_summary+="조치 방법:\n"
        inspection_summary+="- Security > Audits > New Server Audit 생성\n"
        inspection_summary+="- Audit Type: File 선택, 경로 지정\n"
        inspection_summary+="- Server Audit Specifications 생성\n"
        inspection_summary+="- Audit Action Type 선택:\n"
        inspection_summary+="   - SUCCESSFUL_LOGIN_GROUP, FAILED_LOGIN_GROUP\n"
        inspection_summary+="   - DATABASE_ROLE_MEMBER_CHANGE_GROUP\n"
        inspection_summary+="   - SCHEMA_OBJECT_PERMISSION_CHANGE_GROUP\n"
        inspection_summary+="   - DATABASE_OBJECT_ACCESS_GROUP 등\n"
        inspection_summary+="- 감사 활성화 및 로그 정기 검토 (월 1회 이상 권장)"
    fi

    diagnosis_result="MANUAL" status="수동진단"

    save_dual_result "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" "${inspection_summary}" "${command_result}" "${command_executed}" "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
    verify_result_saved "${ITEM_ID}"; return 0
}

main() {
    diagnose
}

if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi
