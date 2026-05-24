#!/bin/bash

# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : D-25
# @Category    : DBMS (Database Management System)
# @Platform    : MSSQL_Linux
# @Severity    : 상
# @Title       : 주기적 보안 패치 및 벤더 권고 사항 적용
# @Description : 과도한 권한 부여 방지 및 최소 권한 원칙 적용
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

ITEM_ID="D-25"

ITEM_NAME="주기적 보안 패치 및 벤더 권고 사항 적용"
SEVERITY="상"
GUIDELINE_PURPOSE="안전한 버전의 데이터베이스를 사용하여 알려진 보안 취약점으로 인한 공격을 차단하기 위함"
GUIDELINE_THREAT="안전하지 않은 버전을 사용할 경우, 알려진 보안 취약점을 통해 시스템에 침투하거나 데이터의 탈취, 악성 코드 감염 및 서비스 중단 등의 보안 사고를 초래할 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="보안 패치가 적용된 버전을 사용하는 경우"
GUIDELINE_CRITERIA_BAD="보안 패치가 적용되지 않는 버전을 사용하는 경우"
GUIDELINE_REMEDIATION="보안 패치가 적용된 버전으로 업데이트"

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
        command_executed="sqlcmd -Q \"SELECT DP1.name AS DatabaseRole, DP2.name AS DatabasePrincipal, permission_name, state_desc FROM sys.database_permissions INNER JOIN sys.database_principals DP1 ON sys.database_permissions.grantee_principal_id = DP1.principal_id INNER JOIN sys.database_principals DP2 ON sys.database_permissions.grantor_principal_id = DP2.principal_id WHERE permission_name IN ('BACKUP DATABASE', 'BACKUP LOG', 'RESTORE DATABASE', 'RESTORE LOG');\""
        inspection_summary="MSSQL 백업/복구 권한 확인 - 수동 확인 필요\n\n"
        inspection_summary+="검증 방법:\n"
        inspection_summary+="1. 위 쿼리 실행으로 백업/복구 권한 보유 계정 확인\n"
        inspection_summary+="2. sysadmin 역할에 속한 계정 확인:\n"
        inspection_summary+="   SELECT name FROM sys.server_principals WHERE IS_SRVROLEMEMBER('sysadmin', name) = 1;\n"
        inspection_summary+="3. db_owner 역할에 속한 계정 확인:\n"
        inspection_summary+="   SELECT DP1.name FROM sys.database_principals DP1 INNER JOIN sys.database_role_members DRM ON DP1.principal_id = DRM.member_principal_id INNER JOIN sys.database_principals DP2 ON DRM.role_principal_id = DP2.principal_id WHERE DP2.name = 'db_owner';\n\n"
        inspection_summary+="조치 방법:\n"
        inspection_summary+="- 불필요한 백업/복구 권한 취소: REVOKE BACKUP DATABASE TO [user];\n"
        inspection_summary+="- sysadmin 역할에서 불필요한 계정 제거\n"
        inspection_summary+="- db_backupoperator 역할에만 백업 권한 부여\n"
        inspection_summary+="- 정기적 권한 감사 실시"
    else
        inspection_summary="MSSQL 백업/복구 권한 확인 - 수동 확인 필요\n\n"
        inspection_summary+="검증 방법:\n"
        inspection_summary+="1. SSMS 실행 > 서버 연결\n"
        inspection_summary+="2. Security > Logins에서 계정별 역할 확인\n"
        inspection_summary+="3. 서버 역할(sysadmin) 확인:\n"
        inspection_summary+="   - 로그인 우클릭 > Properties > Server Roles\n"
        inspection_summary+="4. 데이터베이스 역할(db_owner, db_backupoperator) 확인:\n"
        inspection_summary+="   - Database > Security > Users > 우클릭 > Properties > Membership\n\n"
        inspection_summary+="조치 방법:\n"
        inspection_summary+="- 불필요한 백업/복구 권한 취소\n"
        inspection_summary+="- sysadmin 역할에서 불필요한 계정 제거\n"
        inspection_summary+="- db_backupoperator 역할에만 백업 권한 부여\n"
        inspection_summary+="- 정기적 권한 감사 실시 (분기 1회 권장)"
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
