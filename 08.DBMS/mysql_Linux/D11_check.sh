#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : D-11
# @Category    : DBMS (Database Management System)
# @Platform    : mysql_Linux
# @Severity    : 상
# @Title       : DBA 이외의 인가되지 않은 사용자가 시스템 테이블에 접근할 수 없도록 설정
# @Description : GRANT 권한을 제어하여 무단 권한 부여 방지
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


ITEM_ID="D-11"
ITEM_NAME="DBA 이외의 인가되지 않은 사용자가 시스템 테이블에 접근할 수 없도록 설정"
SEVERITY="상"

GUIDELINE_PURPOSE="시스템 테이블의 일반 사용자 계정 접근 제한 설정 적용 여부를 점검하여 일반 사용자 계정 유출 시 발생할 수 있는 비인가자의 시스템 테이블 접근 위험을 차단하기 위함"
GUIDELINE_THREAT="시스템 테이블의 일반 사용자 계정 접근 제한 설정이 되어 있지 않을 경우 Object, 사용자, 테이블 및 뷰, 작업 내역 등의 시스템 테이블에 저장된 정보가 누출될 수 있음"
GUIDELINE_CRITERIA_GOOD="시스템 테이블에 DBA만 접근 가능하도록 설정되어 있는 경우"
GUIDELINE_CRITERIA_BAD="시스템 테이블에 DBA 외 일반 사용자 계정이 접근 가능하도록 설정되어 있는 경우"
GUIDELINE_REMEDIATION="시스템 테이블에 일반 사용자 계정이 접근할 수 없도록 설정"

# MySQL 연결 정보 초기화 (fallback if library not loaded)
DB_USER="${DB_USER:-root}"
DB_PASSWORD="${DB_PASSWORD:-}"
DB_HOST="${DB_HOST:-localhost}"
DB_PORT="${DB_PORT:-3306}"
DB_ADMIN_USER="${DB_ADMIN_USER:-${DB_USER}}"
DB_ADMIN_PASS="${DB_ADMIN_PASS:-${DB_PASSWORD}}"

diagnose() {
    echo "진단 항목: ${ITEM_ID} - ${ITEM_NAME}"

    # Initialize MySQL connection variables (only if library function exists)
    if declare -f init_mysql_vars >/dev/null 2>&1; then
        init_mysql_vars
    fi

    # FR-022: Check required tools (only if library function exists)
    if declare -f check_mysql_tools >/dev/null 2>&1; then
        if ! check_mysql_tools; then
            if declare -f handle_missing_tools >/dev/null 2>&1; then
                handle_missing_tools "mysql" "${ITEM_ID}" "${ITEM_NAME}" \
                    "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" \
                    "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
            fi
            return 0
        fi
    fi

    local diagnosis_result="GOOD"
    local status="양호"
    local inspection_summary=""
    local command_result=""
    local command_executed=""

    # MySQL/MariaDB 서비스 확인 (only if library function exists)
    if declare -f check_mysql_service >/dev/null 2>&1; then
        if ! check_mysql_service; then
            diagnosis_result="MANUAL"
            status="수동진단"
            inspection_summary="MySQL/MariaDB 서비스가 실행 중이지 않습니다. 서비스 시작 후 진단이 필요합니다."
            command_result="MySQL/MariaDB service not running"
            command_executed="mysqladmin ping -h ${DB_HOST} -P ${DB_PORT}"
            # Save results (only if library function exists)
            if declare -f save_dual_result >/dev/null 2>&1; then
                save_dual_result "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" "${inspection_summary}" "${command_result}" "${command_executed}" "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
            fi
            if declare -f verify_result_saved >/dev/null 2>&1; then
                verify_result_saved "${ITEM_ID}"
            fi
            return 0
        fi
    fi

    # 시스템 테이블 접근 권한 확인 (information_schema.schema_privileges + user_privileges)
    # MySQL 5.7, 8.0, MariaDB에서 사용 가능
    local sys_access_query="SELECT Grantee, Table_schema, Privilege_type FROM information_schema.schema_privileges WHERE Table_schema IN ('mysql','performance_schema','sys') UNION ALL SELECT GRANTEE, '*' as Table_schema, Privilege_type FROM information_schema.user_privileges WHERE Privilege_type IN ('SELECT','INSERT','UPDATE','DELETE','DROP','ALTER','CREATE','ALL PRIVILEGES') ORDER BY Grantee;"
    command_executed="mysql -h \"${DB_HOST}\" -P \"${DB_PORT}\" -u \"${DB_USER}\" -p\"${DB_PASSWORD}\" -e \"${sys_access_query}\""
    command_result=$(mysql -h "${DB_HOST}" -P "${DB_PORT}" -u "${DB_USER}" -p"${DB_PASSWORD}" -e "${sys_access_query}" 2>/dev/null || echo "")

    # 결과 분석
    if [ -n "$command_result" ]; then
        local priv_count=$(echo "$command_result" | tail -n +2 | grep -v "^$" | grep -iv "'root'@" | wc -l)

        if [ "$priv_count" -gt 0 ]; then
            local non_root_privs=$(echo "$command_result" | tail -n +2 | grep -v "^$" | grep -iv "'root'@" || echo "")
            # PUBLIC 또는 '%' broad grant 확인
            if echo "$non_root_privs" | grep -qi "PUBLIC\|'%'"; then
                diagnosis_result="VULNERABLE"
                status="취약"
                inspection_summary="PUBLIC 또는 모든 호스트(%)에 시스템 스키마 접근 권한이 부여되어 있습니다: $(echo "$non_root_privs" | head -5 | tr '\n' ', ')"
            else
                diagnosis_result="MANUAL"
                status="수동진단"
                inspection_summary="root 외 계정에 시스템 테이블 접근 권한이 부여되어 있습니다. 해당 계정이 인가된 DBA인지 수동 확인 필요: $(echo "$non_root_privs" | head -5 | tr '\n' ', ')"
            fi
        else
            diagnosis_result="GOOD"
            status="양호"
            inspection_summary="root 계정 외 시스템 테이블 접근 권한을 가진 계정 없음"
        fi
    else
        # 연결은 성공했으나 결과를 얻지 못했으므로 "양호"로 단정할 수 없음 → 자동 판단 불가.
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="쿼리 결과 확인 불가 - 시스템 테이블 접근 권한 조회 실패. 수동 확인 필요"
    fi

    # Save results (only if library function exists)
    if declare -f save_dual_result >/dev/null 2>&1; then
        save_dual_result "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" "${inspection_summary}" "${command_result}" "${command_executed}" "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
    fi
    if declare -f verify_result_saved >/dev/null 2>&1; then
        verify_result_saved "${ITEM_ID}"
    fi

    return 0
}

main() {
    # MySQL 연결 확인 (FR-018) (only if library function exists)
    if declare -f check_mysql_connection >/dev/null 2>&1; then
        if ! check_mysql_connection; then
            diagnosis_result="MANUAL"
            status="수동진단"
            if declare -f save_dual_result >/dev/null 2>&1; then
                save_dual_result "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" \
                    "MySQL 연결 실패 - 데이터베이스 관리자 비밀번호 확인 필요" \
                    "연결 실패: User=${DB_USER}, Host=${DB_HOST}:${DB_PORT}" \
                    "mysql -u ${DB_USER} -h ${DB_HOST} -P ${DB_PORT}" \
                    "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" \
                    "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
            fi
            return 1
        fi
    fi

    diagnose
}

if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi
