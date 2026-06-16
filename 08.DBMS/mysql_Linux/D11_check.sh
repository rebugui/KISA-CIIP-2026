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

    # GRANT 권한 확인 (mysql.user 테이블의 Grant_priv는 MySQL 8.0에서 제거됨)
    # MySQL 5.7 또는 MariaDB에서만 체크
    # 연결 가드 통과 후이므로, 두 조회(Grant_priv 컬럼 / 역할 폴백)가 모두 공백/오류면
    # "0행(양호)"이 아니라 자동 판단 불가(MANUAL)로 처리해야 함.
    local grant_priv_query="SELECT user, host FROM mysql.user WHERE Grant_priv='Y' ORDER BY user, host;"
    command_executed="mysql -h "${DB_HOST}" -P "${DB_PORT}" -u "${DB_USER}" -p"${DB_PASSWORD}" -e \"${grant_priv_query}\""
    command_result=$(mysql -h "${DB_HOST}" -P "${DB_PORT}" -u "${DB_USER}" -p"${DB_PASSWORD}" -e "${grant_priv_query}" 2>/dev/null || echo "")

    if [ -z "$command_result" ]; then
        # MySQL 8.0+의 경우 grants 테이블(역할 기반)에서 GRANT OPTION 확인 (폴백)
        command_result=$(mysql -h "${DB_HOST}" -P "${DB_PORT}" -u "${DB_USER}" -p"${DB_PASSWORD}" -e "SELECT grantee, table_schema FROM information_schema.role_table_grants WHERE is_grantable='YES' LIMIT 20;" 2>/dev/null || echo "")
    fi

    # 결과 분석
    if [ -n "$command_result" ]; then
        local grant_count=$(echo "$command_result" | tail -n +2 | grep -v "^$" | wc -l)

        if [ "$grant_count" -gt 0 ]; then
            local grant_users=$(echo "$command_result" | tail -n +2 | grep -v "^$" || echo "")
            # 첫 컬럼(grantee)의 계정명을 정규화하여 root 여부 판별.
            # - MySQL 5.7/MariaDB(mysql.user): 첫 컬럼이 bare `root`
            # - MySQL 8.0 폴백(role_table_grants): 첫 컬럼이 따옴표 형식 `'root'@'host'`
            # 두 형식 모두에서 선행 작은따옴표를 제거하고 @ 이전 사용자명으로 root를 제외함.
            local non_root_grant=$(echo "$grant_users" | awk '{ acct=$1; gsub(/^'\''/, "", acct); sub(/'\''?@.*$/, "", acct); if (acct != "root") print }' || echo "")

            if [ -n "$non_root_grant" ]; then
                # 비-root 계정이 GRANT(grantable) 권한을 보유. 해당 계정이 인가된 DBA인지
                # 정적으로 확인할 수 없으므로 자동 취약 단정 대신 수동진단으로 라우팅.
                diagnosis_result="MANUAL"
                status="수동진단"
                inspection_summary="root 외 계정에 GRANT 권한이 부여되어 있습니다. 해당 계정이 인가된 DBA인지 수동 확인 필요: $(echo "$non_root_grant" | head -5 | tr '\n' ', ')"
            else
                diagnosis_result="GOOD"
                status="양호"
                inspection_summary="root 계정에만 GRANT 권한 부여됨 (총 ${grant_count}개)"
            fi
        else
            diagnosis_result="GOOD"
            status="양호"
            inspection_summary="GRANT 권한을 가진 계정 없음"
        fi
    else
        # Grant_priv 컬럼 조회와 역할 기반 폴백이 모두 공백/오류임.
        # 연결은 성공했으나 결과를 얻지 못했으므로 "양호"로 단정할 수 없음 → 자동 판단 불가.
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="쿼리 결과 확인 불가 - 권한 부족 가능. Grant_priv 컬럼 및 역할 기반 GRANT OPTION 부여 계정을 수동으로 확인 필요"
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
