#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : D-21
# @Category    : DBMS (Database Management System)
# @Platform    : mysql_Linux
# @Severity    : 중
# @Title       : 인가되지 않은 GRANTOPTION 사용 제한
# @Description : 일반 사용자(관리자 제외)에게 GRANT OPTION이 부여되지 않았는지 점검
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


ITEM_ID="D-21"
ITEM_NAME="인가되지 않은 GRANTOPTION 사용 제한"
SEVERITY="중"

GUIDELINE_PURPOSE="GRANTOPTION을 ROLE에 의해 설정하여 권한의 남용을 방지하고, 안정성을 확보하기 위함"
GUIDELINE_THREAT="일반 사용자에게 GRANT OPTION이 부여된 경우, 일반 사용자가 Object 소유자인 것과 같이 다른 일반 사용자에게 권한을 부여할 수 있어 권한의 무분별한 확산으로 인한 중요 정보의 유출 등의 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="WITH _GRANT _OPTION이 ROLE에 의하여 설정된 경우"
GUIDELINE_CRITERIA_BAD="WITH _GRANT _OPTION이 ROLE에 의하여 설정되지 않은 경우"
GUIDELINE_REMEDIATION="WITH _GRANT _OPTION이 ROLE에 의하여 설정되도록 변경"

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

    # D-21: 일반 사용자(관리자 제외)에게 GRANT OPTION(Grant_priv)이 부여되어 있으면 취약.
    # 관리자 계정(root, mysql.sys, mysql.session)은 제외하고, 그 외 계정의 GRANT 권한 보유 여부를 확인.
    local grant_option_query="SELECT user, host FROM mysql.user WHERE Grant_priv='Y' AND user NOT IN ('root','mysql.sys','mysql.session') ORDER BY user, host;"
    command_executed="mysql -h "${DB_HOST}" -P "${DB_PORT}" -u "${DB_USER}" -p"${DB_PASSWORD}" -e \"${grant_option_query}\""
    local query_ok=1
    command_result=$(mysql -h "${DB_HOST}" -P "${DB_PORT}" -u "${DB_USER}" -p"${DB_PASSWORD}" -e "${grant_option_query}" 2>/dev/null) || query_ok=0

    # 결과 분석
    if [ "$query_ok" -eq 0 ]; then
        # 쿼리 자체가 실패함(권한 부족 등) → 자동 판단 불가
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="쿼리 결과 확인 불가 - 권한 부족 가능. 일반 사용자(관리자 제외)의 GRANT OPTION 보유 여부를 수동으로 확인 필요"
    elif [ -z "$command_result" ]; then
        # 헤더조차 없는 공백 출력 → 쿼리 결과 확인 불가
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="쿼리 결과 확인 불가 - 권한 부족 가능. 일반 사용자(관리자 제외)의 GRANT OPTION 보유 여부를 수동으로 확인 필요"
    else
        local grantee_count=$(echo "$command_result" | tail -n +2 | grep -v "^$" | wc -l)
        if [ "$grantee_count" -gt 0 ]; then
            diagnosis_result="VULNERABLE"
            status="취약"
            inspection_summary="관리자 외 ${grantee_count}개 계정에 GRANT OPTION 부여됨: $(echo "$command_result" | tail -n +2 | grep -v "^$" | head -5 | tr '\n' ', ')"
        else
            # 쿼리 성공 + 0행 → 관리자 외 GRANT OPTION 보유 계정 없음 (양호)
            diagnosis_result="GOOD"
            status="양호"
            inspection_summary="관리자 외 GRANT OPTION을 보유한 일반 사용자 계정 없음 (양호)"
        fi
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
