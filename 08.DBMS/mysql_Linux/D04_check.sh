#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-04-20
# ============================================================================
# [점검 항목 상세]
# @ID          : D-04
# @Category    : DBMS (Database Management System)
# @Platform    : mysql_Linux
# @Severity    : 상
# @Title       : 데이터베이스 관리자 권한을 꼭 필요한 계정 및 그룹에 대해서만 허용
# @Description : 관리자 계정의 원격 접속을 제한하여 비인가자의 DB 접근을 방지
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


ITEM_ID="D-04"
ITEM_NAME="데이터베이스 관리자 권한을 꼭 필요한 계정 및 그룹에 대해서만 허용"
SEVERITY="상"

GUIDELINE_PURPOSE="관리자 권한이 필요한 계정과 그룹에만 관리자 권한을 부여하였는지 점검하여 관리자 권한의 남용을 방지하여 계정 유출로 인한 비인가자의 DB 접근 가능성을 최소화하고자함"
GUIDELINE_THREAT="관리자 권한이 필요한 계정 및 그룹에만 관리자 권한을 부여하지 않으면 관리자 권한이 부여된 계정이 비인가자에게 유출될 경우 DB에 접근할 수 있는 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="관리자 권한이 필요한 계정 및 그룹에만 관리자 권한이 부여된 경우"
GUIDELINE_CRITERIA_BAD="관리자 권한이 필요 없는 계정 및 그룹에 관리자 권한이 부여된 경우"
GUIDELINE_REMEDIATION="관리자 권한이 필요한 계정 및 그룹에만 관리자 권한 부여"

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

    local diagnosis_result="MANUAL"
    local status="수동진단"
    local inspection_summary=""
    local command_result=""
    local command_executed=""
    local vulnerabilities_found=0

    # MySQL/MariaDB 서비스 확인 (only if library function exists)
    if declare -f check_mysql_service >/dev/null 2>&1; then
        if ! check_mysql_service; then
            if declare -f handle_dbms_not_running >/dev/null 2>&1; then
                handle_dbms_not_running "mysql" "${ITEM_ID}" "${ITEM_NAME}" \
                    "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" \
                    "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
            fi
            return 0
        fi
    fi

    # MySQL 연결 시도 (FR-018) (only if library function exists)
    if declare -f prompt_mysql_connection >/dev/null 2>&1; then
        if ! prompt_mysql_connection; then
            if declare -f handle_dbms_connection_failed >/dev/null 2>&1; then
                handle_dbms_connection_failed "mysql" "${ITEM_ID}" "${ITEM_NAME}" \
                    "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" \
                    "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
            fi
            return 0
        fi
    fi

    # ==========================================================================
    # 1. 관리자 권한(SUPER)을 가진 계정 확인
    # ==========================================================================
    # 연결 가드를 통과한 후이므로, 빈 결과는 "0행"이 아니라 쿼리 오류(권한 부족 등)를 의미할 수 있음.
    # 정상 0행과 오류/공백을 구분하기 위해 종료 코드를 캡처하고, 헤더는 분석 단계에서 제거함.
    local query_ok=1
    local admin_query="SELECT user, host FROM mysql.user WHERE Super_priv = 'Y';"
    command_executed="mysql -e \"SELECT user,host FROM mysql.user WHERE Super_priv='Y'; SELECT user,host FROM mysql.user WHERE Grant_priv='Y';\""
    local admin_raw=""
    admin_raw=$(mysql -h "${DB_HOST}" -P "${DB_PORT}" -u "${DB_USER}" -p"${DB_PASSWORD}" -e "${admin_query}" 2>/dev/null) || query_ok=0
    local admin_users=$(echo "$admin_raw" | tail -n +2 || echo "")

    # ==========================================================================
    # 2. GRANT OPTION 권한을 가진 계정 확인
    # ==========================================================================
    local grant_query="SELECT user, host FROM mysql.user WHERE Grant_priv = 'Y';"
    local grant_raw=""
    grant_raw=$(mysql -h "${DB_HOST}" -P "${DB_PORT}" -u "${DB_USER}" -p"${DB_PASSWORD}" -e "${grant_query}" 2>/dev/null) || query_ok=0
    local grant_users=$(echo "$grant_raw" | tail -n +2 || echo "")

    # ==========================================================================
    # 3. root 계정 원격 접속 확인 (보조 검사)
    # ==========================================================================
    local root_remote_query="SELECT host FROM mysql.user WHERE user='root' AND host NOT IN ('localhost', '127.0.0.1', '::1');"
    local root_remote_raw=""
    root_remote_raw=$(mysql -h "${DB_HOST}" -P "${DB_PORT}" -u "${DB_USER}" -p"${DB_PASSWORD}" -e "${root_remote_query}" 2>/dev/null) || query_ok=0
    local root_remote=$(echo "$root_remote_raw" | tail -n +2 || echo "")

    local details=""
    local admin_count=0
    local non_root_admin=""

    # 관리자 계정 분석
    if [ -n "$admin_users" ]; then
        admin_count=$(echo "$admin_users" | grep -v "^$" | wc -l)
        non_root_admin=$(echo "$admin_users" | grep -v "^root" | grep -v "^$" || true)
        details="SUPER 권한 계정: ${admin_count}개"
    fi

    if [ -n "$grant_users" ]; then
        local grant_count=$(echo "$grant_users" | grep -v "^$" | wc -l)
        details="${details}, GRANT 권한 계정: ${grant_count}개"
    fi

    if [ -n "$root_remote" ]; then
        local remote_count=$(echo "$root_remote" | grep -v "^$" | wc -l)
        details="${details}, root 원격 허용: ${remote_count}개 호스트"
    fi

    # ==========================================================================
    # 4. 판정
    # ==========================================================================
    if [ -n "$root_remote" ]; then
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="root 계정 원격 접속 허용: ${root_remote}"
        command_result="${details}"
    elif [ -n "$non_root_admin" ]; then
        # root 외 계정이 관리자 권한(SUPER)을 보유한 경우.
        # 가이드라인 기준상 "권한이 필요 없는 계정"에 부여된 경우만 취약이며,
        # 해당 계정이 승인된 DBA인지(권한 필요 여부)는 mysql.user만으로 판단 불가 → 수동진단.
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="root 외 관리자 권한(SUPER) 보유 계정 확인됨 - 승인된 DBA 계정으로 권한이 필요한지 수동 확인 필요: ${non_root_admin}"
        command_result="${details}"
    elif [ "$query_ok" -eq 0 ]; then
        # 권한 정보 조회 자체가 실패함(권한 부족 등) → 빈 결과를 양호로 단정할 수 없음. 수동 확인 필요.
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="mysql.user 권한 조회 불가 - 권한 부족 가능. SUPER/GRANT 권한 계정 및 root 원격 접속 허용 여부 수동 확인 필요"
        command_result="${details:-권한 정보 조회 실패}"
    else
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="관리자 권한이 적절히 제한됨: ${details:-root만 관리자 권한 보유}"
        command_result="${details:-root만 관리자 권한 보유}"
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
    diagnose
}

if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi
