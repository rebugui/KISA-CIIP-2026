#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : D-10
# @Category    : DBMS (Database Management System)
# @Platform    : mysql_Linux
# @Severity    : 상
# @Title       : 원격에서 DB 서버로의 접속 제한
# @Description : 지정된 IP 주소만 DB 서버에 접근 가능하도록 설정되어있는지 점검
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


ITEM_ID="D-10"
ITEM_NAME="원격에서 DB 서버로의 접속 제한"
SEVERITY="상"

GUIDELINE_PURPOSE="지정된 IP 주소만 DB 서버에 접근 가능하도록 설정되어 있는지 점검하여 비인가자의 DB 서버 접근을 원천적으로 차단하고자함"
GUIDELINE_THREAT="DB 서버 접속 시 IP 주소 제한이 적용되지 않은 경우 비인가자가 내·외부 망 위치에 상관없이 DB 서버에 접근할 수 있는 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="DB 서버에 지정된 IP 주소에서만 접근 가능하도록 제한한 경우"
GUIDELINE_CRITERIA_BAD="DB 서버에 지정된 IP 주소에서만 접근 가능하도록 제한하지 않은 경우"
GUIDELINE_REMEDIATION="DB 서버에 대해 지정된 IP 주소에서만 접근 가능하도록 설정"

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
    local vulnerabilities_found=0

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

    # 1. bind-address 설정 확인
    local bind_address_query="SHOW VARIABLES LIKE 'bind_address';"
    command_executed="mysql -h "${DB_HOST}" -P "${DB_PORT}" -u "${DB_USER}" -p"${DB_PASSWORD}" -e \"${bind_address_query}\""
    command_result=$(mysql -h "${DB_HOST}" -P "${DB_PORT}" -u "${DB_USER}" -p"${DB_PASSWORD}" -e "${bind_address_query}" 2>/dev/null || echo "")

    local bind_vulnerable=0
    if [ -n "$command_result" ]; then
        local bind_value=$(echo "$command_result" | tail -n +2 | awk '{print $2}' | head -1)
        if [ "$bind_value" = "0.0.0.0" ] || [ "$bind_value" = "::" ]; then
            ((vulnerabilities_found++)) || true
            bind_vulnerable=1
            inspection_summary+="취약: bind_address가 ${bind_value}로 설정되어 모든 IP에서 접속 가능\n"
        else
            inspection_summary+=" bind_address가 ${bind_value}로 제한됨\n"
        fi
    fi

    # 2. 원격 접속 가능한 사용자 확인 (host='%' 또는 host='0.0.0.0')
    local remote_access_query="SELECT user, host FROM mysql.user WHERE host IN ('%', '0.0.0.0', '::') ORDER BY user, host;"
    command_executed+="; mysql -h "${DB_HOST}" -P "${DB_PORT}" -u "${DB_USER}" -p"${DB_PASSWORD}" -e \"${remote_access_query}\""
    local remote_result=$(mysql -h "${DB_HOST}" -P "${DB_PORT}" -u "${DB_USER}" -p"${DB_PASSWORD}" -e "${remote_access_query}" 2>/dev/null || echo "")
    command_result+=$'\n\n'$'\n'"$remote_result"

    local remote_count=0
    if [ -n "$remote_result" ]; then
        remote_count=$(echo "$remote_result" | tail -n +2 | grep -v "^$" | wc -l)
        if [ "$remote_count" -gt 0 ]; then
            ((vulnerabilities_found++)) || true
            local remote_users=$(echo "$remote_result" | tail -n +2 | grep -v "^$" | head -5 | tr '\n' ', ')
            inspection_summary+="취약: ${remote_count}개 계정이 모든 원격 호스트(%)에서 접속 가능: ${remote_users}\n"
        else
            inspection_summary+=" 모든 원격 호스트 접속 허용(%) 사용자 없음\n"
        fi
    fi

    # 3. 포트 설정 확인 (기본 3306)
    local port_query="SHOW VARIABLES LIKE 'port';"
    local port_result=$(mysql -h "${DB_HOST}" -P "${DB_PORT}" -u "${DB_USER}" -p"${DB_PASSWORD}" -e "${port_query}" 2>/dev/null || echo "")
    if [ -n "$port_result" ]; then
        local port_value=$(echo "$port_result" | tail -n +2 | awk '{print $2}' | head -1)
        inspection_summary+="정보: MySQL 포트 = ${port_value}\n"
    fi

    if [ $vulnerabilities_found -gt 0 ]; then
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="원격 접속 제한 미준수:\n${inspection_summary}"
    else
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="원격 접속이 적절하게 제한됨\n${inspection_summary}"
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
