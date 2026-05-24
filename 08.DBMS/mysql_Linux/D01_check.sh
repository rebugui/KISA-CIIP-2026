#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : D-01
# @Category    : DBMS (Database Management System)
# @Platform    : MySQL
# @Severity    : 상
# @Title       : 기본계정의 비밀번호, 정책 등을 변경하여 사용
# @Description : DBMS 기본 계정의 초기 비밀번호 및 권한 정책 변경 사용 유무를 점검
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

# ============================================================================
# 변수 설정
# ============================================================================

ITEM_ID="D-01"
ITEM_NAME="기본 계정의 비밀번호, 정책 등을 변경하여 사용"
SEVERITY="상"

# 가이드라인 정보
GUIDELINE_PURPOSE="DBMS 기본 계정의 초기 비밀번호 및 권한 정책 변경 사용 유무를 점검하여 비인가자의 초기 비밀번호 대입 공격을 차단하고 있는지 확인하기 위함"
GUIDELINE_THREAT="DBMS 기본 계정 초기 비밀번호 및 권한 정책을 변경하지 않을 경우 비인가자가 인터넷 통해 DBMS 기본 계정의 초기 비밀번호를 획득하여 초기 비밀번호를 그대로 사용하고 있는 DB에 접근하여 기본 계정에 부여된 권한의 취약점을 이용하여 DB 정보를 유출할 수 있는 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="기본 계정의 초기 비밀번호를 변경하거나 잠금 설정한 경우"
GUIDELINE_CRITERIA_BAD="기본 계정의 초기 비밀번호를 변경하지 않거나 잠금 설정을 하지 않은 경우"
GUIDELINE_REMEDIATION="기본(관리자)계정의 초기 비밀번호 및 권한 정책 변경"

# MySQL 연결 정보 초기화 (fallback if library not loaded)
DB_USER="${DB_USER:-root}"
DB_PASSWORD="${DB_PASSWORD:-}"
DB_HOST="${DB_HOST:-localhost}"
DB_PORT="${DB_PORT:-3306}"
DB_ADMIN_USER="${DB_ADMIN_USER:-${DB_USER}}"
DB_ADMIN_PASS="${DB_ADMIN_PASS:-${DB_PASSWORD}}"

# ============================================================================
# 진단 함수
# ============================================================================

diagnose() {
    # Initialize MySQL connection variables (only if library function exists)
    if declare -f init_mysql_vars >/dev/null 2>&1; then
        init_mysql_vars
    fi

    # Set DB_ADMIN_* from DB_* for compatibility with existing code
    DB_ADMIN_USER="${DB_ADMIN_USER:-${DB_USER}}"
    DB_ADMIN_PASS="${DB_ADMIN_PASS:-${DB_PASSWORD}}"
    export DB_ADMIN_USER DB_ADMIN_PASS

    diagnosis_result="unknown"  # Changed from local to global

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

    local status="미진단"
    local inspection_summary=""
    local command_result=""
    local command_executed=""

    echo "[INFO] MySQL 기본 계정 비밀번호 점검 시작..."

    # MySQL 서비스 확인
    if ! check_mysql_service; then
        handle_dbms_not_running "mysql" "${ITEM_ID}" "${ITEM_NAME}" \
            "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" \
            "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
        return 1
    fi

    # MySQL 연결 확인
    if ! prompt_mysql_connection; then
        handle_dbms_connection_failed "mysql" "${ITEM_ID}" "${ITEM_NAME}" \
            "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" \
            "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
        return 1
    fi

    echo "[INFO] MySQL 연결 성공"

    # MySQL 버전 확인
    local mysql_version=$(MYSQL_PWD="${DB_ADMIN_PASS}" mysql -u"${DB_ADMIN_USER}" -h"${DB_HOST}" -P"${DB_PORT}" -se "SELECT VERSION();" 2>/dev/null)
    echo "[INFO] MySQL 버전: ${mysql_version}"

    # 기본 계정 목록 (root, test 등)
    local default_accounts=("root" "test")
    local vulnerable_accounts=()
    local secure_accounts=()
    local check_results=""

    for account in "${default_accounts[@]}"; do
        # 계정 존재 여부 확인
        local account_exists=$(MYSQL_PWD="${DB_ADMIN_PASS}" mysql -u"${DB_ADMIN_USER}" -h"${DB_HOST}" -P"${DB_PORT}" -se \
            "SELECT COUNT(*) FROM mysql.user WHERE user='${account}';" 2>/dev/null)

        if [ "${account_exists}" -gt 0 ]; then
            echo "[INFO] 계정 발견: ${account}"

            # 비밀번호가 비어있는지 확인
            local empty_password=$(MYSQL_PWD="${DB_ADMIN_PASS}" mysql -u"${DB_ADMIN_USER}" -h"${DB_HOST}" -P"${DB_PORT}" -se \
                "SELECT COUNT(*) FROM mysql.user WHERE user='${account}' AND (authentication_string='' OR authentication_string IS NULL);" 2>/dev/null)

            # MySQL 5.7 이전 버전에서는 password 필드 확인
            if [[ "${mysql_version}" < "5.7" ]]; then
                empty_password=$(MYSQL_PWD="${DB_ADMIN_PASS}" mysql -u"${DB_ADMIN_USER}" -h"${DB_HOST}" -P"${DB_PORT}" -se \
                    "SELECT COUNT(*) FROM mysql.user WHERE user='${account}' AND (password='' OR password IS NULL);" 2>/dev/null)
            fi

            if [ "${empty_password}" -gt 0 ]; then
                vulnerable_accounts+=("${account} (비밀번호 미설정)")
                check_results="${check_results}[취약] ${account}: 비밀번호 미설정\\n"
            else
                # 비밀번호 변경일 확인 (MySQL 5.7+)
                local password_changed=$(MYSQL_PWD="${DB_ADMIN_PASS}" mysql -u"${DB_ADMIN_USER}" -h"${DB_HOST}" -P"${DB_PORT}" -se \
                    "SELECT password_changed FROM mysql.user WHERE user='${account}';" 2>/dev/null || echo "unknown")

                if [ "${password_changed}" = "Y" ] || [ "${password_changed}" != "N" ]; then
                    secure_accounts+=("${account}")
                    check_results="${check_results}[양호] ${account}: 비밀번호 변경됨\\n"
                else
                    vulnerable_accounts+=("${account} (초기 비밀번호 의심)")
                    check_results="${check_results}[취약] ${account}: 초기 비밀번호 의심\\n"
                fi
            fi
        fi
    done

    # 익명 사용자 확인
    local anonymous_users=$(MYSQL_PWD="${DB_ADMIN_PASS}" mysql -u"${DB_ADMIN_USER}" -h"${DB_HOST}" -P"${DB_PORT}" -se \
        "SELECT COUNT(*) FROM mysql.user WHERE user='';" 2>/dev/null)

    if [ "${anonymous_users}" -gt 0 ]; then
        vulnerable_accounts+=("익명 사용자 ('' user)")
        check_results="${check_results}[취약] 익명 사용자: ${anonymous_users}개 발견\\n"
    fi

    # 최종 판정
    local total_vulnerabilities=${#vulnerable_accounts[@]}

    if [ ${total_vulnerabilities} -eq 0 ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="모든 기본 계정의 비밀번호가 적절히 설정됨"
        command_result="MySQL 버전: ${mysql_version}\\n${check_results}"
        command_executed="mysql -u${DB_ADMIN_USER} -p*** -h${DB_HOST} -P${DB_PORT} -e \"SELECT user, host, authentication_string FROM mysql.user;\""
    else
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="기본 계정 비밀번호 미변경: ${total_vulnerabilities}개"
        command_result="MySQL 버전: ${mysql_version}\\n취약 계정:\\n"
        for account in "${vulnerable_accounts[@]}"; do
            command_result="${command_result}- ${account}\\n"
        done
        command_result="${command_result}\\n상세:\\n${check_results}"
        command_executed="mysql -u${DB_ADMIN_USER} -p*** -h${DB_HOST} -P${DB_PORT} -e \"SELECT user, host, authentication_string FROM mysql.user;\""
    fi

    save_dual_result "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" \
        "${inspection_summary}" "${command_result}" "${command_executed}" \
        "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" \
        "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"

    return 0
}

# ============================================================================
# 메인 실행
# ============================================================================

main() {
    show_diagnosis_start "${ITEM_ID}" "${ITEM_NAME}"

    # 디스크 공간 확인
    check_disk_space

    # 진단 수행
    if diagnose; then
        show_diagnosis_complete "${ITEM_ID}" "${diagnosis_result}"
    else
        show_diagnosis_complete "${ITEM_ID}" "MANUAL"
    fi

    return 0
}

# 스크립트 직접 실행 시에만 진단 수행
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi
