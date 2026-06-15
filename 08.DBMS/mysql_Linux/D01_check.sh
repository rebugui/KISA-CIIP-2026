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
# @Platform    : mysql_Linux
# @Severity    : 상
# @Title       : 기본 계정의 비밀번호, 정책 등을 변경하여 사용
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
    local manual_accounts=()
    local check_results=""
    # 연결 가드(prompt_mysql_connection)는 `SELECT 1;`만 수행하므로 mysql.user 조회 권한을
    # 보장하지 않는다. 최소 권한 계정으로 실행 시 mysql.user 쿼리는 ERROR 1142로 실패하고
    # 빈 문자열을 반환하는데, `[ "" -gt 0 ]`는 거짓이라 GOOD로 흘러 빈 비밀번호 root/익명
    # 계정을 놓칠 수 있다. 따라서 게이트 쿼리의 종료 코드를 추적해 실패 시 MANUAL로 라우팅한다.
    local query_failed=0

    for account in "${default_accounts[@]}"; do
        # 계정 존재 여부 확인 (종료 코드 추적: 빈 결과가 0행인지 쿼리 오류인지 구분)
        local account_exists
        account_exists=$(MYSQL_PWD="${DB_ADMIN_PASS}" mysql -u"${DB_ADMIN_USER}" -h"${DB_HOST}" -P"${DB_PORT}" -se \
            "SELECT COUNT(*) FROM mysql.user WHERE user='${account}';" 2>/dev/null) || { query_failed=1; continue; }

        # 쿼리는 성공했으나 숫자가 아닌(공백 등) 출력이면 신뢰할 수 없으므로 MANUAL 처리
        if ! [[ "${account_exists}" =~ ^[0-9]+$ ]]; then
            query_failed=1
            continue
        fi

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
                # 비밀번호가 설정된 기본/테스트 계정.
                # mysql.user에는 비밀번호가 초기값에서 변경되었는지를 나타내는 신뢰 가능한 컬럼이
                # 없다(예: password_changed 컬럼은 MySQL 5.7/8.x에 존재하지 않음). 따라서 계정이
                # 존재하고 로그인 가능하다는 사실만으로 초기 비밀번호 변경 여부를 정적으로 증명할 수
                # 없으므로 자동 GOOD 판정하지 않고 수동 점검(MANUAL) 대상으로 둔다.
                manual_accounts+=("${account} (비밀번호 설정됨, 초기값 변경 여부 미확인)")
                check_results="${check_results}[수동확인] ${account}: 계정 존재 - 초기 비밀번호 변경 여부 수동 확인 필요\\n"
            fi
        fi
    done

    # 익명 사용자 확인 (종료 코드 추적: 빈 결과가 0행인지 쿼리 오류인지 구분)
    local anonymous_users
    if anonymous_users=$(MYSQL_PWD="${DB_ADMIN_PASS}" mysql -u"${DB_ADMIN_USER}" -h"${DB_HOST}" -P"${DB_PORT}" -se \
        "SELECT COUNT(*) FROM mysql.user WHERE user='';" 2>/dev/null) && [[ "${anonymous_users}" =~ ^[0-9]+$ ]]; then
        if [ "${anonymous_users}" -gt 0 ]; then
            vulnerable_accounts+=("익명 사용자 ('' user)")
            check_results="${check_results}[취약] 익명 사용자: ${anonymous_users}개 발견\\n"
        fi
    else
        # 쿼리 실패 또는 비숫자 출력 → mysql.user 조회 권한 부족 가능 → MANUAL로 라우팅
        query_failed=1
    fi

    # 최종 판정
    # 우선순위: 취약(빈 비밀번호/익명 계정 등 명백한 결함) > 수동(비밀번호가 설정된 기본
    # 계정의 초기값 변경 여부 미증명) > 양호(점검 대상 기본 계정 없음). 계정 존재 사실만으로
    # 비밀번호 변경을 증명할 수 없으므로 GOOD으로 판정하지 않는다.
    local total_vulnerabilities=${#vulnerable_accounts[@]}
    local total_manual=${#manual_accounts[@]}

    if [ ${total_vulnerabilities} -gt 0 ]; then
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="기본 계정 비밀번호 미변경: ${total_vulnerabilities}개"
        command_result="MySQL 버전: ${mysql_version}\\n취약 계정:\\n"
        for account in "${vulnerable_accounts[@]}"; do
            command_result="${command_result}- ${account}\\n"
        done
        command_result="${command_result}\\n상세:\\n${check_results}"
        command_executed="mysql -u${DB_ADMIN_USER} -p*** -h${DB_HOST} -P${DB_PORT} -e \"SELECT user, host, authentication_string FROM mysql.user;\""
    elif [ ${total_manual} -gt 0 ]; then
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="비밀번호가 설정된 기본 계정 ${total_manual}개에 대해 초기 비밀번호 변경 여부를 자동으로 증명할 수 없습니다. 해당 계정의 초기 비밀번호 변경 또는 잠금/삭제 여부를 수동으로 확인하세요."
        command_result="MySQL 버전: ${mysql_version}\\n수동 확인 필요 계정:\\n"
        for account in "${manual_accounts[@]}"; do
            command_result="${command_result}- ${account}\\n"
        done
        command_result="${command_result}\\n상세:\\n${check_results}"
        command_executed="mysql -u${DB_ADMIN_USER} -p*** -h${DB_HOST} -P${DB_PORT} -e \"SELECT user, host, authentication_string FROM mysql.user;\""
    elif [ ${query_failed} -ne 0 ]; then
        # mysql.user 조회 쿼리가 실패(권한 부족 등)하여 빈 결과가 반환됨.
        # 빈 결과를 "계정 없음(양호)"으로 오판하면 빈 비밀번호 root/익명 계정을 놓칠 수 있으므로
        # 증거 확보 불가로 보고 MANUAL로 라우팅한다.
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="mysql.user 조회 권한 부족으로 추정되어 기본/익명 계정 존재 여부를 자동으로 확인할 수 없습니다. mysql.user 조회 권한을 가진 계정으로 기본 계정(root/test) 및 익명 계정의 비밀번호 변경/잠금 여부를 수동으로 확인하세요."
        command_result="MySQL 버전: ${mysql_version}\\nmysql.user 조회 실패(권한 부족 가능)\\n${check_results}"
        command_executed="mysql -u${DB_ADMIN_USER} -p*** -h${DB_HOST} -P${DB_PORT} -e \"SELECT user, host, authentication_string FROM mysql.user;\""
    else
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="점검 대상 기본 계정(root/test) 및 익명 계정이 존재하지 않음"
        command_result="MySQL 버전: ${mysql_version}\\n${check_results}"
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
