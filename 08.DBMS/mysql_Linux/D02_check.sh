#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : D-02
# @Category    : DBMS (Database Management System)
# @Platform    : mysql_Linux
# @Severity    : 상
# @Title       : 데이터베이스의 불필요 계정을 제거하거나, 잠금 설정 후 사용
# @Description : 불필요한 계정 존재 유무를 점검하여 비인가자의 DB 접근에 대비되어 있는지 확인
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


ITEM_ID="D-02"
ITEM_NAME="데이터베이스의 불필요 계정을 제거하거나, 잠금 설정 후 사용"
SEVERITY="상"

GUIDELINE_PURPOSE="불필요한 계정 존재 유무를 점검하여 불필요한 계정 정보(비밀번호)의 유출 시 발생할 수 있는 비인가자의 DB 접근에 대비되어 있는지 확인하기 위함"
GUIDELINE_THREAT="DB 관리나 운용에 사용하지 않는 불필요한 계정이 존재할 경우, 비인가자가 불필요한 계정을 이용하여 DB에 접근하여 데이터를 열람, 삭제, 수정할 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="계정 정보를 확인하여 불필요한 계정이 없는 경우"
GUIDELINE_CRITERIA_BAD="인가되지 않은 계정, 퇴직자 계정, 테스트 계정 등 불필요한 계정이 존재하는 경우"
GUIDELINE_REMEDIATION="계정별 용도를 파악한 후 불필요한 계정 삭제"

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

    # 불필요한 계정 확인 (test 계정, 데모 계정 등)
    # 가이드 항목명: "제거하거나, 잠금 설정 후 사용" → account_locked='Y' 행은 적격(양호).
    # MySQL 5.7+/8.x는 mysql.user.account_locked 컬럼 보유. MariaDB / MySQL 5.6은 미보유 → 폴백.
    # 연결 가드를 통과한 후이므로, 빈 결과는 "0행"이 아니라 쿼리 오류(권한 부족 등)를 의미함.
    local unused_accounts_query="SELECT user, host, account_locked FROM mysql.user WHERE user IN ('test', 'guest', 'demo', 'anonymous', '');"
    command_executed="mysql -h ${DB_HOST} -P ${DB_PORT} -u ${DB_USER} -p*** -e \"${unused_accounts_query}\""
    local query_ok=1
    local has_locked_col=1
    command_result=$(mysql -h "${DB_HOST}" -P "${DB_PORT}" -u "${DB_USER}" -p"${DB_PASSWORD}" -e "${unused_accounts_query}" 2>/dev/null) || query_ok=0

    # account_locked 컬럼이 없는 경우(MariaDB / MySQL 5.6) 폴백 쿼리 재시도
    if [ "$query_ok" -eq 0 ]; then
        local fallback_query="SELECT user, host FROM mysql.user WHERE user IN ('test', 'guest', 'demo', 'anonymous', '');"
        local fb_result
        fb_result=$(mysql -h "${DB_HOST}" -P "${DB_PORT}" -u "${DB_USER}" -p"${DB_PASSWORD}" -e "${fallback_query}" 2>/dev/null) && {
            query_ok=1
            has_locked_col=0
            command_result="$fb_result"
            command_executed="mysql -h ${DB_HOST} -P ${DB_PORT} -u ${DB_USER} -p*** -e \"${fallback_query}\""
        } || true
    fi

    # 결과 분석
    if [ "$query_ok" -eq 0 ]; then
        # 쿼리 자체가 실패함 → 자동 판단 불가
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="쿼리 결과 확인 불가 - 권한 부족 가능. mysql.user 조회 권한으로 불필요 계정 존재 여부 수동 확인 필요"
    elif [ -n "$command_result" ]; then
        local total_rows
        total_rows=$(echo "$command_result" | tail -n +2 | grep -v "^$" | wc -l)

        if [ "$total_rows" -le 0 ]; then
            # 쿼리는 성공했고 0행 → 불필요 계정 없음(양호). absence=good.
            diagnosis_result="GOOD"
            status="양호"
            inspection_summary="불필요한 계정 없음"
        elif [ "$has_locked_col" -eq 1 ]; then
            # MySQL 5.7+/8.x: account_locked 컬럼 기반 판정
            # 3번째 필드(탭 구분)가 'Y'가 아닌 행만 취약으로 집계 (잠금된 계정은 양호)
            local unlocked_rows
            unlocked_rows=$(echo "$command_result" | tail -n +2 | grep -v "^$" \
                | awk -F'\t' 'NF<3 || $3 != "Y"' || true)
            local unlocked_count
            unlocked_count=$(echo "$unlocked_rows" | grep -v "^$" | wc -l)

            if [ "$unlocked_count" -gt 0 ]; then
                ((vulnerabilities_found++)) || true
                diagnosis_result="VULNERABLE"
                status="취약"
                inspection_summary="잠금되지 않은 불필요 계정 ${unlocked_count}개 발견 (account_locked!='Y'): $(echo "$unlocked_rows" | head -5 | tr '\n' ', ')"
            else
                # 모든 해당 행이 account_locked='Y' → 가이드의 "잠금 설정 후 사용" 적격 → 양호
                diagnosis_result="GOOD"
                status="양호"
                inspection_summary="불필요 계정명이 ${total_rows}개 존재하나 모두 잠금 상태(account_locked='Y') - 가이드의 '잠금 설정 후 사용' 적격"
            fi
        else
            # MariaDB / MySQL 5.6: account_locked 컬럼이 없어 자동 잠금 여부 확인 불가 → 수동
            diagnosis_result="MANUAL"
            status="수동진단"
            inspection_summary="불필요 계정명 ${total_rows}개 존재. 본 DB 엔진은 account_locked 컬럼이 없어 잠금 여부 자동 확인 불가. 계정별 잠금/삭제 여부 수동 확인 필요: $(echo "$command_result" | tail -n +2 | head -5 | tr '\n' ', ')"
        fi
    else
        # 헤더조차 없는 공백 출력 → 쿼리 결과 확인 불가
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="쿼리 결과 확인 불가 - 권한 부족 가능. mysql.user 조회 권한으로 불필요 계정 존재 여부 수동 확인 필요"
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
