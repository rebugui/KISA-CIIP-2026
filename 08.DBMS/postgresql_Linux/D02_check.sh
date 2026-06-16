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
# @Platform    : postgresql_Linux
# @Severity    : 상
# @Title       : 데이터베이스의 불필요 계정을 제거하거나, 잠금 설정 후 사용
# @Description : 불필요한 계정 관리 및 권한 제어를 통한 보안 강화
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

diagnose() {
    echo "진단 항목: ${ITEM_ID} - ${ITEM_NAME}"

    # FR-022: Check required tools
    if ! check_postgresql_tools; then
        handle_missing_tools "postgresql" "${ITEM_ID}" "${ITEM_NAME}" \
            "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" \
            "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
        return 0
    fi


    local diagnosis_result="GOOD"
    local status="양호"
    local inspection_summary=""
    local command_result=""
    local command_executed=""

    # Initialize PostgreSQL connection variables
    init_postgresql_vars

    # PostgreSQL 서비스 확인
    if ! check_postgresql_service; then
        handle_dbms_not_running "postgresql" "${ITEM_ID}" "${ITEM_NAME}" \
            "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" \
            "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
        return 0
    fi

    # PostgreSQL 연결 시도 (FR-018)
    if ! prompt_postgresql_connection; then
        handle_dbms_connection_failed "postgresql" "${ITEM_ID}" "${ITEM_NAME}" \
            "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" \
            "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
        return 0
    fi

    # 빈 비밀번호 계정 확인
    # pg_shadow는 슈퍼유저만 조회 가능하다. 비슈퍼유저로 조회 시 권한 오류가 발생하며,
    # 이때 stderr를 버리고 빈 결과를 "빈 비밀번호 계정 없음"으로 처리하면 점검 근거를
    # 확보하지 못했음에도 GOOD으로 오판정하게 된다. 따라서 쿼리 실행 오류(비-0 종료코드 또는
    # stderr 출력)는 "근거 확보 불가"로 보고 MANUAL로 판정하고, 오류 없이 0행이 반환된
    # 경우에만 GOOD으로 판정한다.
    local empty_password_query="SELECT usename FROM pg_catalog.pg_shadow WHERE passwd IS NULL AND usename <> current_user;"
    command_executed="psql -h ${DB_HOST} -p ${DB_PORT} -U ${DB_ADMIN_USER} -d postgres -t -c \"${empty_password_query}\""

    local query_stderr_file
    query_stderr_file=$(mktemp 2>/dev/null || echo "/tmp/d02_pg_$$.err")
    local query_status=0
    command_result=$(PGPASSWORD="${DB_ADMIN_PASS}" psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_ADMIN_USER}" -d postgres -At -c "${empty_password_query}" 2>"${query_stderr_file}") || query_status=$?
    local query_stderr=""
    if [ -f "${query_stderr_file}" ]; then
        query_stderr=$(cat "${query_stderr_file}" 2>/dev/null || echo "")
        rm -f "${query_stderr_file}" 2>/dev/null || true
    fi

    # 빈 줄 제거 후 실제 반환된 계정 행 수 계산
    local empty_pwd_users
    empty_pwd_users=$(printf '%s\n' "${command_result}" | grep -v '^[[:space:]]*$' || true)
    local user_count=0
    if [ -n "${empty_pwd_users}" ]; then
        user_count=$(printf '%s\n' "${empty_pwd_users}" | wc -l)
    fi

    # 결과 분석
    if [ "${query_status}" -ne 0 ] || [ -n "${query_stderr}" ]; then
        # 쿼리 실행 실패(예: pg_shadow 접근 권한 없음) - 점검 근거 확보 불가
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="pg_shadow 조회에 실패하여 빈 비밀번호 계정 존재 여부를 자동 점검할 수 없습니다(슈퍼유저 권한 필요 가능성). 슈퍼유저 계정으로 빈 비밀번호 및 불필요 계정 존재 여부를 수동으로 확인하세요."
        if [ -n "${query_stderr}" ]; then
            command_result="쿼리 오류: ${query_stderr}"
        else
            command_result="쿼리 실행 실패 (종료코드: ${query_status})"
        fi
    elif [ "${user_count}" -gt 0 ]; then
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="빈 비밀번호를 가진 계정 ${user_count}개 발견: $(printf '%s\n' "${empty_pwd_users}" | head -5 | tr '\n' ', ')"
        command_result="${empty_pwd_users}"
    else
        # 빈 비밀번호 계정은 없으나, 본 항목의 판정 기준(criteria_bad)은 인가되지 않은/퇴직자/
        # 테스트 등 '불필요한' 계정의 존재 여부이다. 계정의 불필요 여부는 기관의 인가 정책에
        # 의존하므로 빈 비밀번호 프록시만으로는 자동 GOOD으로 단정할 수 없다. 따라서 이 경로는
        # MANUAL로 판정하여 불필요 계정 존재 여부를 수동으로 확인하도록 한다.
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="빈 비밀번호 계정은 발견되지 않았습니다. 다만 인가되지 않은 계정, 퇴직자 계정, 테스트 계정 등 불필요한 계정의 존재 여부는 기관 인가 정책에 따라 결정되므로 자동 판정할 수 없습니다. SELECT usename FROM pg_catalog.pg_user; 결과를 검토하여 불필요한 계정이 없는지 수동으로 확인하세요."
        command_result="조회 성공: 빈 비밀번호 계정 0건 (불필요 계정 존재 여부는 수동 확인 필요)"
    fi

    save_dual_result "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" "${inspection_summary}" "${command_result}" "${command_executed}" "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
    verify_result_saved "${ITEM_ID}"

    return 0
}

main() {
    diagnose
}

if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi
