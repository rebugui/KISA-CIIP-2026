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
# @Platform    : postgresql_Linux
# @Severity    : 상
# @Title       : DBA 이외의 인가되지 않은 사용자가 시스템 테이블에 접근할 수 없도록 설정
# @Description : 불필요한 접속 경로 제한 및 접근 통제
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

diagnose() {
    echo "진단 항목: ${ITEM_ID} - ${ITEM_NAME}"

    # FR-022: Check required tools
    if ! check_postgresql_tools; then
        handle_missing_tools "postgresql" "${ITEM_ID}" "${ITEM_NAME}" \
            "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" \
            "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
        return 0
    fi

    local diagnosis_result="GOOD" status="양호" inspection_summary="" command_result="" command_executed=""

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

    # PostgreSQL에서 시스템 카탈로그 접근 권한 확인
    # pg_catalog 스키마의 테이블에 대한 권한 확인
    local priv_query="SELECT grantee, privilege_type FROM information_schema.role_table_grants WHERE table_schema='pg_catalog' AND table_name IN ('pg_user', 'pg_roles', 'pg_shadow') AND grantee!='PUBLIC';"
    command_executed="psql -h ${DB_HOST} -p ${DB_PORT} -U ${DB_ADMIN_USER} -d postgres -c \"${priv_query}\""
    command_result=$(PGPASSWORD="${DB_ADMIN_PASS}" psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_ADMIN_USER}" -d postgres -c "${priv_query}" 2>/dev/null || echo "")

    # 시스템 카탈로그에 대한 과도한 권한 확인
    local excess_priv_query="SELECT grantee, table_name, privilege_type FROM information_schema.role_table_grants WHERE table_schema='pg_catalog' AND grantee NOT IN ('postgres', 'PUBLIC') AND privilege_type IN ('INSERT', 'UPDATE', 'DELETE', 'TRUNCATE', 'REFERENCES', 'TRIGGER');"
    # -tAc: tuples-only/unaligned/footer 없음 → 0행을 진짜 빈 출력으로 만들어 (0 rows)/구분선 오탐 방지
    # stderr 를 별도 캡처하고 psql 종료코드를 확인하여, 권한 거부/쿼리 오류로 인한 빈 결과를
    # "과도한 권한 없음(양호)"으로 오판하지 않도록 한다. (정상적인 0행 = 양호, 쿼리 실패 = 수동진단)
    local excess_priv_err
    excess_priv_err=$(mktemp 2>/dev/null || echo "/tmp/d11_pg_err.$$")
    local excess_priv_raw query_rc=0
    excess_priv_raw=$(PGPASSWORD="${DB_ADMIN_PASS}" psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_ADMIN_USER}" -d postgres -tAc "${excess_priv_query}" 2>"${excess_priv_err}") || query_rc=$?
    local excess_priv_result
    excess_priv_result=$(printf '%s\n' "${excess_priv_raw}" | grep -v '^$' || true)
    local query_stderr=""
    [ -f "${excess_priv_err}" ] && query_stderr="$(cat "${excess_priv_err}" 2>/dev/null || true)"
    rm -f "${excess_priv_err}" 2>/dev/null || true
    command_result="${excess_priv_result:-pg_catalog에 DBA 외 과도한 권한 없음}"

    if [ "${query_rc}" -ne 0 ]; then
        # 연결은 성공했으나 권한 카탈로그 조회 자체가 실패(권한 거부/오류) → 증거 미확보 → 수동진단
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="시스템 테이블 권한 조회에 실패하여 자동 판정이 불가합니다(권한 거부/쿼리 오류 가능). 수동으로 pg_catalog 접근 권한을 확인하세요."
        command_result="쿼리 오류: ${query_stderr:-information_schema.role_table_grants 조회 실패}"
    elif [ -n "$excess_priv_result" ]; then
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="취약: DBA 외 사용자가 시스템 테이블(pg_catalog)에 과도한 권한 보유: $(echo "$excess_priv_result" | tr '\n' '; ')"
    else
        # docs D-11 criteria_good: DBA 외 인가되지 않은 사용자의 시스템 테이블 접근이 제한된 경우
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="양호: pg_catalog 시스템 테이블에 대한 DBA 외 사용자의 과도한 쓰기 권한이 없습니다."
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
