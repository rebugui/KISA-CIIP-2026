#!/bin/bash

# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : D-06
# @Category    : DBMS (Database Management System)
# @Platform    : postgresql_Linux
# @Severity    : 중
# @Title       : DB 사용자 계정을 개별적으로 부여하여 사용
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

ITEM_ID="D-06"
ITEM_NAME="DB 사용자 계정을 개별적으로 부여하여 사용"
SEVERITY="중"

GUIDELINE_PURPOSE="사용자별 별도 DBMS 계정을 사용하여 DB에 접근하는지 점검하여 DB 계정 공유 사용으로 발생할 수 있는 로그 감사 추적 문제를 대비하고자함"
GUIDELINE_THREAT="DB 계정을 공유하여 사용할 경우 비인가자의 DB 접근 발생 시 계정 공유 사용으로 인해 로그 감사 추적의 어려움이 발생할 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="사용자별 계정을 사용하고 있는 경우"
GUIDELINE_CRITERIA_BAD="공용 계정을 사용하고 있는 경우"
GUIDELINE_REMEDIATION="사용자별 계정 생성 및 권한 부여"

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
    local vulnerabilities_found=0

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

    # 계정별 로그인 가능한 사용자 확인
    # 개별 로그인 계정 수를 COUNT로 조회 (0행과 조회 실패를 구분하기 위해 count 사용)
    local count_query="SELECT count(*) FROM pg_roles WHERE rolcanlogin=true AND rolname NOT IN ('postgres');"
    local list_query="SELECT rolname FROM pg_roles WHERE rolcanlogin=true AND rolname NOT IN ('postgres');"
    command_executed="psql -h ${DB_HOST} -p ${DB_PORT} -U ${DB_ADMIN_USER} -d postgres -tAc \"${count_query}\""
    local indiv_count
    indiv_count=$(PGPASSWORD="${DB_ADMIN_PASS}" psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_ADMIN_USER}" -d postgres -tAc "${count_query}" 2>/dev/null | tr -d '[:space:]' || true)
    command_result=$(PGPASSWORD="${DB_ADMIN_PASS}" psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_ADMIN_USER}" -d postgres -tAc "${list_query}" 2>/dev/null | grep -v "^$" | tr '\n' ' ' || true)

    if ! printf '%s' "${indiv_count}" | grep -qE '^[0-9]+$'; then
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="수동진단: 사용자 계정 조회에 실패했습니다. 공유 계정 사용 여부를 수동으로 확인하세요."
        command_result="pg_roles 조회 실패"
    elif [ "${indiv_count}" -gt 0 ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="양호: postgres 외 개별 사용자 계정 ${indiv_count}개가 부여되어 있습니다. (${command_result})"
    else
        # 개별 로그인 계정이 없고 공용(postgres) 슈퍼유저만 존재 → 공용 계정 공유 사용 (docs D-06 criteria_bad)
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="취약: postgres 외 개별 사용자 계정이 없어 공용 계정(postgres) 공유 사용으로 판단됩니다. 사용자별 계정을 생성하여 사용하세요."
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
