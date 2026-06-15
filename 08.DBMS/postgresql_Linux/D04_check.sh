#!/bin/bash

# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : D-04
# @Category    : DBMS (Database Management System)
# @Platform    : postgresql_Linux
# @Severity    : 상
# @Title       : 데이터베이스 관리자 권한을 꼭 필요한 계정 및 그룹에 대해서만 허용
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

ITEM_ID="D-04"
ITEM_NAME="데이터베이스 관리자 권한을 꼭 필요한 계정 및 그룹에 대해서만 허용"
SEVERITY="상"

GUIDELINE_PURPOSE="관리자 권한이 필요한 계정과 그룹에만 관리자 권한을 부여하였는지 점검하여 관리자 권한의 남용을 방지하여 계정 유출로 인한 비인가자의 DB 접근 가능성을 최소화하고자함"
GUIDELINE_THREAT="관리자 권한이 필요한 계정 및 그룹에만 관리자 권한을 부여하지 않으면 관리자 권한이 부여된 계정이 비인가자에게 유출될 경우 DB에 접근할 수 있는 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="관리자 권한이 필요한 계정 및 그룹에만 관리자 권한이 부여된 경우"
GUIDELINE_CRITERIA_BAD="관리자 권한이 필요 없는 계정 및 그룹에 관리자 권한이 부여된 경우"
GUIDELINE_REMEDIATION="관리자 권한이 필요한 계정 및 그룹에만 관리자 권한 부여"

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

    # 관리자 권한 확인 (SUPERUSER/CREATEROLE/CREATEDB)
    # rolsuper만 보면 비-슈퍼유저의 권한 상승 권한(CREATEROLE/CREATEDB)을 놓치므로
    # Windows 진단 로직과 동일하게 관리자급 권한을 모두 포함하여 조회한다.
    local superuser_query="SELECT rolname FROM pg_roles WHERE rolsuper OR rolcreaterole OR rolcreatedb;"
    command_executed="psql -h ${DB_HOST} -p ${DB_PORT} -U ${DB_ADMIN_USER} -d postgres -c \"${superuser_query}\""
    command_result=$(PGPASSWORD="${DB_ADMIN_PASS}" psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_ADMIN_USER}" -d postgres -tAc "${superuser_query}" 2>/dev/null | grep -v '^$' || true)

    # 결과 분석
    local admin_count=0
    local nondefault_admins=""
    if [ -n "$command_result" ]; then
        # 헤더 제외하고 실제 rolname만 카운트
        admin_count=$(echo "$command_result" | grep -v "^$" | grep -v "rolname" | wc -l)
        # 기본 관리자(postgres)를 제외한 비-기본 관리자 권한 계정만 추출
        nondefault_admins=$(echo "$command_result" | grep -v "^$" | grep -v "rolname" | grep -vx "postgres" || true)
    fi

    if [ -z "$command_result" ] || [ "$admin_count" -eq 0 ]; then
        # 연결은 성공했으나 pg_roles 조회 결과가 비어 있음(쿼리 오류/권한 문제).
        # 관리자 권한 계정은 최소 postgres 1개가 반환되어야 정상이므로, 0건은 증거 미확보로 간주.
        # 양호(0개)로 오판하지 않도록 수동진단 처리.
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="관리자 권한 계정 조회 결과가 비어 있어 자동 판정이 불가합니다(쿼리 오류 가능). 수동으로 관리자 권한 부여 계정을 확인하세요."
    elif [ -z "$nondefault_admins" ]; then
        # SUPERUSER/CREATEROLE/CREATEDB 보유 계정이 기본 관리자(postgres) 뿐인 경우
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="관리자 권한(SUPERUSER/CREATEROLE/CREATEDB) 계정 ${admin_count}개 (양호 - postgres만 보유)"
    else
        # postgres 외에 관리자급 권한(SUPERUSER/CREATEROLE/CREATEDB)을 보유한 비-기본 계정 존재
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="관리자 권한(SUPERUSER/CREATEROLE/CREATEDB)이 불필요한 계정에 부여됨 (취약 - 최소화 권장): $(echo "$nondefault_admins" | tr '\n' ', ')"
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
