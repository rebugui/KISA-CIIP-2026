#!/bin/bash

# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : D-03
# @Category    : DBMS (Database Management System)
# @Platform    : PostgreSQL
# @Severity    : 중
# @Title       : 비밀번호 사용기간 및 복잡도를 기관의 정책에 맞도록 설정
# @Description : 비밀번호 정책 및 설정 관리를 통한 무단 접근 방지
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

ITEM_ID="D-03"
ITEM_NAME="비밀번호 사용 기간 및 복잡 도를 기관의 정책에 맞도록 설정"
SEVERITY="상"

GUIDELINE_PURPOSE="비밀번호 사용 기간 및 복잡 도 설정 유무를 점검하여 비인가자의 비밀번호 추측 공격(무차별 대입 공격, 사전 대입 공격 등)에 대한 대비가 되어 있는지 확인하기 위함"
GUIDELINE_THREAT="비밀번호 사용 기간 및 복잡 도 설정이 되어 있지 않으면 비인가자가 비밀번호 추측 공격을 통해 획득한 계정의 비밀번호를 이용하여 DB에 접근할 수 있는 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="기관 정책에 맞게 비밀번호 사용 기간 및 복잡 도 설정이 적용된 경우"
GUIDELINE_CRITERIA_BAD="기관 정책에 맞게 비밀번호 사용 기간 및 복잡 도 설정이 적용되지 않은 경우"
GUIDELINE_REMEDIATION="기관 정책에 맞게 비밀번호 사용 기간 및 복잡 도 정책 설정"

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

    # 비밀번호 암호화 방식 확인
    local password_enc_query="SHOW password_encryption;"
    command_result=$(PGPASSWORD="${DB_ADMIN_PASS}" psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_ADMIN_USER}" -d postgres -t -c "${password_enc_query}" 2>/dev/null | xargs || echo "")

    if [ -n "$command_result" ]; then
        if [ "$command_result" = "scram-sha-256" ] || [ "$command_result" = "md5" ]; then
            inspection_summary+="양호: 비밀번호 암호화 ${command_result} 사용; "
        else
            ((vulnerabilities_found++)) || true
            inspection_summary+="취약: 비밀번호 암호화가 ${command_result}로 설정됨; "
        fi
    else
        ((vulnerabilities_found++)) || true
        inspection_summary+="취약: 비밀번호 암호화 설정 확인 불가; "
    fi

    # 비밀번호 만료 정책 확인
    local password_expiry_query="SELECT rolname, rolvaliduntil FROM pg_authid WHERE rolname='postgres';"
    local expiry_result=$(PGPASSWORD="${DB_ADMIN_PASS}" psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_ADMIN_USER}" -d postgres -t -c "${password_expiry_query}" 2>/dev/null || echo "")

    if [ -n "$expiry_result" ]; then
        local has_expiry=$(echo "$expiry_result" | grep -c "infinity" || echo "0")
        if [ "$has_expiry" -gt 0 ]; then
            ((vulnerabilities_found++)) || true
            inspection_summary+="취약: postgres 계정 비밀번호 만료 기간 없음; "
        else
            inspection_summary+="양호: 비밀번호 만료 정책 설정됨; "
        fi
    fi

    # 비밀번호 복잡도 확인 (passwordcheck 확장 모듈)
    local passwordcheck_query="SELECT * FROM pg_available_extensions WHERE name='passwordcheck';"
    local passwordcheck_result=$(PGPASSWORD="${DB_ADMIN_PASS}" psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_ADMIN_USER}" -d postgres -t -c "${passwordcheck_query}" 2>/dev/null | xargs || echo "")

    if [ -z "$passwordcheck_result" ]; then
        ((vulnerabilities_found++)) || true
        inspection_summary+="취약: passwordcheck 확장 모듈 미설치; "
    else
        inspection_summary+="양호: passwordcheck 확장 모듈 설치됨; "
    fi

    if [ $vulnerabilities_found -gt 0 ]; then
        diagnosis_result="VULNERABLE"
        status="취약"
    else
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="비밀번호 정책이 적절히 설정됨"
    fi
    command_executed="psql -h ${DB_HOST} -p ${DB_PORT} -U ${DB_ADMIN_USER} -d postgres -c \"SHOW password_encryption; SELECT * FROM pg_available_extensions WHERE name='passwordcheck';\""

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
