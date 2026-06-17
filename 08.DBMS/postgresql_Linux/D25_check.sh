#!/bin/bash

# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : D-25
# @Category    : DBMS (Database Management System)
# @Platform    : postgresql_Linux
# @Severity    : 상
# @Title       : 주기적 보안 패치 및 벤더 권고 사항 적용
# @Description : 과도한 권한 부여 방지 및 최소 권한 원칙 적용
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

ITEM_ID="D-25"

ITEM_NAME="주기적 보안 패치 및 벤더 권고 사항 적용"
SEVERITY="상"
GUIDELINE_PURPOSE="안전한 버전의 데이터베이스를 사용하여 알려진 보안 취약점으로 인한 공격을 차단하기 위함"
GUIDELINE_THREAT="안전하지 않은 버전을 사용할 경우, 알려진 보안 취약점을 통해 시스템에 침투하거나 데이터의 탈취, 악성 코드 감염 및 서비스 중단 등의 보안 사고를 초래할 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="보안 패치가 적용된 버전을 사용하는 경우"
GUIDELINE_CRITERIA_BAD="보안 패치가 적용되지 않는 버전을 사용하는 경우"
GUIDELINE_REMEDIATION="보안 패치가 적용된 버전으로 업데이트"

diagnose() {
    echo "진단 항목: ${ITEM_ID} - ${ITEM_NAME}"

    # FR-022: Check required tools
    if ! check_postgresql_tools; then
        handle_missing_tools "postgresql" "${ITEM_ID}" "${ITEM_NAME}" \
            "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" \
            "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
        return 0
    fi

    init_postgresql_vars

    local diagnosis_result="MANUAL" status="수동진단" inspection_summary="PostgreSQL 버전 확인이 필요합니다. 발견된 버전을 최신 보안 패치 현황과 비교하여 수동 확인 권장 (수동진단)" command_result="" command_executed=""

    # PostgreSQL 버전 조회 시도 (증거 수집)
    command_executed="psql -h ${DB_HOST} -p ${DB_PORT} -U ${DB_ADMIN_USER} -d postgres -c \"SELECT VERSION();\""
    local db_version
    db_version=$(PGPASSWORD="${DB_ADMIN_PASS}" psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_ADMIN_USER}" -d postgres -t -c "SELECT VERSION();" 2>/dev/null || echo "")
    if [ -n "$db_version" ]; then
        command_result="$db_version"
        db_version=$(echo "$db_version" | head -1)
        inspection_summary="설치된 PostgreSQL 버전: ${db_version}. 벤더 보안 공지(권고 패치 버전) 대비 적용 여부를 수동으로 판단 필요"
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
