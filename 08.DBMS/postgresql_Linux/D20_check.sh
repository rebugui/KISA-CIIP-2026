#!/bin/bash

# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : D-20
# @Category    : DBMS (Database Management System)
# @Platform    : postgresql_Linux
# @Severity    : 하
# @Title       : 인가되지 않은 Object Owner의 제한
# @Description : 인가되지않은Object Owner의제한 관리를 통한 DBMS 보안 강화
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

ITEM_ID="D-20"
ITEM_NAME="인가되지 않은 Object Owner의 제한"
SEVERITY="하"

GUIDELINE_PURPOSE="Object Owner가 비인가자에게 존재하고 있는 경우 중요 데이터에 대한 무단 접근이 가능하여 데이터의 일관성 및 무결성을 해치는 위험이 발생할 수 있으므로 비인가된 계정의 Object Owner를 제한하여 내부 및 외부의 보안 위협을 최소화하기 위함"
GUIDELINE_THREAT="Object Owner는 SYS, SYSTEM과 같은 데이터베이스 관리자 계정과 응용 프로그램의 관리자 계정에만 존재하여야 하며, 일반 계정이 존재할 경우 공격자가 이를 이용하여 Object의 수정, 삭제가 가능하므로 중요 정보의 유출 및 변경의 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="ObjectOwner가 SYS,SYSTEM, 관리자 계정 등으로 제한된 경우"
GUIDELINE_CRITERIA_BAD="ObjectOwner가 일반 사용자에게도 존재하는 경우"
GUIDELINE_REMEDIATION="Object Owner를 SYS, SYSTEM, 관리자 계정으로 제한 설정"

# PostgreSQL 연결 정보 초기화
DB_ADMIN_USER="${DB_ADMIN_USER:-postgres}"
DB_ADMIN_PASS="${DB_ADMIN_PASS:-}"
DB_HOST="${DB_HOST:-localhost}"
DB_PORT="${DB_PORT:-5432}"

# PostgreSQL 연결 프롬프트 (FR-018)
check_postgresql_connection() {
    if [ -z "${DB_ADMIN_PASS}" ] && [ -t 0 ]; then
        echo "[INFO] PostgreSQL 연결 정보 입력이 필요합니다."
        read -p "PostgreSQL Host [${DB_HOST}]: " input_host
        DB_HOST="${input_host:-$DB_HOST}"

        read -p "PostgreSQL Port [${DB_PORT}]: " input_port
        DB_PORT="${input_port:-$DB_PORT}"

        read -p "PostgreSQL Username [${DB_ADMIN_USER}]: " input_user
        DB_ADMIN_USER="${input_user:-$DB_ADMIN_USER}"

        read -s -p "PostgreSQL Password: " input_pass
        echo ""
        DB_ADMIN_PASS="${input_pass}"
    fi

    # 3회 재시도 로직
    local retry_count=0
    local max_retries=3

    while [ $retry_count -lt $max_retries ]; do
        # Try Unix socket connection first (peer authentication in Docker)
        if psql -U "${DB_ADMIN_USER}" -d postgres -c "SELECT 1;" &>/dev/null; then
            echo "[INFO] PostgreSQL 연결 성공 (Unix socket)"
            export DB_ADMIN_USER DB_ADMIN_PASS DB_HOST DB_PORT
            return 0
        fi

        # Fall back to TCP connection with password
        if PGPASSWORD="${DB_ADMIN_PASS}" psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_ADMIN_USER}" -d postgres -c "SELECT 1;" &>/dev/null; then
            echo "[INFO] PostgreSQL 연결 성공 (TCP)"
            export DB_ADMIN_USER DB_ADMIN_PASS DB_HOST DB_PORT
            return 0
        fi

        ((retry_count++)) || true
        if [ $retry_count -lt $max_retries ]; then
            echo "[WARN] PostgreSQL 연결 실패 (${retry_count}/${max_retries}). 2초 후 재시도..."
            sleep 2
        fi
    done

    return 1
}

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

    if ! pg_isready -h "${DB_HOST}" -p "${DB_PORT}" &>/dev/null; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="PostgreSQL 서비스 미실행"
        save_dual_result "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" "${inspection_summary}" "${command_result}" "${command_executed}" "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
        verify_result_saved "${ITEM_ID}"
        return 0
    fi

    # 비슈퍼유저가 소유한 객체 확인 (KISA 가이드라인 참조)
    local object_owner_query="SELECT DISTINCT relowner::regrole as owner, COUNT(*) as object_count FROM pg_class WHERE relowner NOT IN (SELECT usesysid FROM pg_user WHERE usesuper = TRUE) AND relkind IN ('r', 'v', 'm', 'f', 'p') GROUP BY relowner ORDER BY object_count DESC LIMIT 20;"
    command_executed="psql -h ${DB_HOST} -p ${DB_PORT} -U ${DB_ADMIN_USER} -d postgres -c \"${object_owner_query}\""

    # Try Unix socket connection first (peer authentication in Docker)
    command_result=$(psql -U "${DB_ADMIN_USER}" -d postgres -c "${object_owner_query}" 2>/dev/null || echo "")

    # Fall back to TCP connection with password
    if [ -z "$command_result" ]; then
        command_result=$(PGPASSWORD="${DB_ADMIN_PASS}" psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_ADMIN_USER}" -d postgres -c "${object_owner_query}" 2>/dev/null || echo "")
    fi

    local non_superuser_objects=0
    local non_superuser_owners=""

    if [ -n "$command_result" ]; then
        non_superuser_objects=$(echo "$command_result" | grep -v "^$" | grep -v "^--" | grep -v "^owner" | grep -v "^[(]" | grep -v "^-" | wc -l)
        non_superuser_owners=$(echo "$command_result" | grep -v "^$" | grep -v "^--" | grep -v "^owner" | grep -v "^[(]" | grep -v "^-" || echo "")
    fi

    if [ "$non_superuser_objects" -gt 0 ]; then
        ((vulnerabilities_found++)) || true
        local sample_owners=$(echo "$non_superuser_owners" | head -5 | tr '\n' ', ' || echo "")
        inspection_summary="취약: 비슈퍼유저가 소유한 ${non_superuser_objects}개 객체 소유자 발견: ${sample_owners}\n"
        inspection_summary+="\n조치 방법:\n"
        inspection_summary+="1. 객체 소유자를 postgres 또는 슈퍼유저로 변경:\n"
        inspection_summary+="   ALTER TABLE table_name OWNER TO postgres;\n"
        inspection_summary+="   ALTER VIEW view_name OWNER TO postgres;\n"
        inspection_summary+="   ALTER FUNCTION func_name(...) OWNER TO postgres;\n"
        inspection_summary+="2. REVOKE CONNECT를 통해 불필요한 스키마 접근 제한:\n"
        inspection_summary+="   REVOKE CONNECT ON DATABASE database_name FROM non_admin_user;"
    else
        inspection_summary="양호: 모든 객체가 슈퍼유저(postgres 또는 usesuper=true 계정)가 소유\n"
        inspection_summary+="확인된 객체: 전체 확인 완료"
    fi

    if [ $vulnerabilities_found -gt 0 ]; then
        diagnosis_result="VULNERABLE"
        status="취약"
    else
        diagnosis_result="GOOD"
        status="양호"
    fi

    save_dual_result "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" "${inspection_summary}" "${command_result}" "${command_executed}" "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
    verify_result_saved "${ITEM_ID}"

    return 0
}

main() {
    # PostgreSQL 연결 확인 (FR-018)
    if ! check_postgresql_connection; then
        diagnosis_result="MANUAL"
        status="수동진단"
        save_dual_result "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" \
            "PostgreSQL 연결 실패 - 데이터베이스 관리자 비밀번호 확인 필요" \
            "연결 실패: User=${DB_ADMIN_USER}, Host=${DB_HOST}:${DB_PORT}" \
            "psql -U ${DB_ADMIN_USER} -h ${DB_HOST} -p ${DB_PORT} -d postgres" \
            "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" \
            "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
        return 1
    fi

    diagnose
}

if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi
