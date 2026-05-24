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
# @Platform    : PostgreSQL
# @Severity    : 상
# @Title       : 기본계정의 비밀번호, 정책 등을 변경하여 사용
# @Description : DBMS 기본 계정의 초기 비밀번호 및 권한 정책 변경 사용 유무 점검
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

# 데이터베이스 연결 정보
DB_ADMIN_USER="${DB_ADMIN_USER:-postgres}"
DB_ADMIN_PASS="${DB_ADMIN_PASS:-}"
DB_HOST="${DB_HOST:-localhost}"
DB_PORT="${DB_PORT:-5432}"

# ============================================================================
# 유틸리티 함수
# ============================================================================

# PostgreSQL 연결 확인
check_postgresql_connection() {
    local max_attempts=3
    local attempt=1

    while [ $attempt -le $max_attempts ]; do
        # Try Unix socket connection first (peer authentication in Docker)
        if psql -U "${DB_ADMIN_USER}" -d postgres -c "SELECT 1;" &>/dev/null; then
            echo "[INFO] Unix socket 연결 성공 (peer 인증)"
            return 0
        fi

        # Fall back to TCP connection with password
        if PGPASSWORD="${DB_ADMIN_PASS}" psql -U "${DB_ADMIN_USER}" -h "${DB_HOST}" -p "${DB_PORT}" -d postgres -c "SELECT 1;" &>/dev/null; then
            echo "[INFO] TCP 연결 성공 (password 인증)"
            return 0
        fi

        echo "[WARN] PostgreSQL 연결 실패 (시도 $attempt/$max_attempts)"
        attempt=$((attempt + 1))
        sleep 2
    done

    return 1
}

# ============================================================================
# 진단 함수
# ============================================================================

diagnose() {
    diagnosis_result="unknown"  # Changed from local to global for main() access

    # FR-022: Check required tools
    if ! check_postgresql_tools; then
        handle_missing_tools "postgresql" "${ITEM_ID}" "${ITEM_NAME}" \
            "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" \
            "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
        return 0
    fi

    local status="미진단"
    local inspection_summary=""
    local command_result=""
    local command_executed=""

    echo "[INFO] PostgreSQL 기본 계정 비밀번호 점검 시작..."

    # PostgreSQL 연결 확인
    if ! check_postgresql_connection; then
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="PostgreSQL 연결 실패 - 데이터베이스 관리자 비밀번호 확인 필요"
        command_result="연결 실패: User=${DB_ADMIN_USER}, Host=${DB_HOST}:${DB_PORT}"
        command_executed="psql -U ${DB_ADMIN_USER} -h ${DB_HOST} -p ${DB_PORT} -d postgres -c \"SELECT 1;\""

        save_dual_result "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" \
            "${inspection_summary}" "${command_result}" "${command_executed}" \
            "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" \
            "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
        return 1
    fi

    echo "[INFO] PostgreSQL 연결 성공"

    # PostgreSQL 버전 확인
    local pg_version=$(psql -U "${DB_ADMIN_USER}" -d postgres -t -c "SELECT version();" 2>/dev/null | head -1)
    if [ -z "$pg_version" ]; then
        pg_version=$(PGPASSWORD="${DB_ADMIN_PASS}" psql -U "${DB_ADMIN_USER}" -h "${DB_HOST}" -p "${DB_PORT}" -d postgres -t -c "SELECT version();" 2>/dev/null | head -1)
    fi
    echo "[INFO] PostgreSQL 버전: ${pg_version}"

    # 기본 계정 목록 (postgres 등)
    local default_accounts=("postgres")
    local vulnerable_accounts=()
    local secure_accounts=()
    local check_results=""

    for account in "${default_accounts[@]}"; do
        # pg_shadow에서 계정 정보 확인 (try Unix socket first)
        local account_info=$(psql -U "${DB_ADMIN_USER}" -d postgres -t -A -F"," -c \
            "SELECT usename, usepasswd, valuntil, useconfig FROM pg_shadow WHERE usename='${account}';" 2>/dev/null)

        # Fall back to TCP if Unix socket fails
        if [ -z "$account_info" ]; then
            account_info=$(PGPASSWORD="${DB_ADMIN_PASS}" psql -U "${DB_ADMIN_USER}" -h "${DB_HOST}" -p "${DB_PORT}" -d postgres -t -A -F"," -c \
                "SELECT usename, usepasswd, valuntil, useconfig FROM pg_shadow WHERE usename='${account}';" 2>/dev/null)
        fi

        if [ -n "$account_info" ]; then
            echo "[INFO] 계정 발견: ${account}"

            # usepasswd: '********' (비밀번호 있음) 또는 NULL (비밀번호 없음)
            local usepasswd=$(echo "$account_info" | cut -d',' -f2)

            if [ "$usepasswd" = "" ] || [ "$usepasswd" = "NULL" ]; then
                vulnerable_accounts+=("${account} (비밀번호 미설정)")
                check_results="${check_results}[취약] ${account}: 비밀번호 미설정\\n"
            else
                # 비밀번호 만료일 확인
                local valuntil=$(echo "$account_info" | cut -d',' -f3)

                if [ "$valuntil" = "" ] || [ "$valuntil" = "NULL" ] || [ "$valuntil" = "infinity" ]; then
                    # 비밀번호 만료일 없음 - 기본 설정 가능성
                    # 추가 확인: 비밀번호 변경일 확인 (PostgreSQL에 password_changed 필드는 없음)
                    # connlimit 확인
                    local connlimit=$(psql -U "${DB_ADMIN_USER}" -d postgres -t -c \
                        "SELECT rolconnlimit FROM pg_roles WHERE rolname='${account}';" 2>/dev/null | xargs)

                    if [ -z "$connlimit" ]; then
                        connlimit=$(PGPASSWORD="${DB_ADMIN_PASS}" psql -U "${DB_ADMIN_USER}" -h "${DB_HOST}" -p "${DB_PORT}" -d postgres -t -c \
                            "SELECT rolconnlimit FROM pg_roles WHERE rolname='${account}';" 2>/dev/null | xargs)
                    fi

                    if [ "$connlimit" = "-1" ] || [ "$connlimit" = "0" ]; then
                        # 기본 설정 - 비밀번호 변경 여부 확인 불가, 정책 확인 필요
                        secure_accounts+=("${account}")
                        check_results="${check_results}[양호] ${account}: 비밀번호 설정됨 (만료일 없음)\\n"
                    else
                        secure_accounts+=("${account}")
                        check_results="${check_results}[양호] ${account}: 비밀번호 설정됨\\n"
                    fi
                else
                    secure_accounts+=("${account}")
                    check_results="${check_results}[양호] ${account}: 비밀번호 설정됨 (만료일: ${valuntil})\\n"
                fi
            fi
        fi
    done

    # password_encryption 정책 확인
    local password_encryption=$(psql -U "${DB_ADMIN_USER}" -d postgres -t -c \
        "SHOW password_encryption;" 2>/dev/null | xargs)

    if [ -z "$password_encryption" ]; then
        password_encryption=$(PGPASSWORD="${DB_ADMIN_PASS}" psql -U "${DB_ADMIN_USER}" -h "${DB_HOST}" -p "${DB_PORT}" -d postgres -t -c \
            "SHOW password_encryption;" 2>/dev/null | xargs)
    fi

    check_results="${check_results}[정보] password_encryption: ${password_encryption}\\n"

    # 최종 판정
    local total_vulnerabilities=${#vulnerable_accounts[@]}

    if [ ${total_vulnerabilities} -eq 0 ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="모든 기본 계정의 비밀번호가 적절히 설정됨"
        command_result="PostgreSQL 버전: ${pg_version}\\n${check_results}"
        command_executed="psql -U ${DB_ADMIN_USER} -h ${DB_HOST} -p ${DB_PORT} -d postgres -c \"SELECT usename, usepasswd FROM pg_shadow;\""
    else
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="기본 계정 비밀번호 미변경: ${total_vulnerabilities}개"
        command_result="PostgreSQL 버전: ${pg_version}\\n취약 계정:\\n"
        for account in "${vulnerable_accounts[@]}"; do
            command_result="${command_result}- ${account}\\n"
        done
        command_result="${command_result}\\n상세:\\n${check_results}"
        command_executed="psql -U ${DB_ADMIN_USER} -h ${DB_HOST} -p ${DB_PORT} -d postgres -c \"SELECT usename, usepasswd FROM pg_shadow;\""
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

    # PostgreSQL 비밀번호 입력 프롬프트 (배치 모드에서는 건너뜀)
    # Docker 환경에서는 peer 인증을 사용하므로 비밀번호 불필요
    if [ -z "${DB_ADMIN_PASS}" ] && [ -t 0 ]; then
        echo -n "PostgreSQL 관리자(${DB_ADMIN_USER}) 비밀번호 입력: "
        read -s DB_ADMIN_PASS
        echo ""
        export DB_ADMIN_PASS
    fi

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
