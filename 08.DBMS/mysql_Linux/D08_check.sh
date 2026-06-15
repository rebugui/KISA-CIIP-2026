#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-04-20
# ============================================================================
# [점검 항목 상세]
# @ID          : D-08
# @Category    : DBMS (Database Management System)
# @Platform    : mysql_Linux
# @Severity    : 상
# @Title       : 안전한 암호화 알고리즘 사용
# @Description : 안전한 암호화 알고리즘 사용 유무를 점검
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


ITEM_ID="D-08"
ITEM_NAME="안전한 암호화 알고리즘 사용"
SEVERITY="상"

GUIDELINE_PURPOSE="안전한 해시 알고리즘 사용으로 데이터의 기밀성 및 무결성을 보장하고, 사용자 인증을 강화하기 위함"
GUIDELINE_THREAT="SHA-1이나 MD5와 같은 오래된 알고리즘 사용 시 공격자의 무차별 대입 공격 등으로 비밀번호 유추가 가능하며, 데이터 변조 및 유출의 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="해시 알고리즘 SHA-256 이상의 암호화 알고리즘을 사용하고 있는 경우"
GUIDELINE_CRITERIA_BAD="해시 알고리즘 SHA-256 미만의 암호화 알고리즘을 사용하고 있는 경우"
GUIDELINE_REMEDIATION="SHA-256 이상의 암호화 알고리즘 적용"

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

    # ==========================================================================
    # 1. 기본 인증 플러그인 확인 (SHA-256 이상)
    # ==========================================================================
    local auth_plugin_query="SHOW VARIABLES LIKE 'default_authentication_plugin';"
    command_executed="mysql -e \"${auth_plugin_query}; SELECT user,host,plugin FROM mysql.user WHERE plugin IN ('mysql_native_password') AND user NOT IN ('mysql.sys','mysql.session','mysql.infoschema');\""
    local default_plugin=$(mysql -h "${DB_HOST}" -P "${DB_PORT}" -u "${DB_USER}" -p"${DB_PASSWORD}" -e "${auth_plugin_query}" 2>/dev/null | tail -n +2 | awk '{print $2}' || echo "")

    # ==========================================================================
    # 2. 기존 사용자 인증 방식 확인
    # ==========================================================================
    local weak_auth_query="SELECT user, host, plugin FROM mysql.user WHERE plugin = 'mysql_native_password' AND user NOT IN ('mysql.sys', 'mysql.session', 'mysql.infoschema', 'debian-sys-maint');"
    local weak_users=$(mysql -h "${DB_HOST}" -P "${DB_PORT}" -u "${DB_USER}" -p"${DB_PASSWORD}" -e "${weak_auth_query}" 2>/dev/null | tail -n +2 || echo "")

    local details="기본 플러그인: ${default_plugin:-확인불가}"

    if [ -n "$weak_users" ]; then
        local weak_count=$(echo "$weak_users" | grep -v "^$" | wc -l)
        details="${details}, SHA-1 인증 사용자: ${weak_count}개"
    fi

    # ==========================================================================
    # 3. 판정
    # ==========================================================================
    if [ "$default_plugin" = "caching_sha2_password" ] || [ "$default_plugin" = "sha256_password" ]; then
        # 기본 플러그인이 SHA-256 이상인 경우
        if [ -n "$weak_users" ]; then
            diagnosis_result="VULNERABLE"
            status="취약"
            inspection_summary="기본 인증은 SHA-256이나 일부 계정이 SHA-1(mysql_native_password) 사용 중: ${details}"
            command_result="${details}"$'\n'"취약 계정:"$'\n'"${weak_users}"
        else
            diagnosis_result="GOOD"
            status="양호"
            inspection_summary="모든 계정이 SHA-256 이상 해시 알고리즘 사용 중: ${details}"
            command_result="${details}"
        fi
    elif [ "$default_plugin" = "mysql_native_password" ]; then
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="기본 인증 플러그인이 SHA-1(mysql_native_password)입니다. SHA-256 이상 권장: ${details}"
        command_result="${details}"
    else
        # 플러그인 확인 불가 또는 알 수 없는 플러그인
        if [ -n "$weak_users" ]; then
            diagnosis_result="VULNERABLE"
            status="취약"
            inspection_summary="SHA-1(mysql_native_password) 사용 계정 존재: ${details}"
            command_result="${details}"$'\n'"취약 계정:"$'\n'"${weak_users}"
        elif [ -z "$default_plugin" ]; then
            # 기본 플러그인 조회 결과가 비어 있음(연결/쿼리 실패 또는 연결 헬퍼 미적재).
            # 암호화 알고리즘 증거를 확보하지 못한 상태이므로 양호로 단정하지 않고 수동진단 처리.
            diagnosis_result="MANUAL"
            status="수동진단"
            inspection_summary="기본 인증 플러그인 정보를 확인하지 못해 해시 알고리즘을 자동 판정할 수 없습니다. 수동으로 default_authentication_plugin 및 계정별 plugin 을 확인하세요: ${details}"
            command_result="${details}"
        else
            diagnosis_result="GOOD"
            status="양호"
            inspection_summary="SHA-1 미사용: ${details}"
            command_result="${details}"
        fi
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
