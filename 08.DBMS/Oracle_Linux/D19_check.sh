#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : D-19
# @Category    : DBMS (Database Management System)
# @Platform    : Oracle_Linux
# @Severity    : 상
# @Title       : OS_ROLES, REMOTE_OS_AUTHENTICATION, REMOTE_OS_ROLES를 FALSE로 설정
# @Description : OS_ROLES, REMOTE_OS_AUTHENTICATION, REMOTE_OS_ROLES 설정 점검
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
source "${LIB_DIR}/dbms_connector.sh"
source "${LIB_DIR}/db_connection_helpers.sh"

ITEM_ID="D-19"

ITEM_NAME="OS_ROLES, REMOTE_OS_AUTHENTICATION, REMOTE_OS_ROLES를 FALSE로 설정"
SEVERITY="상"

GUIDELINE_PURPOSE="OS_ROLES, REMOTE_OS_AUTHENTICATION, REMOTE_OS_ROLES의 설정을 점검하여 비인가자들의 데이터베이스 접근을 막고 데이터베이스 관리자에 의한 사용자 Role 설정이 가능하게 하기 위함"
GUIDELINE_THREAT="OS_ROLES가 TRUE로 설정된 경우, 데이터베이스 접근 제어로 컨트롤되지 않는 OS 그룹에 의해 GRANT된 권한이 허락되어 악의적인 사용자가 시스템 권한을 악용할 위험이 존재 REMOTE_OS_ROLES가 TRUE로 설정된 경우, 원격 사용자가 OS의 다른 사용자로 속여 데이터베이스에 접근할 수 있으므로 중요 정보에 대한 무단 접근 및 권한 상승의 위험이 존재함 REMOTE_OS_AUTHENT가 TRUE로 설정된 경우, 신뢰하는 원격 호스트에서 인증 절차 없이 데이터베이스에 접속할 수 있으므로 중요 정보의 유출 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="OS_ROLES, REMOTE_OS_AUTHENTICATION, REMOTE_OS_ROLES 설정이 FALSE로 설정된 경우"
GUIDELINE_CRITERIA_BAD="OS_ROLES, REMOTE_OS_AUTHENTICATION, REMOTE_OS_ROLES 설정이 TRUE로 설정되지 않은 경우"
GUIDELINE_REMEDIATION="OS_ROLES, REMOTE_OS_AUTHENTICATION, REMOTE_OS_ROLES 설정을 FALSE로 변경"

# Oracle 연결 정보 초기화 (fallback if library not loaded)
ORACLE_USER="${ORACLE_USER:-system}"
ORACLE_PASSWORD="${ORACLE_PASSWORD:-manager}"
ORACLE_HOST="${ORACLE_HOST:-localhost}"
ORACLE_PORT="${ORACLE_PORT:-1521}"
ORACLE_SID="${ORACLE_SID:-ORCL}"
ORACLE_SYSDBA="${ORACLE_SYSDBA:-sys as sysdba}"

diagnose() {
    echo "진단 항목: ${ITEM_ID} - ${ITEM_NAME}"

    # Initialize Oracle connection variables (only if library function exists)
    if declare -f init_oracle_vars >/dev/null 2>&1; then
        init_oracle_vars
    fi

    # FR-022: Check required tools (only if library function exists)
    if declare -f check_oracle_tools >/dev/null 2>&1; then
        if ! check_oracle_tools; then
            if declare -f handle_missing_tools >/dev/null 2>&1; then
                handle_missing_tools "oracle" "${ITEM_ID}" "${ITEM_NAME}" \
                    "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" \
                    "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
            fi
            return 0
        fi
    fi

    local diagnosis_result="MANUAL" status="수동진단" inspection_summary="" command_result="" command_executed=""

    # Oracle 서비스 확인 (only if library function exists)
    if declare -f check_oracle_service >/dev/null 2>&1; then
        if ! check_oracle_service; then
            diagnosis_result="MANUAL"
            status="수동진단"
            inspection_summary="Oracle 서비스 미실행 (서비스 시작 후 수동 확인 필요)"
            if declare -f save_dual_result >/dev/null 2>&1; then
                save_dual_result "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" "${inspection_summary}" "${command_result}" "${command_executed}" "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
            fi
            if declare -f verify_result_saved >/dev/null 2>&1; then
                verify_result_saved "${ITEM_ID}"
            fi
            return 0
        fi
    fi

    inspection_summary="Oracle OS 인증 설정 확인 필요 (수동진단 권장)"
    inspection_summary+="\\n1. OS_ROLES 확인: SHOW PARAMETER os_roles;"
    inspection_summary+="\\n2. REMOTE_OS_AUTHENTICATION 확인: SHOW PARAMETER remote_os_authent;"
    inspection_summary+="\\n3. REMOTE_OS_ROLES 확인: SHOW PARAMETER remote_os_roles;"
    inspection_summary+="\\n4. 모든 파라미터가 FALSE로 설정되어야 함"
    diagnosis_result="MANUAL" status="수동진단"

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
