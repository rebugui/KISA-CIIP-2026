#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : D-07
# @Category    : DBMS (Database Management System)
# @Platform    : Oracle_Linux
# @Severity    : 중
# @Title       : root 권한으로 서비스 구동 제한
# @Description : DBMS 진단 항목 D-07 관련 점검
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

# Oracle 연결 정보 초기화 (fallback if library not loaded)
ORACLE_USER="${ORACLE_USER:-system}"
ORACLE_PASSWORD="${ORACLE_PASSWORD:-manager}"
ORACLE_HOST="${ORACLE_HOST:-localhost}"
ORACLE_PORT="${ORACLE_PORT:-1521}"
ORACLE_SID="${ORACLE_SID:-ORCL}"
ORACLE_SYSDBA="${ORACLE_SYSDBA:-sys as sysdba}"

ITEM_ID="D-07"
ITEM_NAME="root 권한으로 서비스 구동 제한"
SEVERITY="중"

GUIDELINE_PURPOSE="root 권한을 제한적으로 사용함으로써 시스템의 손상, 데이터의 유출 및 변조 등을 차단하여 보안 위협을 방지하기 위함"
GUIDELINE_THREAT="root 권한으로 서비스를 구동할 경우 시스템 손상, 데이터 유출 및 변조, 감사 및 추적의 어려움 등으로 인해 서비스 공격의 표적이 될 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="DBMS가 root 계정 또는 root 권한이 아닌 별도의 계정 및 권한으로 구동되고 있는 경우"
GUIDELINE_CRITERIA_BAD="DBMS가 root 계정 또는 root 권한으로 구동되고 있는 경우"
GUIDELINE_REMEDIATION="DBMS 구동 계정 변경"

diagnose() {
    diagnosis_result="unknown"  # Global variable (not local)
    local status="수동진단"
    local inspection_summary=""
    local command_result=""
    local command_executed=""

    # Initialize Oracle connection variables (only if library function exists)
    if declare -f init_oracle_vars >/dev/null 2>&1; then
        init_oracle_vars
    fi

    # D-07 은 OS 프로세스 소유자 점검 항목 (KISA 가이드: ps -ef | grep tnslsnr).
    # SQL 접속 불필요. 리스너 프로세스가 없으면 자동 점검 불가 -> 수동진단.
    echo "진단 항목: ${ITEM_ID} - ${ITEM_NAME}"

    command_executed="ps -ef | grep tnslsnr | grep -v grep"
    local listener_ps
    listener_ps=$(ps -ef 2>/dev/null | grep "tnslsnr" | grep -v "grep" || true)
    command_result="${listener_ps}"

    if [ -z "${listener_ps}" ]; then
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="서비스 미실행으로 자동 점검 불가 (수동진단 필요). 리스너(tnslsnr) 프로세스를 찾을 수 없습니다. 서비스 시작 후 'ps -ef | grep tnslsnr' 로 구동 계정을 확인하세요."
    else
        # 프로세스 소유자(첫 번째 필드) 확인. root 로 구동 시 취약, 그 외 별도 계정이면 양호.
        local owners
        owners=$(echo "${listener_ps}" | awk '{print $1}' | sort -u | tr '\n' ',' | sed 's/,$//')
        if echo "${listener_ps}" | awk '{print $1}' | grep -qx "root"; then
            diagnosis_result="VULNERABLE"
            status="취약"
            inspection_summary="리스너(tnslsnr) 프로세스가 root 권한으로 구동되고 있습니다 (소유자: ${owners}). 별도의 전용 계정으로 구동하도록 변경하세요."
        else
            diagnosis_result="GOOD"
            status="양호"
            inspection_summary="리스너(tnslsnr) 프로세스가 root 가 아닌 별도 계정으로 구동되고 있습니다 (소유자: ${owners})."
        fi
    fi

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
