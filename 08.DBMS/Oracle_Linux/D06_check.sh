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
# @Platform    : Oracle_Linux
# @Severity    : 중
# @Title       : DB 사용자 계정을 개별적으로 부여하여 사용
# @Description : DB 접근 시 사용자별로 서로 다른 계정을 사용하는지 점검
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

    local diagnosis_result="GOOD"
    local status="양호"
    local inspection_summary=""
    local command_result=""
    local command_executed=""

    # Oracle 서비스 확인 (only if library function exists)
    if declare -f check_oracle_service >/dev/null 2>&1; then
        if ! check_oracle_service; then
            diagnosis_result="MANUAL"
            status="수동진단"
            inspection_summary="Oracle 서비스가 실행 중이지 않습니다. 서비스 시작 후 진단이 필요합니다."
            command_result="Oracle service not running"
            command_executed="pgrep -x 'tnslsnr' || pgrep -x 'oracle'"
            # Save results (only if library function exists)
            if declare -f save_dual_result >/dev/null 2>&1; then
                save_dual_result "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" "${inspection_summary}" "${command_result}" "${command_executed}" "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
            fi
            if declare -f verify_result_saved >/dev/null 2>&1; then
                verify_result_saved "${ITEM_ID}"
            fi
            return 0
        fi
    fi

    # Oracle 연결 확인 및 sqlplus 확인
    if ! command -v sqlplus &>/dev/null; then
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="sqlplus가 설치되지 않았습니다. 수동 진단이 필요합니다."
        command_result="sqlplus command not found"
        command_executed="which sqlplus"
        # Save results (only if library function exists)
        if declare -f save_dual_result >/dev/null 2>&1; then
            save_dual_result "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" "${inspection_summary}" "${command_result}" "${command_executed}" "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
        fi
        if declare -f verify_result_saved >/dev/null 2>&1; then
            verify_result_saved "${ITEM_ID}"
        fi
        return 0
    fi

    # Initialize Oracle connection variables (only if library function exists)
    if declare -f init_oracle_vars >/dev/null 2>&1; then
        init_oracle_vars
    fi

    # Oracle 연결 정보 초기화 (fallback if library not loaded)
    ORACLE_USER="${ORACLE_USER:-system}"
    ORACLE_PASSWORD="${ORACLE_PASSWORD:-manager}"
    ORACLE_HOST="${ORACLE_HOST:-localhost}"
    ORACLE_PORT="${ORACLE_PORT:-1521}"
    ORACLE_SID="${ORACLE_SID:-ORCL}"
    ORACLE_SYSDBA="${ORACLE_SYSDBA:-sys as sysdba}"

    # 1. 계정 확인 (dba_users)
    local user_query="SELECT username FROM dba_users ORDER BY username;"
    command_executed="sqlplus -s ${ORACLE_SYSDBA}/${ORACLE_PASSWORD}@${ORACLE_HOST}:${ORACLE_PORT}/${ORACLE_SID} AS SYSDBA << EOF
SET PAGESIZE 0
SET FEEDBACK OFF
SET HEADING ON
${user_query}
EXIT;
EOF"

    command_result=$(sqlplus -s "${ORACLE_SYSDBA}/${ORACLE_PASSWORD}@${ORACLE_HOST}:${ORACLE_PORT}/${ORACLE_SID}" AS SYSDBA << EOF 2>/dev/null
SET PAGESIZE 0
SET FEEDBACK OFF
SET HEADING ON
${user_query}
EXIT;
EOF
)

    # 일반적인 공용 계정 패턴 (예: test, user, admin, guest 등)
    local common_shared_accounts=("TEST" "USER" "ADMIN" "GUEST" "PUBLIC" "SHARED" "COMMON" "APP" "WEB")
    local found_shared_accounts=()

    if [ -n "$command_result" ]; then
        # 공용 계정 탐지
        while IFS= read -r username; do
            # SYS, SYSTEM, DBSNMP 등 Oracle 기본 계정은 제외
            if [[ "$username" =~ ^(SYS|SYSTEM|DBSNMP|SYSMAN|OUTLN|DIP|ORACLE_OCM|APPQOSSYS|WMSYS|EXFSYS|CTXSYS|XDB|ANONYMOUS|SI_INFORMTN_SCHEMA|ORDDATA|ORDPLUGINS|ORDSYS|MDSYS|OLAPSYS|OWBSYS|FLOWS_FILES|APEX_PUBLIC_USER|APEX_040000|MDDATA|ORDDATA_DOC|XS\$NULL|OJVMSYS|LBACSYS|AUDSYS|DVF|DVSYS|DBSFWUSER|REMOTE_SCHEDULER_AGENT|DIP|SYSBACKUP|GSMADMIN_INTERNAL|SYSKM|SYSDG|GSMCATUSER|SYSRAC) ]]; then
                continue
            fi

            # 공용 계정 패턴 확인
            for shared_pattern in "${common_shared_accounts[@]}"; do
                if [[ "$username" == "$shared_pattern" ]]; then
                    found_shared_accounts+=("$username")
                    break
                fi
            done
        done < <(echo "$command_result" | grep -v "^$" | grep -v "USERNAME" || echo "")

        # 결과 분석
        local total_users=$(echo "$command_result" | grep -v "^$" | grep -v "USERNAME" | wc -l)
        local oracle_system_users=$(echo "$command_result" | grep -E "^(SYS|SYSTEM|DBSNMP|SYSMAN|OUTLN|DIP|ORACLE_OCM|APPQOSSYS|WMSYS|EXFSYS|CTXSYS|XDB|ANONYMOUS|SI_INFORMTN_SCHEMA|ORDDATA|ORDPLUGINS|ORDSYS|MDSYS|OLAPSYS|OWBSYS|FLOWS_FILES|APEX_PUBLIC_USER|APEX_040000|MDDATA|ORDDATA_DOC|XS\$NULL|OJVMSYS|LBACSYS|AUDSYS|DVF|DVSYS|DBSFWUSER|REMOTE_SCHEDULER_AGENT|DIP|SYSBACKUP|GSMADMIN_INTERNAL|SYSKM|SYSDG|GSMCATUSER|SYSRAC)" | wc -l)

        if [ ${#found_shared_accounts[@]} -gt 0 ]; then
            diagnosis_result="VULNERABLE"
            status="취약"
            inspection_summary="공용 계정 사용 발견: ${found_shared_accounts[*]} (취약 - 계정 공유로 로그 추적 어려움)"
        elif [ $total_users -eq $oracle_system_users ]; then
            diagnosis_result="MANUAL"
            status="수동진단"
            inspection_summary="Oracle 기본 계정만 존재. 응용 프로그램별 계정 생성 여부 수동 확인 필요 (총 ${total_users}개 계정)"
        else
            diagnosis_result="GOOD"
            status="양호"
            local app_users=$((total_users - oracle_system_users))
            inspection_summary="사용자별 개별 계정 사용 중 (총 ${total_users}개 중 Oracle 기본 ${oracle_system_users}개, 응용 ${app_users}개)"
        fi
    else
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="Oracle 계정 조회 실패. 수동 진단 필요합니다."
        command_result="Query failed or no results"
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
