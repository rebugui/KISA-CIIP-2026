#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : D-11
# @Category    : DBMS (Database Management System)
# @Platform    : Oracle
# @Severity    : 상
# @Title       : DBA 이외의 인가되지 않은 사용자가 시스템 테이블에 접근할 수 없도록 설정
# @Description : DBA 권한이 없는 사용자의 시스템 테이블 접근 권한 확인
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/command_validator.sh"
source "${LIB_DIR}/timeout_handler.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/dbms_connector.sh"
source "${LIB_DIR}/db_connection_helpers.sh"

ITEM_ID="D-11"
ITEM_NAME="DBA 이외의 인가되지 않은 사용자가 시스템 테이블에 접근할 수 없도록 설정"
SEVERITY="상"

GUIDELINE_PURPOSE="시스템 테이블의 일반 사용자 계정 접근 제한 설정 적용 여부를 점검하여 일반 사용자 계정 유출 시 발생할 수 있는 비인가자의 시스템 테이블 접근 위험을 차단하기 위함"
GUIDELINE_THREAT="시스템 테이블의 일반 사용자 계정 접근 제한 설정이 되어 있지 않을 경우 Object, 사용자, 테이블 및 뷰, 작업 내역 등의 시스템 테이블에 저장된 정보가 누출될 수 있음"
GUIDELINE_CRITERIA_GOOD="시스템 테이블에 DBA만 접근 가능하도록 설정되어 있는 경우"
GUIDELINE_CRITERIA_BAD="시스템 테이블에 DBA 외 일반 사용자 계정이 접근 가능하도록 설정되어 있는 경우"
GUIDELINE_REMEDIATION="시스템 테이블에 일반 사용자 계정이 접근할 수 없도록 설정"

diagnose() {
    echo "진단 항목: ${ITEM_ID} - ${ITEM_NAME}"

    # FR-022: Check required tools
    if ! check_oracle_tools; then
        handle_missing_tools "oracle" "${ITEM_ID}" "${ITEM_NAME}" \
            "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" \
            "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
        return 0
    fi


    local diagnosis_result="VULNERABLE"
    local status="취약"
    local inspection_summary=""
    local command_result=""
    local command_executed=""

    # Process check
    if command -v pgrep >/dev/null; then
        if ! pgrep -x "tnslsnr" > /dev/null && ! pgrep -x "oracle" > /dev/null; then
            diagnosis_result="N/A"
            status="N/A"
            inspection_summary="Oracle 서비스가 실행 중이 아닙니다."
            command_result="Oracle process not found"
            command_executed="pgrep -x tnslsnr; pgrep -x oracle"
            save_dual_result "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" "${inspection_summary}" "${command_result}" "${command_executed}" "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
            verify_result_saved "${ITEM_ID}"
            return 0
        fi
    else
        echo "[INFO] pgrep command missing, skipping process check."
    fi

    # sqlplus check
    if ! command -v sqlplus >/dev/null; then
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="Oracle SQL*Plus 클라이언트가 설치되지 않았습니다. 수동으로 확인이 필요합니다."
        command_result="sqlplus command not found"
        command_executed="command -v sqlplus"
        save_dual_result "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" "${inspection_summary}" "${command_result}" "${command_executed}" "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
        verify_result_saved "${ITEM_ID}"
        return 0
    fi

    # Connection prompt if not already connected
    if [ -z "${DBMS_HOST:-}" ] || [ -z "${DBMS_USER:-}" ]; then
        echo "[INFO] Oracle 연결 정보 입력이 필요합니다."
        prompt_dbms_connection "oracle"
    fi

    # Test connection
    if ! echo "SELECT 1 FROM DUAL;" | sqlplus -s "${DBMS_USER}/${DBMS_PASSWORD}@${DBMS_HOST}:${DBMS_PORT}/${DBMS_SID}" &>/dev/null; then
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="Oracle 연결에 실패했습니다. 연결 정보를 확인하고 다시 시도하세요."
        command_result="Connection failed"
        command_executed="sqlplus -s ${DBMS_USER}/***@${DBMS_HOST}:${DBMS_PORT}/${DBMS_SID}"
        save_dual_result "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" "${inspection_summary}" "${command_result}" "${command_executed}" "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
        verify_result_saved "${ITEM_ID}"
        return 0
    fi

    echo "[INFO] Oracle 연결 성공"

    # Get list of DBA role users
    local dba_query="SELECT GRANTEE FROM DBA_ROLE_PRIVS WHERE GRANTED_ROLE='DBA' AND GRANTEE NOT IN ('SYS', 'SYSTEM', 'SYSMAN', 'DBSNMP') ORDER BY GRANTEE;"
    local dba_users=$(echo "${dba_query}" | sqlplus -s "${DBMS_USER}/${DBMS_PASSWORD}@${DBMS_HOST}:${DBMS_PORT}/${DBMS_SID}" 2>/dev/null | grep -v "^$" | grep -v "SQL>" | tail -n +2 || echo "")

    echo "[INFO] DBA 권한 사용자:\n${dba_users}"

    # Check for non-DBA users with system table privileges
    # Query DBA_TAB_PRIVS for SELECT privileges on system tables
    local sys_privs_query="SELECT GRANTEE, OWNER, TABLE_NAME, PRIVILEGE FROM DBA_TAB_PRIVS WHERE (TABLE_NAME LIKE 'DBA_%' OR TABLE_NAME LIKE 'V\$%' OR TABLE_NAME LIKE 'USER_%' OR OWNER='SYS') AND PRIVILEGE='SELECT' AND GRANTEE NOT IN (SELECT GRANTEE FROM DBA_ROLE_PRIVS WHERE GRANTED_ROLE='DBA') AND GRANTEE NOT IN ('PUBLIC', 'SYS', 'SYSTEM', 'DBSNMP', 'SYSMAN', 'OUTLN') ORDER BY GRANTEE, TABLE_NAME;"
    command_executed="${dba_query}; ${sys_privs_query}"
    command_result=$(echo "${sys_privs_query}" | sqlplus -s "${DBMS_USER}/${DBMS_PASSWORD}@${DBMS_HOST}:${DBMS_PORT}/${DBMS_SID}" 2>/dev/null | grep -v "^$" | grep -v "SQL>" | tail -n +2 || echo "")

    echo "[DEBUG] System table privileges:\n${command_result}"

    # Check for non-DBA users with system privileges
    local sys_grant_query="SELECT GRANTEE, PRIVILEGE FROM DBA_SYS_PRIVS WHERE GRANTEE NOT IN (SELECT GRANTEE FROM DBA_ROLE_PRIVS WHERE GRANTED_ROLE='DBA') AND GRANTEE NOT IN ('PUBLIC', 'SYS', 'SYSTEM', 'DBSNMP', 'SYSMAN') AND PRIVILEGE LIKE '%ANY%' ORDER BY GRANTEE, PRIVILEGE;"
    local sys_grants=$(echo "${sys_grant_query}" | sqlplus -s "${DBMS_USER}/${DBMS_PASSWORD}@${DBMS_HOST}:${DBMS_PORT}/${DBMS_SID}" 2>/dev/null | grep -v "^$" | grep -v "SQL>" | tail -n +2 || echo "")

    # Count problematic privileges
    local violation_count=0
    local violation_details=""

    if [ -n "${command_result}" ]; then
        while IFS= read -r line; do
            if [ -n "$line" ]; then
                violation_count=$((violation_count + 1))
                violation_details+="${line}; "
            fi
        done <<< "$command_result"
    fi

    if [ -n "${sys_grants}" ]; then
        while IFS= read -r line; do
            if [ -n "$line" ]; then
                violation_count=$((violation_count + 1))
                violation_details+="SYSTEM PRIVILEGE: ${line}; "
            fi
        done <<< "$sys_grants"
    fi

    echo "[INFO] 발견된 위반 수: ${violation_count}"

    # Determine result
    if [ ${violation_count} -gt 0 ]; then
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="DBA 이외의 사용자에게 시스템 테이블 접근 권한이 부여되어 있습니다(${violation_count}건 위반). ${violation_details:0:200}... 불필요한 권한을 회수하세요."
    else
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="시스템 테이블 접근 권한이 DBA 사용자로만 적절하게 제한되어 있습니다."
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
