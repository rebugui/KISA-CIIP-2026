#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : D-12
# @Category    : DBMS (Database Management System)
# @Platform    : Oracle
# @Severity    : 상
# @Title       : 안전한 리스너 비밀번호 설정 및 사용
# @Description : Oracle 리스너 비밀번호 설정 여부 확인 (Oracle 12c Release 2+ 미지원)
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/command_validator.sh"
source "${LIB_DIR}/timeout_handler.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/dbms_connector.sh"
source "${LIB_DIR}/db_connection_helpers.sh"

ITEM_ID="D-12"
ITEM_NAME="안전한 리스너 비밀번호 설정 및 사용"
SEVERITY="상"

GUIDELINE_PURPOSE="Listener의 Owner는 DBA가 아니더라도 Listener를 shutdown시키거나 DB 서버에 임의의 파일을 생성할 수 있으며, 원격에서 LSNRCTL 유틸리티를 사용하여 listener.ora 파일에 대한 변경이 가능하므로 Listener에 비밀번호를 설정하여 비인가자가 이를 수정하지 못하도록하기 위함"
GUIDELINE_THREAT="Listener에 비밀번호가 설정되지 않았을 경우 DoS, 정보 획득, Listener 프로세스를 중지시킬 수 있는 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="Listener의 비밀번호가 설정된 경우"
GUIDELINE_CRITERIA_BAD="Listener의 비밀번호가 설정되어 있지 않은 경우"
GUIDELINE_REMEDIATION="Listener 비밀번호 설정"

# Version-specific handling (FR-030)
LISTENER_PASSWORD_DEPRECATED_VERSION="12.2"

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

    # Process check (check for TNS listener)
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

    # sqlplus check for version detection
    if ! command -v sqlplus >/dev/null; then
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="Oracle SQL*Plus 클라이언트가 설치되지 않았습니다. 수동으로 리스너 설정을 확인하세요."
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

    # Test connection and get version
    local version_query="SELECT BANNER FROM V\$VERSION WHERE BANNER LIKE 'Oracle%';"
    local oracle_version_output=$(echo "${version_query}" | sqlplus -s "${DBMS_USER}/${DBMS_PASSWORD}@${DBMS_HOST}:${DBMS_PORT}/${DBMS_SID}" 2>/dev/null | grep -v "^$" | grep -v "SQL>" | tail -1 || echo "")

    echo "[DEBUG] Oracle version: ${oracle_version_output}"

    # Extract version number
    local full_version=$(echo "${oracle_version_output}" | grep -oE "[0-9]+\.[0-9]+" | head -1 || echo "")

    if [ -z "${full_version}" ]; then
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="Oracle 버전을 확인할 수 없습니다: ${oracle_version_output}. 수동으로 리스너 비밀번호를 확인하세요."
        save_dual_result "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" "${inspection_summary}" "${oracle_version_output}" "${version_query}" "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
        verify_result_saved "${ITEM_ID}"
        return 0
    fi

    echo "[INFO] Oracle 버전: ${full_version}"

    # Version-specific handling (FR-030)
    # Oracle 12c Release 2 (12.2) onwards: Listener password feature not supported
    if [[ "${full_version}" == "${LISTENER_PASSWORD_DEPRECATED_VERSION}"* ]] || [ "$(printf '%s\n' "${LISTENER_PASSWORD_DEPRECATED_VERSION}" "${full_version}" | sort -V | head -1)" = "${LISTENER_PASSWORD_DEPRECATED_VERSION}" ]; then
        diagnosis_result="N/A"
        status="N/A"
        inspection_summary="Oracle ${full_version}은 리스너 비밀번호 기능을 지원하지 않습니다(12.2+). 대신 Oracle Wallet 또는 OS 인증을 사용하세요."
        command_result="Version: ${oracle_version_output}"
        command_executed="${version_query}"
        save_dual_result "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" "${inspection_summary}" "${command_result}" "${command_executed}" "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
        verify_result_saved "${ITEM_ID}"
        return 0
    fi

    # For versions < 12.2, check listener.ora for password configuration
    # Find listener.ora location
    local listener_ora_path=""
    local common_locations=(
        "$ORACLE_HOME/network/admin/listener.ora"
        "/u01/app/oracle/product/*/network/admin/listener.ora"
        "/oracle/app/oracle/product/*/network/admin/listener.ora"
    )

    for loc in "${common_locations[@]}"; do
        if ls $loc 2>/dev/null | head -1 | grep -q .; then
            listener_ora_path=$(ls $loc 2>/dev/null | head -1)
            break
        fi
    done

    command_executed="ls $ORACLE_HOME/network/admin/listener.ora; find /u01/app/oracle -name 'listener.ora' 2>/dev/null"

    if [ -z "${listener_ora_path}" ]; then
        # Try lsnrctl status to find listener.ora location
        if command -v lsnrctl >/dev/null; then
            local lsnr_status=$(lsnrctl status 2>/dev/null || echo "")
            listener_ora_path=$(echo "${lsnr_status}" | grep -i "listener.ora" | head -1 | awk '{print $NF}' || echo "")
        fi
    fi

    if [ -z "${listener_ora_path}" ] || [ ! -f "${listener_ora_path}" ]; then
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="listener.ora 파일을 찾을 수 없습니다. 수동으로 리스너 비밀번호 설정을 확인하세요."
        command_result="listener.ora not found (searched: ORACLE_HOME=${ORACLE_HOME:-not set})"
        save_dual_result "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" "${inspection_summary}" "${command_result}" "${command_executed}" "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
        verify_result_saved "${ITEM_ID}"
        return 0
    fi

    echo "[INFO] listener.ora 경로: ${listener_ora_path}"

    # Check for PASSWORDS_* parameter in listener.ora
    local password_config=$(grep -i "^PASSWORDS_" "${listener_ora_path}" 2>/dev/null || echo "")

    # Also check if password is set using lsnrctl (requires password to test)
    if command -v lsnrctl >/dev/null; then
        # Try to set a dummy status - if password is set, this will prompt for password
        local lsnr_test=$(echo "exit" | timeout 5 lsnrctl 2>&1 || echo "")
        if echo "${lsnr_test}" | grep -qi "password"; then
            password_config="Password is configured (lsnrctl prompts for password)"
        fi
    fi

    command_result="listener.ora path: ${listener_ora_path}\nPassword config: ${password_config:-Not found}"

    # Determine result
    if [ -n "${password_config}" ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="리스너 비밀번호가 설정되어 있습니다(${listener_ora_path})."
    else
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="리스너 비밀번호가 설정되지 않았습니다(${listener_ora_path}). lsnrctl SET PASSWORD 또는 listener.ora에 PASSWORDS_listener_name 설정이 필요합니다."
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
