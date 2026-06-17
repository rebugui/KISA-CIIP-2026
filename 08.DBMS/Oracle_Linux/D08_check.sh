#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : D-08
# @Category    : DBMS (Database Management System)
# @Platform    : Oracle_Linux
# @Severity    : 상
# @Title       : 안전한 암호화 알고리즘 사용
# @Description : DBMS 진단 항목 D-08 관련 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================



SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/command_validator.sh"
source "${LIB_DIR}/timeout_handler.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/dbms_connector.sh"
source "${LIB_DIR}/db_connection_helpers.sh"

ITEM_ID="D-08"
ITEM_NAME="안전한 암호화 알고리즘 사용"
SEVERITY="상"

GUIDELINE_PURPOSE="안전한 해시 알고리즘 사용으로 데이터의 기밀성 및 무결성을 보장하고, 사용자 인증을 강화하기 위함"
GUIDELINE_THREAT="SHA-1이나 MD5와 같은 오래된 알고리즘 사용 시 공격자의 무차별 대입 공격 등으로 비밀번호 유추가 가능하며, 데이터 변조 및 유출의 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="해시 알고리즘 SHA-256 이상의 암호화 알고리즘을 사용하고 있는 경우"
GUIDELINE_CRITERIA_BAD="해시 알고리즘 SHA-256 미만의 암호화 알고리즘을 사용하고 있는 경우"
GUIDELINE_REMEDIATION="SHA-256 이상의 암호화 알고리즘 적용"

# Vulnerable versions based on FR-030
VULNERABLE_VERSIONS=("10.1" "10.2" "11.1" "11.2" "12.1")
SAFE_VERSIONS=("12.2" "18" "19" "21")

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

    # Get Oracle version
    local version_query="SELECT BANNER FROM V\$VERSION WHERE BANNER LIKE 'Oracle%';"
    command_executed="${version_query}"
    command_result=$(echo "${version_query}" | sqlplus -s "${DBMS_USER}/${DBMS_PASSWORD}@${DBMS_HOST}:${DBMS_PORT}/${DBMS_SID}" 2>/dev/null | grep -v "^$" | grep -v "SQL>" | tail -1 || echo "")

    echo "[DEBUG] Oracle version: ${command_result}"

    # Extract version number (e.g., "19.23.0.0.0" -> "19", "11.2.0.4.0" -> "11.2")
    local oracle_version=$(echo "${command_result}" | grep -oE "Oracle [0-9]+" | awk '{print $2}' || echo "")
    local full_version=$(echo "${command_result}" | grep -oE "[0-9]+\.[0-9]+" | head -1 || echo "")

    if [ -z "${oracle_version}" ]; then
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="Oracle 버전을 확인할 수 없습니다: ${command_result}. 수동으로 암호화 알고리즘을 확인하세요."
        save_dual_result "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" "${inspection_summary}" "${command_result}" "${command_executed}" "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
        verify_result_saved "${ITEM_ID}"
        return 0
    fi

    echo "[INFO] Oracle 버전: ${oracle_version} (전체: ${full_version})"

    # Check password encryption algorithm
    local encryption_query="SELECT PASSWORD_VERSIONS FROM DBA_USERS WHERE USERNAME='SYS';"
    local password_versions=$(echo "${encryption_query}" | sqlplus -s "${DBMS_USER}/${DBMS_PASSWORD}@${DBMS_HOST}:${DBMS_PORT}/${DBMS_SID}" 2>/dev/null | grep -v "^$" | grep -v "SQL>" | tail -1 || echo "")

    echo "[INFO] 비밀번호 버전: ${password_versions:-확인 불가}"

    # Determine result based on version (FR-030)
    # Oracle 10g: MD5 (VULNERABLE)
    # Oracle 11g: SHA-1 (VULNERABLE)
    # Oracle 12c+: SHA-512/AES (GOOD)
    local is_vulnerable=false
    local encryption_algorithm=""

    for vuln_ver in "${VULNERABLE_VERSIONS[@]}"; do
        if [[ "${full_version}" == "${vuln_ver}"* ]]; then
            is_vulnerable=true
            break
        fi
    done

    if [ "${is_vulnerable}" = true ]; then
        if [[ "${full_version}" == "10."* ]]; then
            encryption_algorithm="MD5"
        elif [[ "${full_version}" == "11."* ]]; then
            encryption_algorithm="SHA-1"
        else
            encryption_algorithm="취약한 알고리즘 (MD5 또는 SHA-1)"
        fi

        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="Oracle ${full_version}은 취약한 암호화 알고리즘(${encryption_algorithm})을 사용합니다. Oracle 12.2+로 업그레이드하여 SHA-512/AES 암호화를 적용하세요."
    elif [[ "${full_version}" == "12.2"* ]] || { [[ "${oracle_version}" -ge 12 ]] && [[ "${oracle_version}" -ne 12 ]]; }; then
        encryption_algorithm="SHA-512/AES"
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="Oracle ${full_version}은 안전한 암호화 알고리즘(SHA-512, AES)을 사용합니다."
    else
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="Oracle ${full_version}의 암호화 알고리즘을 확인할 수 없습니다. 수동으로 비밀번호 암호화 설정(PASSWORD_VERSIONS)을 확인하세요."
    fi

    # Add password_versions info if available
    if [ -n "${password_versions}" ]; then
        inspection_summary+=" (비밀번호 버전: ${password_versions})"
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
