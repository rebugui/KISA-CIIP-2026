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
# @Platform    : Oracle
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
source "${LIB_DIR}/dbms_connector.sh"
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

# Oracle 연결 정보 초기화 (fallback if library not loaded)
ORACLE_USER="${ORACLE_USER:-system}"
ORACLE_PASSWORD="${ORACLE_PASSWORD:-manager}"
ORACLE_HOST="${ORACLE_HOST:-localhost}"
ORACLE_PORT="${ORACLE_PORT:-1521}"
ORACLE_SID="${ORACLE_SID:-ORCL}"
ORACLE_SYSDBA="${ORACLE_SYSDBA:-sys as sysdba}"

# ============================================================================
# 진단 함수
# ============================================================================

diagnose() {
    diagnosis_result="unknown"  # Changed from local to global for main() access
    local status="미진단"
    local inspection_summary=""
    local command_result=""
    local command_executed=""

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

    echo "[INFO] Oracle 기본 계정 비밀번호 점검 시작..."

    # Oracle 서비스 확인 (using helper from db_connection_helpers.sh)
    if ! pgrep -x "tnslsnr" &>/dev/null && ! pgrep -x "oracle" &>/dev/null; then
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="Oracle 서비스 미실행"
        command_result="Oracle service not running"
        command_executed="pgrep -x tnslsnr; pgrep -x oracle"

        save_dual_result "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" \
            "${inspection_summary}" "${command_result}" "${command_executed}" \
            "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" \
            "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
        return 1
    fi

    # sqlplus 확인
    if ! command -v sqlplus &>/dev/null; then
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="Oracle SQL*Plus 클라이언트 미설치"
        command_result="sqlplus command not found"
        command_executed="command -v sqlplus"

        save_dual_result "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" \
            "${inspection_summary}" "${command_result}" "${command_executed}" \
            "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" \
            "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
        return 1
    fi

    # 연결 정보 입력 (using dbms_connector.sh)
    if [ -z "${DBMS_HOST:-}" ] || [ -z "${DBMS_USER:-}" ]; then
        if declare -f prompt_dbms_connection >/dev/null 2>&1; then
            prompt_dbms_connection "oracle"
        fi
    else
        # Use environment variables for batch mode
        DBMS_HOST="${DBMS_HOST:-${ORACLE_HOST:-localhost}}"
        DBMS_USER="${DBMS_USER:-${ORACLE_USER:-system}}"
        DBMS_PASSWORD="${DBMS_PASSWORD:-${ORACLE_PASSWORD:-manager}}"
        DBMS_PORT="${DBMS_PORT:-${ORACLE_PORT:-1521}}"
        DBMS_SID="${DBMS_SID:-${ORACLE_SID:-ORCL}}"
        export DBMS_HOST DBMS_USER DBMS_PASSWORD DBMS_PORT DBMS_SID
    fi

    # 연결 문자열 생성
    local conn_str="${DBMS_USER}/${DBMS_PASSWORD}@${DBMS_HOST}:${DBMS_PORT}/${DBMS_SID}"

    # 연결 시도
    if ! echo "SELECT 1 FROM DUAL;" | sqlplus -s "${conn_str}" &>/dev/null; then
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="Oracle 연결 실패 - 데이터베이스 관리자 비밀번호 확인 필요"
        command_result="연결 실패: User=${DBMS_USER}, Host=${DBMS_HOST}:${DBMS_PORT}/${DBMS_SID}"
        command_executed="sqlplus -s ${DBMS_USER}/***@${DBMS_HOST}:${DBMS_PORT}/${DBMS_SID}"

        save_dual_result "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" \
            "${inspection_summary}" "${command_result}" "${command_executed}" \
            "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" \
            "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
        return 1
    fi

    echo "[INFO] Oracle 연결 성공"

    # Oracle 버전 확인
    local oracle_version=$(echo "SELECT VERSION FROM PRODUCT_COMPONENT_VERSION WHERE ROWNUM = 1;" | sqlplus -s "${conn_str}" 2>/dev/null | grep -v "^$" | grep -v "SQL>" | tail -1)
    echo "[INFO] Oracle 버전: ${oracle_version}"

    # 기본 계정 목록 (SYS, SYSTEM, DBSNMP, SYSMAN 등)
    local default_accounts=("SYS" "SYSTEM" "DBSNMP" "SYSMAN" "OUTLN")
    local vulnerable_accounts=()
    local secure_accounts=()
    local check_results=""

    for account in "${default_accounts[@]}"; do
        # DBA_USERS에서 계정 정보 확인
        local account_info=$(echo "SELECT USERNAME, ACCOUNT_STATUS, LOCK_DATE, EXPIRY_DATE FROM DBA_USERS WHERE USERNAME='${account}';" | sqlplus -s "${conn_str}" 2>/dev/null | grep -v "^$" | grep -v "SQL>" | tail -n +2 | head -1)

        if [ -n "$account_info" ]; then
            echo "[INFO] 계정 발견: ${account}"

            # ACCOUNT_STATUS 확인 (OPEN, EXPIRED, LOCKED 등)
            local account_status=$(echo "$account_info" | awk '{print $2}')

            if [ "$account_status" = "OPEN" ]; then
                # 비밀번호 만료일 확인
                local expiry_date=$(echo "$account_info" | awk '{print $4}')

                if [ "$expiry_date" = "NULL" ] || [ -z "$expiry_date" ]; then
                    # 만료일 없음 - 기본 설정 가능성
                    vulnerable_accounts+=("${account} (만료일 없음)")
                    check_results="${check_results}[취약] ${account}: 비밀번호 만료일 없음\\n"
                else
                    secure_accounts+=("${account}")
                    check_results="${check_results}[양호] ${account}: 비밀번호 설정됨 (만료일: ${expiry_date})\\n"
                fi
            elif [ "$account_status" = "EXPIRED" ] || [ "$account_status" = "EXPIRED & LOCKED" ]; then
                # 만료됨 - 변경 필요성
                secure_accounts+=("${account}")
                check_results="${check_results}[양호] ${account}: 비밀번호 만료됨 (${account_status})\\n"
            elif [ "$account_status" = "LOCKED" ] || [ "$account_status" = "LOCKED(TIMED)" ]; then
                # 잠김
                secure_accounts+=("${account}")
                check_results="${check_results}[정보] ${account}: 계정 잠김 (${account_status})\\n"
            else
                # 기타 상태
                check_results="${check_results}[정보] ${account}: ${account_status}\\n"
            fi
        fi
    done

    # PASSWORD_VERSIONS 확인 (비밀번호 알고리즘)
    local password_versions=$(echo "SELECT USERNAME, PASSWORD_VERSIONS FROM DBA_USERS WHERE USERNAME IN ('SYS', 'SYSTEM') ORDER BY USERNAME;" | sqlplus -s "${conn_str}" 2>/dev/null | grep -v "^$" | grep -v "SQL>" | tail -n +2)
    check_results="${check_results}\\n[정보] PASSWORD_VERSIONS:\\n${password_versions}\\n"

    # DEFAULT PROFILE 확인 (비밀번호 정책)
    local profile_info=$(echo "SELECT LIMIT FROM DBA_PROFILES WHERE PROFILE='DEFAULT' AND RESOURCE_NAME='PASSWORD_LIFE_TIME';" | sqlplus -s "${conn_str}" 2>/dev/null | grep -v "^$" | grep -v "SQL>" | tail -n +2 | head -1)
    check_results="${check_results}[정보] DEFAULT PROFILE: PASSWORD_LIFE_TIME = ${profile_info}\\n"

    # 최종 판정
    local total_vulnerabilities=${#vulnerable_accounts[@]}

    if [ ${total_vulnerabilities} -eq 0 ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="모든 기본 계정의 비밀번호 정책이 적절히 설정됨"
        command_result="Oracle 버전: ${oracle_version}\\n${check_results}"
        command_executed="sqlplus -s ${DBMS_USER}/***@${DBMS_HOST}:${DBMS_PORT}/${DBMS_SID}"
    else
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="기본 계정 비밀번호 정책 미변경: ${total_vulnerabilities}개"
        command_result="Oracle 버전: ${oracle_version}\\n취약 계정:\\n"
        for account in "${vulnerable_accounts[@]}"; do
            command_result="${command_result}- ${account}\\n"
        done
        command_result="${command_result}\\n상세:\\n${check_results}"
        command_executed="sqlplus -s ${DBMS_USER}/***@${DBMS_HOST}:${DBMS_PORT}/${DBMS_SID}"
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
