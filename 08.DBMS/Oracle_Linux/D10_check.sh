#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : D-10
# @Category    : DBMS (Database Management System)
# @Platform    : Oracle_Linux
# @Severity    : 상
# @Title       : 원격에서 DB 서버로의 접속 제한
# @Description : Oracle 리스너 원격 접속 제한 설정 확인
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

ITEM_ID="D-10"
ITEM_NAME="원격에서 DB 서버로의 접속 제한"
SEVERITY="상"

GUIDELINE_PURPOSE="지정된 IP 주소만 DB 서버에 접근 가능하도록 설정되어 있는지 점검하여 비인가자의 DB 서버 접근을 원천적으로 차단하고자함"
GUIDELINE_THREAT="DB 서버 접속 시 IP 주소 제한이 적용되지 않은 경우 비인가자가 내·외부 망 위치에 상관없이 DB 서버에 접근할 수 있는 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="DB 서버에 지정된 IP 주소에서만 접근 가능하도록 제한한 경우"
GUIDELINE_CRITERIA_BAD="DB 서버에 지정된 IP 주소에서만 접근 가능하도록 제한하지 않은 경우"
GUIDELINE_REMEDIATION="DB 서버에 대해 지정된 IP 주소에서만 접근 가능하도록 설정"

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




    if ! pgrep -x "tnslsnr" &>/dev/null && ! pgrep -x "oracle" &>/dev/null; then
        diagnosis_result="N/A"
        status="N/A"
        inspection_summary="Oracle 서비스 미실행"
        if declare -f save_dual_result >/dev/null 2>&1; then
            save_dual_result "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" "${inspection_summary}" "${command_result}" "${command_executed}" "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
        fi
        if declare -f verify_result_saved >/dev/null 2>&1; then
            verify_result_saved "${ITEM_ID}"
        fi
        return 0
    fi

    # D-10 판단기준 (KISA 가이드): sqlnet.ora 의 tcp.validnode_checking=yes 와
    #   tcp.invited_nodes(허용 IP 목록) 설정으로 IP 접근 제한 여부를 점검.
    #   양호: validnode_checking=yes + invited_nodes(또는 excluded_nodes) 설정
    #   취약: validnode_checking 미설정/off 또는 허용 IP 목록 없음
    #   파일 판독 불가: 수동진단
    local sqlnet_file="${ORACLE_HOME:-}/network/admin/sqlnet.ora"
    command_executed="grep -iE 'tcp.validnode_checking|tcp.invited_nodes|tcp.excluded_nodes' ${sqlnet_file}"

    if [ -z "${ORACLE_HOME:-}" ] || [ ! -f "${sqlnet_file}" ] || [ ! -r "${sqlnet_file}" ]; then
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="sqlnet.ora 파일을 찾을 수 없거나 읽을 수 없습니다 (경로: ${sqlnet_file}). 수동으로 tcp.validnode_checking 및 tcp.invited_nodes 설정을 확인하세요."
        command_result="sqlnet.ora not found or unreadable: ${sqlnet_file}"
    else
        command_result=$(grep -iE 'tcp\.validnode_checking|tcp\.invited_nodes|tcp\.excluded_nodes' "${sqlnet_file}" 2>/dev/null | grep -v '^[[:space:]]*#' || true)

        local validnode_on=0 invited_set=0
        if echo "${command_result}" | grep -iE 'tcp\.validnode_checking[[:space:]]*=[[:space:]]*(yes|on|true)' >/dev/null 2>&1; then
            validnode_on=1
        fi
        if echo "${command_result}" | grep -iE 'tcp\.(invited|excluded)_nodes[[:space:]]*=[[:space:]]*\(' >/dev/null 2>&1; then
            invited_set=1
        fi

        if [ "${validnode_on}" -eq 1 ] && [ "${invited_set}" -eq 1 ]; then
            diagnosis_result="GOOD"
            status="양호"
            inspection_summary="sqlnet.ora 에 tcp.validnode_checking=yes 및 허용/차단 노드 목록이 설정되어 IP 접근이 제한됩니다."
        else
            diagnosis_result="VULNERABLE"
            status="취약"
            inspection_summary="sqlnet.ora 에 IP 접근 제한 설정이 미흡합니다 (validnode_checking=${validnode_on}, invited/excluded_nodes=${invited_set}). tcp.validnode_checking=yes 와 tcp.invited_nodes 를 설정하세요."
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
