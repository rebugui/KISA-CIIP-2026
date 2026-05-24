#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : # : D-16
# @Category    : DBMS (Database Management System)
# @Platform    : MSSQL
# @Severity    : # : 하
# @Title       : # : Windows 인증 모드 사용
# @Description : # : MSSQL Server가 Windows 인증 모드만 사용하도록 설정되어 있는지 확인
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

# Initialize MSSQL connection variables
init_mssql_vars
ITEM_ID="D-16"
ITEM_NAME="Windows 인증 모드 사용"
SEVERITY="하"

# 가이드라인 정보
GUIDELINE_PURPOSE="적절한 Windows 인증 모드를 적용하여 적합한 복잡성 수준을 유지하기 위함"
GUIDELINE_THREAT="혼합 인증 모드를 사용하고 sa 계정이 활성화되어 있는 경우, 잘 알려진 sa 계정에 대한 계정 추측 공격의 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="Windows 인증 모드를 사용하고 sa 계정이 비활성화되어 있는 경우 sa 계정 활성화 시 강력한 암호 정책을 설정한 경우"
GUIDELINE_CRITERIA_BAD="혼합 인증 모드를 사용하고, 활성화된 sa 계정에 대한 강력한 암호 정책 설정을 하지 않은 경우"
GUIDELINE_REMEDIATION="Windows 인증 모드 사용"

# ============================================================================
# 진단 함수
# ============================================================================

diagnose() {
    echo "진단 항목: ${ITEM_ID} - ${ITEM_NAME}"

    # FR-022: Check required tools
    if ! check_mssql_tools; then
        handle_missing_tools "mssql" "${ITEM_ID}" "${ITEM_NAME}" \
            "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" \
            "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
        return 0
    fi


    local diagnosis_result="UNKNOWN"
    local status="미진단"
    local inspection_summary=""
    local command_result=""
    local command_executed=""

    # MSSQL은 Linux에서도 실행 가능하지만, Windows 인증 모드는 Windows 환경에서만 의미 있음
    # Linux 환경에서는 이 항목이 N/A로 처리되어야 함

    # OS 확인
    local os_type=""
    if [ -f "/etc/os-release" ]; then
        os_type="Linux"
    elif [[ "$OSTYPE" == "msys" || "$OSTYPE" == "win32" ]]; then
        os_type="Windows"
    else
        os_type="Unknown"
    fi

    # Linux 환경인 경우 MSSQL이 설치되어 있어도 Windows 인증 모드는 지원하지 않음
    if [ "$os_type" = "Linux" ]; then
        diagnosis_result="N/A"
        status="N/A"
        inspection_summary="MSSQL이 Linux 환경에서 실행 중입니다. Windows 인증 모드는 Windows 환경에서만 지원됩니다. Linux의 경우 인증서 기반 인증 또는 AD(Azure Active Directory) 인증을 사용하세요."
        command_result="OS: Linux, Windows Authentication not supported"
        command_executed="cat /etc/os-release"

        save_dual_result \
            "${ITEM_ID}" \
            "${ITEM_NAME}" \
            "${status}" \
            "${diagnosis_result}" \
            "${inspection_summary}" \
            "${command_result}" \
            "${command_executed}" \
            "${GUIDELINE_PURPOSE}" \
            "${GUIDELINE_THREAT}" \
            "${GUIDELINE_CRITERIA_GOOD}" \
            "${GUIDELINE_CRITERIA_BAD}" \
            "${GUIDELINE_REMEDIATION}"

        verify_result_saved "${ITEM_ID}"
        return 0
    fi

    # Windows 환경인 경우 수동 진단 유도
    # (실제 환경에서는 sqlcmd 또는 PowerShell로 레지스트리/설정 확인 가능하지만,
    #  bash 스크립트에서 Windows 레지스트리 직접 접근은 어려움)

    diagnosis_result="MANUAL"
    status="수동진단"
    inspection_summary="MSSQL Server의 인증 모드를 수동으로 확인해야 합니다. SQL Server Management Studio에서 해당 서버 우클릭 > 속성 > 보안 > 서버 인증을 확인하세요. 'Windows 인증 모드'만 선택되어 있어야 양호입니다. 'SQL Server 및 Windows 인증 모드'이면 취약합니다."
    command_result="Windows Authentication Mode: Manual check required"
    command_executed="SQL Server Management Studio > Server Properties > Security"

    save_dual_result \
        "${ITEM_ID}" \
        "${ITEM_NAME}" \
        "${status}" \
        "${diagnosis_result}" \
        "${inspection_summary}" \
        "${command_result}" \
        "${command_executed}" \
        "${GUIDELINE_PURPOSE}" \
        "${GUIDELINE_THREAT}" \
        "${GUIDELINE_CRITERIA_GOOD}" \
        "${GUIDELINE_CRITERIA_BAD}" \
        "${GUIDELINE_REMEDIATION}"

    verify_result_saved "${ITEM_ID}"

    return 0
}

# ============================================================================
# 메인 실행
# ============================================================================

main() {
    show_diagnosis_start "${ITEM_ID}" "${ITEM_NAME}"
    check_disk_space
    diagnose
    show_diagnosis_complete "${ITEM_ID}" "${diagnosis_result:-UNKNOWN}"
}

if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi
