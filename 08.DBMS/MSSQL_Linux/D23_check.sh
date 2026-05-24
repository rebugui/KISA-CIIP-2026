#!/bin/bash

# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : D-23
# @Category    : DBMS (Database Management System)
# @Platform    : MSSQL_Linux
# @Severity    : 상
# @Title       : xp_cmdshell 사용 제한
# @Description : 비밀번호 정책 및 설정 관리를 통한 무단 접근 방지
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

ITEM_ID="D-23"

ITEM_NAME="xp_cmdshell 사용 제한"
SEVERITY="상"
GUIDELINE_PURPOSE="불필요하게 활성화되어 있는 xp_cmdshell를 제한하여 공격자의 무단 접근 및 악성 코드의 실행 위험을 감소시키기 위함"
GUIDELINE_THREAT="해킹 툴에서 자주 이용되고 있으며, 권한 상승이나 데이터 유출 등의 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="xp_cmdshell이 비활성화되어 있거나, 활성화되어 있으면 다음의 조건을 모두 만족하는 경우 1. public의 실행(Execute)권한이 부여되어 있지 않은 경우 2. 서비스 계정(애플리케이션 연동)에 sysadmin 권한이 부여되어 있지 않은 경우"
GUIDELINE_CRITERIA_BAD="xp_cmdshell이 활성화되어 있고, 양호의 조건을 만족하지 않는 경우"
GUIDELINE_REMEDIATION="xp_cmdshell 설정 값을 0 또는 False로 설정"

diagnose() {
    echo "진단 항목: ${ITEM_ID} - ${ITEM_NAME}"

    # FR-022: Check required tools
    if ! check_mssql_tools; then
        handle_missing_tools "mssql" "${ITEM_ID}" "${ITEM_NAME}" \
            "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" \
            "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
        return 0
    fi

    local diagnosis_result="MANUAL" status="수동진단" inspection_summary="" command_result="" command_executed=""

    if command -v sc.exe &>/dev/null; then
        if ! sc.exe query MSSQLSERVER &>/dev/null && ! sc.exe query SQLServerAgent &>/dev/null; then
            diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="MSSQL 서비스 미실행 (서비스 시작 후 수동 확인 필요)"
            save_dual_result "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" "${inspection_summary}" "${command_result}" "${command_executed}" "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
            verify_result_saved "${ITEM_ID}"; return 0
        fi
    fi

    if command -v sqlcmd &>/dev/null; then
        command_executed="sqlcmd -Q \"SELECT name, value FROM sys.dm_server_registry WHERE registry_key LIKE '%ForceEncryption%';\""
        inspection_summary="MSSQL 네트워크 암호화 확인 - 수동 확인 필요\n\n"
        inspection_summary+="검증 방법:\n"
        inspection_summary+="1. 레지스트리 확인:\n"
        inspection_summary+="   - HKLM\\SOFTWARE\\Microsoft\\Microsoft SQL Server\\MSSQLXX.MSSQLServer\\SuperSocketNetLib\\Certificate\n"
        inspection_summary+="   - HKLM\\SOFTWARE\\Microsoft\\Microsoft SQL Server\\MSSQLXX.MSSQLServer\\SuperSocketNetLib\\ForceEncryption\n"
        inspection_summary+="2. ForceEncryption = 1: 양호 (암호화 활성화)\n"
        inspection_summary+="3. ForceEncryption = 0: 취약 (암호화 비활성화)\n\n"
        inspection_summary+="조치 방법:\n"
        inspection_summary+="- SQL Server Configuration Manager > SQL Server Network Configuration > Protocols > Properties\n"
        inspection_summary+="- Force Encryption: Yes 설정\n"
        inspection_summary+="- Certificate: SSL 인증서 선택\n"
        inspection_summary+="- SQL Server 서비스 재시작"
    else
        inspection_summary="MSSQL 네트워크 암호화 확인 - 수동 확인 필요\n\n"
        inspection_summary+="검증 방법:\n"
        inspection_summary+="1. SQL Server Configuration Manager 실행\n"
        inspection_summary+="2. SQL Server Network Configuration > Protocols for MSSQLSERVER\n"
        inspection_summary+="3. Properties > Flag Protocols 탭 확인\n"
        inspection_summary+="4. Force Encryption = Yes: 양호\n"
        inspection_summary+="5. Force Encryption = No: 취약\n\n"
        inspection_summary+="조치 방법:\n"
        inspection_summary+="- Force Encryption: Yes 설정\n"
        inspection_summary+="- Certificate 탭에서 SSL 인증서 선택\n"
        inspection_summary+="- SQL Server 서비스 재시작\n"
        inspection_summary+="- 클라이언트 연결 시 Encrypt=True 옵션 사용"
    fi

    diagnosis_result="MANUAL" status="수동진단"

    save_dual_result "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" "${inspection_summary}" "${command_result}" "${command_executed}" "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
    verify_result_saved "${ITEM_ID}"; return 0
}

main() {
    diagnose
}

if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi
