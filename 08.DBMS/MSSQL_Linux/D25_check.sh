#!/bin/bash

# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : D-25
# @Category    : DBMS (Database Management System)
# @Platform    : MSSQL_Linux
# @Severity    : 상
# @Title       : 주기적 보안 패치 및 벤더 권고 사항 적용
# @Description : 설치된 DB 버전을 수집하여 벤더 보안 공지 대비 패치 적용 여부를 수동 판단
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

ITEM_ID="D-25"

ITEM_NAME="주기적 보안 패치 및 벤더 권고 사항 적용"
SEVERITY="상"
GUIDELINE_PURPOSE="안전한 버전의 데이터베이스를 사용하여 알려진 보안 취약점으로 인한 공격을 차단하기 위함"
GUIDELINE_THREAT="안전하지 않은 버전을 사용할 경우, 알려진 보안 취약점을 통해 시스템에 침투하거나 데이터의 탈취, 악성 코드 감염 및 서비스 중단 등의 보안 사고를 초래할 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="보안 패치가 적용된 버전을 사용하는 경우"
GUIDELINE_CRITERIA_BAD="보안 패치가 적용되지 않는 버전을 사용하는 경우"
GUIDELINE_REMEDIATION="보안 패치가 적용된 버전으로 업데이트"

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
        inspection_summary="diagnosis_result="MANUAL" (서비스 시작 후 수동 확인 필요)"
            save_dual_result "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" "${inspection_summary}" "${command_result}" "${command_executed}" "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
            verify_result_saved "${ITEM_ID}"; return 0
        fi
    fi

    if command -v sqlcmd &>/dev/null; then
        command_executed="sqlcmd -Q \"SELECT @@VERSION;\""
        inspection_summary="MSSQL 보안 패치 버전 확인 필요 (수동진단 권장)\n\n"
        inspection_summary+="설치된 MSSQL 버전:\n"
        inspection_summary+="   SELECT @@VERSION;\n\n"
        inspection_summary+="확인 방법:\n"
        inspection_summary+="1. 위 쿼리 실행으로 설치된 MSSQL 버전 및 패치 수준 확인\n"
        inspection_summary+="2. Microsoft 보안 공지(https://msrc.microsoft.com)를 통해\n"
        inspection_summary+="   최신 보안 패치 버전과 현재 설치된 버전 비교\n"
        inspection_summary+="3. 보안 패치가 적용되지 않은 경우 업데이트 필요\n\n"
        inspection_summary+="조치 방법:\n"
        inspection_summary+="- 최신 보안 패치가 적용된 버전으로 업데이트\n"
        inspection_summary+="- Microsoft 보안 공지 사항 주기적 확인\n"
        inspection_summary+="- 정기적 패치 적용 프로세스 수립"
    else
        inspection_summary="MSSQL 보안 패치 버전 확인 필요 (수동진단 권장)\n\n"
        inspection_summary+="sqlcmd를 사용하여 다음 쿼리 실행:\n"
        inspection_summary+="   SELECT @@VERSION;\n\n"
        inspection_summary+="확인 방법:\n"
        inspection_summary+="1. sqlcmd로 MSSQL 서버 연결 후 버전 확인\n"
        inspection_summary+="2. Microsoft 보안 공지(https://msrc.microsoft.com)를 통해\n"
        inspection_summary+="   최신 보안 패치 버전과 현재 설치된 버전 비교\n"
        inspection_summary+="3. 보안 패치가 적용되지 않은 경우 업데이트 필요\n\n"
        inspection_summary+="조치 방법:\n"
        inspection_summary+="- 최신 보안 패치가 적용된 버전으로 업데이트\n"
        inspection_summary+="- Microsoft 보안 공지 사항 주기적 확인\n"
        inspection_summary+="- 정기적 패치 적용 프로세스 수립"
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
