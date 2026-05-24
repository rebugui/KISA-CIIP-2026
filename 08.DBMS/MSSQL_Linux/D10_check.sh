#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"

ITEM_ID="D-10"
ITEM_NAME="원격에서 DB 서버로의 접속 제한"
SEVERITY="상"

GUIDELINE_PURPOSE="지정된 IP 주소만 DB 서버에 접근 가능하도록 설정되어 있는지 점검하여 비인가자의 DB 서버 접근을 원천적으로 차단하고자함"
GUIDELINE_THREAT="DB 서버 접속 시 IP 주소 제한이 적용되지 않은 경우 비인가자가 내·외부 망 위치에 상관없이 DB 서버에 접근할 수 있는 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="DB 서버에 지정된 IP 주소에서만 접근 가능하도록 제한한 경우"
GUIDELINE_CRITERIA_BAD="DB 서버에 지정된 IP 주소에서만 접근 가능하도록 제한하지 않은 경우"
GUIDELINE_REMEDIATION="DB 서버에 대해 지정된 IP 주소에서만 접근 가능하도록 설정"

diagnose() {
    local diagnosis_result="N/A"
    local status="N/A"
    local inspection_summary="MSSQL_Linux is not a target platform for D-10 according to docs/guideline_metadata.json."
    local command_result="D-10 target: Windows OS, Oracle DB, MySQL, Altibase, Tibero, PostgreSQL 등"
    local command_executed="guideline_metadata.json D-10 target platform review"

    save_dual_result "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" \
        "${inspection_summary}" "${command_result}" "${command_executed}" \
        "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" \
        "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
}

main() {
    diagnose
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    main "$@"
fi
