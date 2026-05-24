#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"

ITEM_ID="D-22"
ITEM_NAME="데이터베이스의 자원 제한 기능을 TRUE로 설정"
SEVERITY="하"

GUIDELINE_PURPOSE="RESOURCE _LIMIT 값을 TRUE로 설정하여 자원의 과도한 사용을 방지하여 데이터베이스의 안정성을 보장하고, 효율적인 자원 관리를 수행하기 위함"
GUIDELINE_THREAT="자원 제한 기능을 TRUE로 설정하지 않을 경우, 특정 사용자가 과도하게 많은 자원을 소비할 수 있으며 이로 인해 시스템에 과부하가 발생할 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="RESOURCE _LIMIT 설정이 TRUE로 되어 있는 경우"
GUIDELINE_CRITERIA_BAD="RESOURCE _LIMIT 설정이 FALSE로 되어 있는 경우"
GUIDELINE_REMEDIATION="RESOURCE _LIMIT 설정을 TRUE로 설정 변경"

diagnose() {
    local diagnosis_result="N/A"
    local status="N/A"
    local inspection_summary="MSSQL_Linux is not a target platform for D-22 according to docs/guideline_metadata.json."
    local command_result="D-22 target: Oracle DB"
    local command_executed="guideline_metadata.json D-22 target platform review"

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
