#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"

ITEM_ID="D-23"
ITEM_NAME="xp_cmdshell 사용 제한"
SEVERITY="상"

GUIDELINE_PURPOSE="불필요하게 활성화되어 있는 xp_cmdshell를 제한하여 공격자의 무단 접근 및 악성 코드의 실행 위험을 감소시키기 위함"
GUIDELINE_THREAT="해킹 툴에서 자주 이용되고 있으며, 권한 상승이나 데이터 유출 등의 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="xp_cmdshell이 비활성화되어 있거나, 활성화되어 있으면 다음의 조건을 모두 만족하는 경우 1. public의 실행(Execute)권한이 부여되어 있지 않은 경우 2. 서비스 계정(애플리케이션 연동)에 sysadmin 권한이 부여되어 있지 않은 경우"
GUIDELINE_CRITERIA_BAD="xp_cmdshell이 활성화되어 있고, 양호의 조건을 만족하지 않는 경우"
GUIDELINE_REMEDIATION="xp_cmdshell 설정 값을 0 또는 False로 설정"

diagnose() {
    local diagnosis_result="N/A"
    local status="N/A"
    local inspection_summary="mysql_Linux is not a target platform for D-23 according to docs/guideline_metadata.json."
    local command_result="D-23 target: MSSQL"
    local command_executed="guideline_metadata.json D-23 target platform review"

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
