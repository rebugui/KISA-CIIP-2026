#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"

ITEM_ID="D-16"
ITEM_NAME="Windows 인증 모드 사용"
SEVERITY="하"

GUIDELINE_PURPOSE="적절한 Windows 인증 모드를 적용하여 적합한 복잡성 수준을 유지하기 위함"
GUIDELINE_THREAT="혼합 인증 모드를 사용하고 sa 계정이 활성화되어 있는 경우, 잘 알려진 sa 계정에 대한 계정 추측 공격의 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="Windows 인증 모드를 사용하고 sa 계정이 비활성화되어 있는 경우 sa 계정 활성화 시 강력한 암호 정책을 설정한 경우"
GUIDELINE_CRITERIA_BAD="혼합 인증 모드를 사용하고, 활성화된 sa 계정에 대한 강력한 암호 정책 설정을 하지 않은 경우"
GUIDELINE_REMEDIATION="Windows 인증 모드 사용"

diagnose() {
    local diagnosis_result="N/A"
    local status="N/A"
    local inspection_summary="Oracle_Linux is not a target platform for D-16 according to docs/guideline_metadata.json."
    local command_result="D-16 target: MSSQL"
    local command_executed="guideline_metadata.json D-16 target platform review"

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
