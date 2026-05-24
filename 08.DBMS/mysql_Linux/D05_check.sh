#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"

ITEM_ID="D-05"
ITEM_NAME="비밀번호 재사용에 대한 제약 설정"
SEVERITY="중"

GUIDELINE_PURPOSE="비밀번호 재사용 제약 설정 적용 여부를 점검하여 비밀번호 변경 시 이전 비밀번호 재사용을 제약하여 형식적인 비밀번호 변경을 원천적으로 차단하기 위함"
GUIDELINE_THREAT="비밀번호 재사용 제약 설정이 적용되어 있지 않을 경우 비밀번호 변경 전 사용했던 비밀번호를 재사용함으로써 비인가자의 계정 비밀번호 추측 공격에 대한 시간을 더 많이 허용하여 비밀번호 유출 위험이 증가함"
GUIDELINE_CRITERIA_GOOD="비밀번호 재사용 제한 설정을 적용한 경우"
GUIDELINE_CRITERIA_BAD="비밀번호 재사용 제한 설정을 적용하지 않은 경우"
GUIDELINE_REMEDIATION="PASSWORD _REUSE _TIME, PASSWORD _REUSE _MAX 파라미터 설정"

diagnose() {
    local diagnosis_result="N/A"
    local status="N/A"
    local inspection_summary="mysql_Linux is not a target platform for D-05 according to docs/guideline_metadata.json."
    local command_result="D-05 target: Oracle DB, Altibase, Tibero 등"
    local command_executed="guideline_metadata.json D-05 target platform review"

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
