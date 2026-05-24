#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"

ITEM_ID="D-09"
ITEM_NAME="일정 횟수의 로그인 실패 시 이에 대한 잠금 정책 설정"
SEVERITY="중"

GUIDELINE_PURPOSE="일정 횟수의 로그인 실패 시 계정 잠금 정책을 설정하여 비인가자의 자동화된 무차별 대입 공격, 사전 대입 공격 등을 통한 사용자 계정 비밀번호 유출을 방지하기 위함"
GUIDELINE_THREAT="일정한 횟수의 로그인 실패 횟수를 설정하여 제한하지 않으면 자동화된 방법으로 계정 및 비밀번호를 획득하여 데이터베이스에 접근하여 정보가 유출될 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="로그인 시도 횟수를 제한하는 값을 설정한 경우"
GUIDELINE_CRITERIA_BAD="로그인 시도 횟수를 제한하는 값을 설정하지 않은 경우"
GUIDELINE_REMEDIATION="로그인 시도 횟수 제한 값 설정"

diagnose() {
    local diagnosis_result="N/A"
    local status="N/A"
    local inspection_summary="mysql_Linux is not a target platform for D-09 according to docs/guideline_metadata.json."
    local command_result="D-09 target: Oracle DB, Altibase, Tibero 등"
    local command_executed="guideline_metadata.json D-09 target platform review"

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
