#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"

ITEM_ID="D-21"
ITEM_NAME="인가되지 않은 GRANTOPTION 사용 제한"
SEVERITY="중"

GUIDELINE_PURPOSE="GRANTOPTION을 ROLE에 의해 설정하여 권한의 남용을 방지하고, 안정성을 확보하기 위함"
GUIDELINE_THREAT="일반 사용자에게 GRANT OPTION이 부여된 경우, 일반 사용자가 Object 소유자인 것과 같이 다른 일반 사용자에게 권한을 부여할 수 있어 권한의 무분별한 확산으로 인한 중요 정보의 유출 등의 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="WITH _GRANT _OPTION이 ROLE에 의하여 설정된 경우"
GUIDELINE_CRITERIA_BAD="WITH _GRANT _OPTION이 ROLE에 의하여 설정되지 않은 경우"
GUIDELINE_REMEDIATION="WITH _GRANT _OPTION이 ROLE에 의하여 설정되도록 변경"

diagnose() {
    local diagnosis_result="N/A"
    local status="N/A"
    local inspection_summary="postgresql_Linux is not a target platform for D-21 according to docs/guideline_metadata.json."
    local command_result="D-21 target: Oracle DB, MySQL, Altibase, Tibero 등"
    local command_executed="guideline_metadata.json D-21 target platform review"

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
