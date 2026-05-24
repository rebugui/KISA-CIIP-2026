#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Version: 1.0.1
# @Last Updated: 2026-05-24
# ============================================================================
# [Assessment Item]
# @ID          : D-12
# @Category    : DBMS>2.접근관리
# @Platform    : Altibase_Linux
# @Severity    : 상
# @Title       : 안전한 리스너 비밀번호 설정 및 사용
# @Description : docs/guideline_metadata.json and docs guidelines must be applied before final automation.
# @Reference   : docs/guideline_metadata.json and docs guideline Markdown
# ============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"
source "${SCRIPT_DIR}/altibase_linux_lib.sh"

ITEM_ID="D-12"
ITEM_NAME="안전한 리스너 비밀번호 설정 및 사용"
SEVERITY="상"

GUIDELINE_PURPOSE="Listener의 Owner는 DBA가 아니더라도 Listener를 shutdown시키거나 DB 서버에 임의의 파일을 생성할 수 있으며, 원격에서 LSNRCTL 유틸리티를 사용하여 listener.ora 파일에 대한 변경이 가능하므로 Listener에 비밀번호를 설정하여 비인가자가 이를 수정하지 못하도록하기 위함"
GUIDELINE_THREAT="Listener에 비밀번호가 설정되지 않았을 경우 DoS, 정보 획득, Listener 프로세스를 중지시킬 수 있는 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="Listener의 비밀번호가 설정된 경우"
GUIDELINE_CRITERIA_BAD="Listener의 비밀번호가 설정되어 있지 않은 경우"
GUIDELINE_REMEDIATION="Listener 비밀번호 설정"

diagnose() {
    invoke_altibase_linux_check "${ITEM_ID}"

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