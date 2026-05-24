#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Version: 1.0.1
# @Last Updated: 2026-05-24
# ============================================================================
# [Assessment Item]
# @ID          : WEB-15
# @Category    : 웹서비스>2.서비스관리 웹서비스의불필요한스크립트매핑제거
# @Platform    : JEUS_Linux
# @Severity    : 상
# @Title       : 웹 서비스의 불필요한 스크립트 매핑 제거
# @Description : docs/guideline_metadata.json and docs guidelines must be applied before final automation.
# @Reference   : docs/guideline_metadata.json and docs guideline Markdown
# ============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"
source "${SCRIPT_DIR}/jeus_linux_lib.sh"

ITEM_ID="WEB-15"
ITEM_NAME="웹 서비스의 불필요한 스크립트 매핑 제거"
SEVERITY="상"

GUIDELINE_PURPOSE="웹 서비스에서 사용하지 않는 불필요 스크립트 매핑이 존재하는지 점검하여 잠재적 보안 위협을 방지하기 위함"
GUIDELINE_THREAT="웹 서비스에서 불필요한 스크립트 매핑을 제거하지 않은 경우, 버퍼오버플로우(Buffer Overflow), 서비스 거부 공격(Denial of Service), 크로스 사이트 스크립 팅(CrossSiteScripting) 등의 공격 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="불필요한 스크립트 매핑이 존재하지 않는 경우"
GUIDELINE_CRITERIA_BAD="불필요한 스크립트 매핑이 존재하는 경우"
GUIDELINE_REMEDIATION="불필요한 스크립트 매핑 존재 여부 점검 및 제거 설정"

diagnose() {
    invoke_jeus_linux_check "${ITEM_ID}"

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