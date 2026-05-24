#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Version: 1.0.1
# @Last Updated: 2026-05-24
# ============================================================================
# [Assessment Item]
# @ID          : WEB-17
# @Category    : 웹서비스>2.서비스관리
# @Platform    : WebtoB_Linux
# @Severity    : 중
# @Title       : 웹 서비스 가상 디렉터리 삭제
# @Description : docs/guideline_metadata.json and docs guidelines must be applied before final automation.
# @Reference   : docs/guideline_metadata.json and docs guideline Markdown
# ============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"
source "${SCRIPT_DIR}/webtob_linux_lib.sh"

ITEM_ID="WEB-17"
ITEM_NAME="웹 서비스 가상 디렉터리 삭제"
SEVERITY="중"

GUIDELINE_PURPOSE="불필요한 가상 디렉터리를 삭제하여 공격이 가능한 영역을 최소화하고 정보 노출 방지 및 권한 상승 공격 등의 위험을 제거하기 위함"
GUIDELINE_THREAT="불필요한 가상 디렉터리를 삭제하지 않은 경우, 취약한 가상 디렉터리를 통해 시스템 권한 탈취 및 시스템 구조 등의 중요 정보가 노출될 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="불필요한 가상 디렉터리가 존재하지 않는 경우"
GUIDELINE_CRITERIA_BAD="불필요한 가상 디렉터리가 존재하는 경우"
GUIDELINE_REMEDIATION="불필요한 가상 디렉터리 존재 여부 점검 및 삭제하도록 설정"
diagnose() {
    invoke_webtob_linux_check "${ITEM_ID}"

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