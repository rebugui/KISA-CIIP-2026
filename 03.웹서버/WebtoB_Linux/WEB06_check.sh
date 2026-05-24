#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Version: 1.0.1
# @Last Updated: 2026-05-24
# ============================================================================
# [Assessment Item]
# @ID          : WEB-06
# @Category    : 웹서비스>2.서비스관리
# @Platform    : WebtoB_Linux
# @Severity    : 상
# @Title       : 웹 서비스 상위 디렉터리 접근 제한 설정
# @Description : docs/guideline_metadata.json and docs guidelines must be applied before final automation.
# @Reference   : docs/guideline_metadata.json and docs guideline Markdown
# ============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"
source "${SCRIPT_DIR}/webtob_linux_lib.sh"

ITEM_ID="WEB-06"
ITEM_NAME="웹 서비스 상위 디렉터리 접근 제한 설정"
SEVERITY="상"

GUIDELINE_PURPOSE="상위 디렉터리 접근 제한 설정을 통해 비인가자의 특정 디렉터리에 대한 접근 및 열람을 제한하여 중요 파일 및 데이터를 보호하고,Unicode 버그 및 서비스 거부 공격 등을 방지하기 위함"
GUIDELINE_THREAT="상위 디렉터리로 이동하는 것이 가능할 경우 접근하고자하는 디렉터리의 하위 경로에서 상위로 이동하며 정보 탐색이 가능하여 중요 정보가 노출될 위험이 존재함 악의적인 목적을 가진 사용자가 중요 파일 및 디렉터리의 접근이 가능하여 데이터가 유출될 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="상위 디렉터리 접근 기능을 제거한 경우"
GUIDELINE_CRITERIA_BAD="상위 디렉터리 접근 기능을 제거하지 않은 경우"
GUIDELINE_REMEDIATION="상위 디렉터리 접근 기능 제거 설정"
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