#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Version: 1.0.1
# @Last Updated: 2026-05-24
# ============================================================================
# [Assessment Item]
# @ID          : WEB-18
# @Category    : 웹서비스>2.서비스관리
# @Platform    : JEUS_Linux
# @Severity    : 상
# @Title       : 웹 서비스 WebDAV 비활성화
# @Description : docs/guideline_metadata.json and docs guidelines must be applied before final automation.
# @Reference   : docs/guideline_metadata.json and docs guideline Markdown
# ============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"
source "${SCRIPT_DIR}/jeus_linux_lib.sh"

ITEM_ID="WEB-18"
ITEM_NAME="웹 서비스 WebDAV 비활성화"
SEVERITY="상"

GUIDELINE_PURPOSE="WebDAV 서비스를 비활성화하여,WebDAV에서 발견되는 다수의 인증 우회 취약점을 제거하고자함"
GUIDELINE_THREAT="WebDAV가 활성화되어 있는 경우 웹 서비스에 악의적으로 작성된 요청을 이용하여 인증을 우회함으로써 비밀번호로 보호된 WebDAV의 자원에 접근 (디렉터리 열람, 파일 다운로드 등)이 가능하며, WebDAV에 의해 호출된 일부 구성 요소에 매개 변수를 정확하게 점검하지 않는 결함이 존재하여, 이로 인해 버퍼 오버 런이 발생할 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="WebDAV 서비스를 비활성화하고 있는 경우"
GUIDELINE_CRITERIA_BAD="WebDAV 서비스를 활성화하고 있는 경우"
GUIDELINE_REMEDIATION="WebDAV 서비스 비활성화 설정"

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