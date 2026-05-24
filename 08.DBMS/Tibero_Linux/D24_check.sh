#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Version: 1.0.1
# @Last Updated: 2026-05-24
# ============================================================================
# [Assessment Item]
# @ID          : D-24
# @Category    : DBMS>3.옵션관리
# @Platform    : Tibero_Linux
# @Severity    : 상
# @Title       : Registry Procedure 권한 제한
# @Description : docs/guideline_metadata.json and docs guidelines must be applied before final automation.
# @Reference   : docs/guideline_metadata.json and docs guideline Markdown
# ============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"
source "${SCRIPT_DIR}/tibero_linux_lib.sh"

ITEM_ID="D-24"
ITEM_NAME="Registry Procedure 권한 제한"
SEVERITY="상"

GUIDELINE_PURPOSE="불필요한 RegistryProcedure의 권한 설정을 확인하고 제한하여 시스템의 보안 및 안정성을 강화하기 위함"
GUIDELINE_THREAT="불필요한 레지스트리 접근 권한이 제한되지 않는 경우, 공격자가 시스템을 변경하거나 악성 소프트웨어를 설치하여 권한 상승, 데이터 유출, 시스템 장애를 발생시킬 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="제한이 필요한 시스템 확장 저장 프로 시저들이 DBA 외 guest/public에게 부여되지 않은 경우"
GUIDELINE_CRITERIA_BAD="제한이 필요한 시스템 확장 저장 프로 시저들이 DBA 외 guest/public에게 부여된 경우"
GUIDELINE_REMEDIATION="guest/public에게 부여된 시스템 확장 저장 프로 시저 권한 제거"

diagnose() {
    invoke_tibero_linux_check "${ITEM_ID}"

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