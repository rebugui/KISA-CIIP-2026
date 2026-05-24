#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Version: 1.0.1
# @Last Updated: 2026-05-24
# ============================================================================
# [Assessment Item]
# @ID          : D-07
# @Category    : DBMS>1.계정관리
# @Platform    : Cubrid_Linux
# @Severity    : 중
# @Title       : root 권한으로 서비스 구동 제한
# @Description : docs/guideline_metadata.json and docs guidelines must be applied before final automation.
# @Reference   : docs/guideline_metadata.json and docs guideline Markdown
# ============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"
source "${SCRIPT_DIR}/cubrid_linux_lib.sh"

ITEM_ID="D-07"
ITEM_NAME="root 권한으로 서비스 구동 제한"
SEVERITY="중"

GUIDELINE_PURPOSE="root 권한을 제한적으로 사용함으로써 시스템의 손상, 데이터의 유출 및 변조 등을 차단하여 보안 위협을 방지하기 위함"
GUIDELINE_THREAT="root 권한으로 서비스를 구동할 경우 시스템 손상, 데이터 유출 및 변조, 감사 및 추적의 어려움 등으로 인해 서비스 공격의 표적이 될 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="DBMS가 root 계정 또는 root 권한이 아닌 별도의 계정 및 권한으로 구동되고 있는 경우"
GUIDELINE_CRITERIA_BAD="DBMS가 root 계정 또는 root 권한으로 구동되고 있는 경우"
GUIDELINE_REMEDIATION="DBMS 구동 계정 변경"

diagnose() {
    invoke_cubrid_linux_check "${ITEM_ID}"

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