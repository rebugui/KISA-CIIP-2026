#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Version: 1.0.1
# @Last Updated: 2026-05-24
# ============================================================================
# [Assessment Item]
# @ID          : D-18
# @Category    : DBMS>3.옵션관리
# @Platform    : Cubrid_Linux
# @Severity    : 상
# @Title       : 응용 프로그램 또는 DBA 계정의 Role이 Public으로 설정되지 않도록 조정
# @Description : docs/guideline_metadata.json and docs guidelines must be applied before final automation.
# @Reference   : docs/guideline_metadata.json and docs guideline Markdown
# ============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"
source "${SCRIPT_DIR}/cubrid_linux_lib.sh"

ITEM_ID="D-18"
ITEM_NAME="응용 프로그램 또는 DBA 계정의 Role이 Public으로 설정되지 않도록 조정"
SEVERITY="상"

GUIDELINE_PURPOSE="응용 프로그램 또는 DBA 계정의 Role을 점검하여 일반 계정으로 응용 프로그램 테이블이나 DBA 테이블의 접근을 차단하기 위함"
GUIDELINE_THREAT="응용 프로그램 또는 DBA 계정의 Role이 Public으로 설정된 경우 일반 계정에서도 응용 프로그램 테이블 및 DBA 테이블로 접근할 수 있으므로 중요 정보 유출의 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="DBA 계정의 Role이 Public으로 설정되지 않은 경우"
GUIDELINE_CRITERIA_BAD="DBA 계정의 Role이 Public으로 설정된 경우"
GUIDELINE_REMEDIATION="DBA 계정의 Role 설정에서 Public 그룹 권한 취소"

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