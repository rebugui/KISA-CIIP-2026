#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Version: 1.0.1
# @Last Updated: 2026-05-24
# ============================================================================
# [Assessment Item]
# @ID          : D-03
# @Category    : DBMS>1.계정관리
# @Platform    : Cubrid_Linux
# @Severity    : 상
# @Title       : 비밀번호 사용 기간 및 복잡 도를 기관의 정책에 맞도록 설정
# @Description : docs/guideline_metadata.json and docs guidelines must be applied before final automation.
# @Reference   : docs/guideline_metadata.json and docs guideline Markdown
# ============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"
source "${SCRIPT_DIR}/cubrid_linux_lib.sh"

ITEM_ID="D-03"
ITEM_NAME="비밀번호 사용 기간 및 복잡 도를 기관의 정책에 맞도록 설정"
SEVERITY="상"

GUIDELINE_PURPOSE="비밀번호 사용 기간 및 복잡 도 설정 유무를 점검하여 비인가자의 비밀번호 추측 공격(무차별 대입 공격, 사전 대입 공격 등)에 대한 대비가 되어 있는지 확인하기 위함"
GUIDELINE_THREAT="비밀번호 사용 기간 및 복잡 도 설정이 되어 있지 않으면 비인가자가 비밀번호 추측 공격을 통해 획득한 계정의 비밀번호를 이용하여 DB에 접근할 수 있는 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="기관 정책에 맞게 비밀번호 사용 기간 및 복잡 도 설정이 적용된 경우"
GUIDELINE_CRITERIA_BAD="기관 정책에 맞게 비밀번호 사용 기간 및 복잡 도 설정이 적용되지 않은 경우"
GUIDELINE_REMEDIATION="기관 정책에 맞게 비밀번호 사용 기간 및 복잡 도 정책 설정"

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