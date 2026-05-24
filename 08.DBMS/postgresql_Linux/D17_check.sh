#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"

ITEM_ID="D-17"
ITEM_NAME="AuditTable은 데이터베이스 관리자 계정으로 접근하도록 제한"
SEVERITY="하"

GUIDELINE_PURPOSE="Audit Table 접근 권한을 관리자 계정으로 제한함으로써 비인가자가 감사 데이터의 수정, 삭제하는 것을 방지하고, 감사 기록 의무 결성과 신뢰성을 보장하기 위함"
GUIDELINE_THREAT="Audit Table이 데이터베이스 관리자 계정에 속하지 않을 경우, 비인가자가 감사 데이터의 수정, 삭제 등을 수행할 수 있으므로 보안 사고 발생 시 원인 분석이 불가능하게 되며, 이로 인해 재발 방지를 위한 조치를 할 수 없으므로 동일 유형의 공격이 반복되거나 시스템 취약점의 악용이 반복될 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="AuditTable 접근 권한이 관리자 계정으로 설정한 경우"
GUIDELINE_CRITERIA_BAD="AuditTable 접근 권한이 일반 계정으로 설정한 경우"
GUIDELINE_REMEDIATION="AuditTable 접근 권한을 관리자 계정으로 제한"

diagnose() {
    local diagnosis_result="N/A"
    local status="N/A"
    local inspection_summary="postgresql_Linux is not a target platform for D-17 according to docs/guideline_metadata.json."
    local command_result="D-17 target: Oracle DB, Altibase, Tibero 등"
    local command_executed="guideline_metadata.json D-17 target platform review"

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
