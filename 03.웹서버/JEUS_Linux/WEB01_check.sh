#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Version: 1.0.1
# @Last Updated: 2026-05-24
# ============================================================================
# [Assessment Item]
# @ID          : WEB-01
# @Category    : 웹서비스>1.계정관리
# @Platform    : JEUS_Linux
# @Severity    : 상
# @Title       : Default 관리자 계정 명 변경
# @Description : docs/guideline_metadata.json and docs guidelines must be applied before final automation.
# @Reference   : docs/guideline_metadata.json and docs guideline Markdown
# ============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"
source "${SCRIPT_DIR}/jeus_linux_lib.sh"

ITEM_ID="WEB-01"
ITEM_NAME="Default 관리자 계정 명 변경"
SEVERITY="상"

GUIDELINE_PURPOSE="기본 관리자 계정 명과 같은 알려진 계정 명을 유추하기 어려운 계정 명으로 변경 후 사용하여 공격자에 의한 추측 공격 및 무단 접근 등을 방지하고 보안을 강화하기 위함"
GUIDELINE_THREAT="기본 관리자 계정 명을 변경하지 않고 사용할 경우, 공격자에 의한 계정 및 비밀번호 추측 공격이 가능하고, 이를 통해 불법적인 접근, 데이터 유출, 시스템 장애 등의 보안 사고가 발생할 수 있는 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="관리자 페이지를 사용하지 않거나, 계정 명이 기본 계정 명으로 설정되어 있지 않은 경우"
GUIDELINE_CRITERIA_BAD="계정 명이 기본 계정 명으로 설정되어 있거나, 추측하기 쉬운 문자 조합으로 이루어진 계정 명을 사용하는 경우"
GUIDELINE_REMEDIATION="기본 관리자 계정 명을 추측하기 어려운 계정 명으로 설정"

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