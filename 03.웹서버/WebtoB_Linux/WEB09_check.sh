#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Version: 1.0.1
# @Last Updated: 2026-05-24
# ============================================================================
# [Assessment Item]
# @ID          : WEB-09
# @Category    : 웹서비스>2.서비스관리
# @Platform    : WebtoB_Linux
# @Severity    : 상
# @Title       : 웹 서비스 프로세스 권한 제한
# @Description : docs/guideline_metadata.json and docs guidelines must be applied before final automation.
# @Reference   : docs/guideline_metadata.json and docs guideline Markdown
# ============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"
source "${SCRIPT_DIR}/webtob_linux_lib.sh"

ITEM_ID="WEB-09"
ITEM_NAME="웹 서비스 프로세스 권한 제한"
SEVERITY="상"

GUIDELINE_PURPOSE="웹 프로세스가 웹 서비스 운영에 필요한 최소한의 권한만을 갖도록 제한함으로써 웹 사이트 방문자가 웹 서비스의 취약점을 이용해 시스템에 대한 어떤 권한도 획득할 수 없도록하여 침해 사고 발생 시 피해 범위 확산을 방지하기 위함"
GUIDELINE_THREAT="웹 프로세스 권한을 제한하지 않은 경우, 웹 사이트 방문자가 웹 서비스의 취약점을 이용하여 시스템 권한을 획득할 수 있으며, 웹 취약점을 통해 접속 권한을 획득한 경우에는 관리자 권한을 획득하여 서버에 접속 후 정보의 변경, 훼손 및 유출될 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="웹 프로세스(웹 서비스)가 관리자 권한이 부여된 계정이 아닌 운영에 필요한 최소한의 권한을 가진 별도의 계정으로 구동되고 있는 경우"
GUIDELINE_CRITERIA_BAD="웹 프로세스(웹 서비스)가 운영에 필요한 최소한의 권한을 가진 별도의 계정이 아닌 관리자 권한이 부여된 계정으로 구동되고 있는 경우"
GUIDELINE_REMEDIATION="웹 서비스 프로세스 구동 시 관리자 권한이 아닌 운영에 필요한 최소한의 권한을 가진 계정으로 구동 설정"
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