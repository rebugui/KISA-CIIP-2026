#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Version: 1.0.1
# @Last Updated: 2026-05-24
# ============================================================================
# [Assessment Item]
# @ID          : D-13
# @Category    : DBMS>2.접근관리
# @Platform    : Altibase_Linux
# @Severity    : 중
# @Title       : 불필요한 ODBC/OLE-DB 데이터 소스와 드라이브를 제거하여 사용
# @Description : docs/guideline_metadata.json and docs guidelines must be applied before final automation.
# @Reference   : docs/guideline_metadata.json and docs guideline Markdown
# ============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"
source "${SCRIPT_DIR}/altibase_linux_lib.sh"

ITEM_ID="D-13"
ITEM_NAME="불필요한 ODBC/OLE-DB 데이터 소스와 드라이브를 제거하여 사용"
SEVERITY="중"

GUIDELINE_PURPOSE="불필요한 데이터 소스 및 드라이버를 제거함으로써 비인가자에 의한 데이터베이스 접속 및 자료 유출을 차단하기 위함"
GUIDELINE_THREAT="불필요한 ODBC/OLE-DB 데이터 소스를 통한 비인가자의 데이터베이스 접속 및 주요 정보 유출에 대한 위험이 발생할 수 있음"
GUIDELINE_CRITERIA_GOOD="불필요한 ODBC/OLE-DB가 설치되지 않은 경우"
GUIDELINE_CRITERIA_BAD="불필요한 ODBC/OLE-DB가 설치된 경우"
GUIDELINE_REMEDIATION="불필요한 ODBC/OLE-DB 제거"

diagnose() {
    invoke_altibase_linux_check "${ITEM_ID}"

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