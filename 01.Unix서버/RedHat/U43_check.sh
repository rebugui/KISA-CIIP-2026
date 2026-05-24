#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-28
# ============================================================================
# [점검 항목 상세]
# @ID          : U-43
# @Category    : UNIX > 3. 서비스 관리
# @Platform    : SOLARIS, LINUX, AIX, HP-UX 등
# @Severity    : (상)
# @Title       : NIS, NIS+ 점검
# @Description : 계정 정보를 네트워크로 공유하는 NIS 서비스의 활성화 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/metadata_parser.sh"

ITEM_ID="U-43"
ITEM_NAME="NIS, NIS+ 점검"
SEVERITY="상"

# 가이드라인 정보 (PDF 내용 반영)
GUIDELINE_PURPOSE="안전하지 않은 NIS 서비스를 비활성화하고 안전한 NIS + 서비스를 활성화하여 시스템의 보안성을 높이기 위함"
GUIDELINE_THREAT="NIS 서비스가 활성화된 경우, 비인가자가 타 시스템의 root 권한까지 탈취할 수 있는 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="NIS 서비스가 비활성화되어 있거나, 불가피하게 사용 시 NIS +서비스를 사용하는 경우"
GUIDELINE_CRITERIA_BAD="NIS 서비스가 활성화된 경우"
GUIDELINE_REMEDIATION="NIS 관련 서비스 비활성화 설정"

diagnose() {
    local status="양호"
    diagnosis_result="GOOD"
    local inspection_summary="NIS 관련 서비스가 비활성화되어 있습니다."
    local command_result=""
    local command_executed="ps -ef | grep -E 'ypserv|ypbind'"

    local nis_procs=$(ps -ef | grep -Ei "ypserv|ypbind|yppasswdd" | grep -v grep || echo "")

    if [ -n "$nis_procs" ]; then
        status="취약"
        diagnosis_result="VULNERABLE"
        inspection_summary="계정 정보 유출 위험이 있는 NIS 서비스가 활성화되어 있습니다."
        command_result="NIS 프로세스 실행 중: [ $(echo $nis_procs | awk '{print $8}' | xargs) ]"
    else
        command_result="NIS 관련 서비스가 실행 중이지 않습니다."
    fi

    save_dual_result \
        "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" \
        "${inspection_summary}" "${command_result}" "${command_executed}" \
        "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" \
        "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
    
    return 0
}

main() { [ "$EUID" -ne 0 ] && exit 1; diagnose; }
main "$@"
