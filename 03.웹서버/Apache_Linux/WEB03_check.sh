#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : WEB-03
# @Category    : Web Server
# @Platform    : Apache_Linux
# @Severity    : 상
# @Title       : 비밀번호 파일 권한 관리
# @Description : 비밀번호 파일에 대해 적절한 접근 권한 설정 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================


set -euo pipefail

# 스크립트 디렉토리 설정
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../../lib"

# 필수 라이브러리 로드
source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/command_validator.sh"
source "${LIB_DIR}/timeout_handler.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/metadata_parser.sh"

ITEM_ID="WEB-03"
ITEM_NAME="비밀번호 파일 권한 관리"
SEVERITY="상"

GUIDELINE_PURPOSE="비밀번호 파일의 접근 권한을 적절하게 설정하여 비인가자가 비밀번호 파일에 무단 접근 및 유출 등을 방지하기 위함"
GUIDELINE_THREAT="비밀번호 파일의 권한을 적절하게 설정하지 않은 경우, 비인가자에게 비밀번호 정보가 노출될 수 있고 웹 서버에 접속하는 등의 침해 사고가 발생할 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="비밀번호 파일에 권한이 600 이하로 설정된 경우"
GUIDELINE_CRITERIA_BAD="비밀번호 파일에 권한이 600 초과로 설정된 경우"
GUIDELINE_REMEDIATION="비밀번호 파일 권한 600 이하로 설정"

diagnose() {
    echo "진단 항목: ${ITEM_ID} - ${ITEM_NAME}"

    local diagnosis_result="N/A"
    local status="N/A"
    local inspection_summary="이 항목은 Tomcat/IIS/JEUS 대상이며 Apache는 해당하지 않습니다. Apache는 .htpasswd 파일을 사용하지만 이는 OS 파일 권한 관리(600 또는 640 권한 권장)에 따르며, KISA 가이드라인의 WEB-03은 Tomcat(tomcat-users.xml), IIS(SAM), JEUS(accounts.xml) 대상입니다."
    local command_result="N/A"
    local command_executed="N/A"

    # Run-all 모드 확인
    save_dual_result \
        "${ITEM_ID}" \
        "${ITEM_NAME}" \
        "${status}" \
        "${diagnosis_result}" \
        "${inspection_summary}" \
        "${command_result}" \
        "${command_executed}" \
        "${GUIDELINE_PURPOSE}" \
        "${GUIDELINE_THREAT}" \
        "${GUIDELINE_CRITERIA_GOOD}" \
        "${GUIDELINE_CRITERIA_BAD}" \
        "${GUIDELINE_REMEDIATION}"

    # 결과 저장 확인
    verify_result_saved "${ITEM_ID}"

    return 0
}

main() {
    show_diagnosis_start "${ITEM_ID}" "${ITEM_NAME}"
    check_disk_space
    diagnose
    show_diagnosis_complete "${ITEM_ID}" "${diagnosis_result:-UNKNOWN}"
}

if true; then
    main "$@"
fi
