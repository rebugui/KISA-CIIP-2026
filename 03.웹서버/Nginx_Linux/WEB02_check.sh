#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : WEB-02
# @Category    : Web Server
# @Platform    : Nginx_Linux
# @Severity    : 상
# @Title       : 취약한 비밀번호 사용 제한
# @Description : 관리자 계정의 취약한 비밀번호 설정 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==========================================================================

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

ITEM_ID="WEB-02"
ITEM_NAME="취약한 비밀번호 사용 제한"
SEVERITY="상"

GUIDELINE_PURPOSE="관리자 계정의 비밀번호가 복잡 도 기준에 맞게 적용되어 있는지 점검하여, 비인가자에 의한 비밀번호 유추 공격 및 관리자 권한 탈취 등을 방지하기 위함"
GUIDELINE_THREAT="관리자 계정의 비밀번호를 취약하게 설정하여 사용하는 경우, 비인가자의 비밀번호 유추 공격으로 관리자 권한 탈취 및 시스템 침입 등의 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="관리자 비밀번호가 암호화되어 있거나, 유추하기 어려운 비밀번호로 설정된 경우"
GUIDELINE_CRITERIA_BAD="관리자 비밀번호가 암호화되어 있지 않거나, 유추하기 쉬운 비밀번호로 설정된 경우"
GUIDELINE_REMEDIATION="복잡 도 기준에 맞는 추측하기 어려운 비밀번호 설정"

diagnose() {
    echo "진단 항목: ${ITEM_ID} - ${ITEM_NAME}"

    local diagnosis_result="N/A"
    local status="N/A"
    local inspection_summary=""
    local command_result="N/A"
    local command_executed="N/A"

    # KISA 가이드라인 WEB-02 대상: Tomcat, IIS, JEUS only
    inspection_summary="WEB-02(취약한비밀번호사용제한) 항목의 KISA 가이드라인 점검 대상은 'Tomcat, IIS, JEUS'입니다. Nginx는 점검 대상이 아닙니다."

    # Run-all 모드 확인
    # 결과 저장 (run_all 모드는 라이브러리에서 판단)
    save_dual_result "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" "${inspection_summary}" "${command_result}" "${command_executed}" "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
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
