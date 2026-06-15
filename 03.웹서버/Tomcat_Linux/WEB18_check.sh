#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : WEB-18
# @Category    : Server
# @Platform    : Tomcat_Linux
# @Severity    : 상
# @Title       : 웹 서비스 WebDAV 비활성화
# @Description : WebDAV 모듈 비활성화 여부 점검
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

ITEM_ID="WEB-18"
ITEM_NAME="웹 서비스 WebDAV 비활성화"
SEVERITY="상"

GUIDELINE_PURPOSE="WebDAV 서비스를 비활성화하여,WebDAV에서 발견되는 다수의 인증 우회 취약점을 제거하고자함"
GUIDELINE_THREAT="WebDAV가 활성화되어 있는 경우 웹 서비스에 악의적으로 작성된 요청을 이용하여 인증을 우회함으로써 비밀번호로 보호된 WebDAV의 자원에 접근 (디렉터리 열람, 파일 다운로드 등)이 가능하며, WebDAV에 의해 호출된 일부 구성 요소에 매개 변수를 정확하게 점검하지 않는 결함이 존재하여, 이로 인해 버퍼 오버 런이 발생할 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="WebDAV 서비스를 비활성화하고 있는 경우"
GUIDELINE_CRITERIA_BAD="WebDAV 서비스를 활성화하고 있는 경우"
GUIDELINE_REMEDIATION="WebDAV 서비스 비활성화 설정"

diagnose() {
    echo "진단 항목: ${ITEM_ID} - ${ITEM_NAME}"

    local diagnosis_result="N/A"
    local status="N/A"
    local inspection_summary=""
    local command_result=""
    local command_executed=""

    # 점검 대상 외 항목 (Out-of-target)
    # WEB-18(WebDAV 비활성화)의 점검 대상은 Apache, Nginx, IIS, WebtoB이며 Tomcat은 제외됨
    # (docs/guideline_metadata.json target: "Apache, Nginx, IIS, WebtoB")
    # 따라서 Tomcat에서는 본 항목을 점검하지 않고 N/A로 처리함
    diagnosis_result="N/A"
    status="N/A"
    inspection_summary="WEB-18(웹 서비스 WebDAV 비활성화) 항목의 점검 대상은 Apache, Nginx, IIS, WebtoB이며 Tomcat은 점검 대상에 포함되지 않으므로 N/A로 판단합니다."
    command_executed="N/A (Tomcat is out of scope for WEB-18)"
    command_result="점검 대상(target): Apache, Nginx, IIS, WebtoB / 현재 플랫폼: Tomcat_Linux (점검 대상 외)"

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
