#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : WEB-21
# @Category    : Server
# @Platform    : Tomcat_Linux
# @Severity    : 중
# @Title       : HTTP 리디렉션
# @Description : HTTP에서 HTTPS로의 리디렉션 설정 여부 점검
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

ITEM_ID="WEB-21"
ITEM_NAME="HTTP 리디렉션"
SEVERITY="중"

GUIDELINE_PURPOSE="HTTP 차단 및 HTTPS로 Redirection 활성화를 통해 평문으로 전송되는 데이터를 암호화하여 공격자의 데이터 스니 핑에 대비하기 위함"
GUIDELINE_THREAT="HTTP 통신은 암호화 전송이 아닌 평문 전송을 하므로 공격자가 스니핑을 시도할 경우 관리자의 ID, 비밀번호가 노출되어 악의적 사용자가 관리자 계정을 탈취할 수 있는 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="HTTP 접근 시 HTTPSRedirection이 활성화된 경우"
GUIDELINE_CRITERIA_BAD="HTTP 접근 시 HTTPSRedirection이 비활성화된 경우"
GUIDELINE_REMEDIATION="HTTP Redirection 활성화 설정"

diagnose() {
    echo "진단 항목: ${ITEM_ID} - ${ITEM_NAME}"

    local diagnosis_result="N/A"
    local status="N/A"
    local inspection_summary=""
    local command_result=""
    local command_executed=""

    # 점검 대상 외 항목 (Out-of-target)
    # WEB-21(HTTP 리디렉션)의 점검 대상은 Apache, Nginx, IIS, WebtoB이며 Tomcat은 제외됨
    # (docs/guideline_metadata.json target: "Apache, Nginx, IIS, WebtoB")
    # 따라서 Tomcat에서는 본 항목을 점검하지 않고 N/A로 처리함
    diagnosis_result="N/A"
    status="N/A"
    inspection_summary="WEB-21(HTTP 리디렉션) 항목의 점검 대상은 Apache, Nginx, IIS, WebtoB이며 Tomcat은 점검 대상에 포함되지 않으므로 N/A로 판단합니다."
    command_executed="N/A (Tomcat is out of scope for WEB-21)"
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
