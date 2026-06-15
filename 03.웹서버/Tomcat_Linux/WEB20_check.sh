#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : WEB-20
# @Category    : Server
# @Platform    : Tomcat_Linux
# @Severity    : 상
# @Title       : SSL/TLS 활성화
# @Description : 웹 서비스 SSL/TLS 활성화 여부 점검
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

ITEM_ID="WEB-20"
ITEM_NAME="SSL/TLS 활성화"
SEVERITY="상"

GUIDELINE_PURPOSE="서버와 클라이언트 간 통신 시 데이터의 평문 전송을 사용하지 않고 데이터가 암호화되는 SSL/TLS 인증 암호화 접속을 통해 스니 핑을 통한 정보 유출의 위험을 방지하기 위함"
GUIDELINE_THREAT="웹상의 데이터 통신 시 서버와 클라이언트 간에 데이터를 평문 전송하는 경우, 간단한 도청(스니핑)을 통해 정보가 탈취 및 도용될 위험이 존재함 SSL/TLS가 활성화되어 있지 않을 경우, 데이터는 암호화되지 않아 공격자가 중간에서 데이터를 가로채거나 도청할 수 있으며, 더 나아가 평문으로 전송되어 중간에서 변경될 우려가 있어 데이터의 정확성이 훼손될 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="SSL/TLS 설정이 활성화되어 있는 경우"
GUIDELINE_CRITERIA_BAD="SSL/TLS 설정이 비활성화되어 있는 경우"
GUIDELINE_REMEDIATION="웹 서비스 내 SSL/TLS 활성화 설정"

diagnose() {
    echo "진단 항목: ${ITEM_ID} - ${ITEM_NAME}"

    local diagnosis_result="N/A"
    local status="N/A"
    local inspection_summary=""
    local command_result=""
    local command_executed=""

    # 점검 대상 외 항목 (Out-of-target)
    # WEB-20(SSL/TLS 활성화)의 점검 대상은 Apache, Nginx, IIS, WebtoB이며 Tomcat은 제외됨
    # (docs/guideline_metadata.json target: "Apache, Nginx, IIS, WebtoB")
    # 따라서 Tomcat에서는 본 항목을 점검하지 않고 N/A로 처리함
    diagnosis_result="N/A"
    status="N/A"
    inspection_summary="WEB-20(SSL/TLS 활성화) 항목의 점검 대상은 Apache, Nginx, IIS, WebtoB이며 Tomcat은 점검 대상에 포함되지 않으므로 N/A로 판단합니다."
    command_executed="N/A (Tomcat is out of scope for WEB-20)"
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
