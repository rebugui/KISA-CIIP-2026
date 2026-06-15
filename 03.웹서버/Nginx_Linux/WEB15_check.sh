#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : WEB-15
# @Category    : Web Server
# @Platform    : Nginx_Linux
# @Severity    : 상
# @Title       : 웹 서비스의 불필요한 스크립트 매핑 제거
# @Description : 불필요한 스크립트 매핑 제거 여부 점검. 점검 대상: Tomcat, IIS, JEUS (Nginx 비대상)
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

ITEM_ID="WEB-15"
ITEM_NAME="웹 서비스의 불필요한 스크립트 매핑 제거"
SEVERITY="상"

GUIDELINE_PURPOSE="웹 서비스에서 사용하지 않는 불필요 스크립트 매핑이 존재하는지 점검하여 잠재적 보안 위협을 방지하기 위함"
GUIDELINE_THREAT="웹 서비스에서 불필요한 스크립트 매핑을 제거하지 않은 경우, 버퍼오버플로우(Buffer Overflow), 서비스 거부 공격(Denial of Service), 크로스 사이트 스크립 팅(CrossSiteScripting) 등의 공격 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="불필요한 스크립트 매핑이 존재하지 않는 경우"
GUIDELINE_CRITERIA_BAD="불필요한 스크립트 매핑이 존재하는 경우"
GUIDELINE_REMEDIATION="불필요한 스크립트 매핑 존재 여부 점검 및 제거 설정"

diagnose() {
    echo "진단 항목: ${ITEM_ID} - ${ITEM_NAME}"

    # WEB-15 점검 대상은 Tomcat, IIS, JEUS 이며 Nginx는 비대상(out-of-target)이다.
    # (docs/guideline_metadata.json WEB-15 target: "Tomcat, IIS, JEUS")
    # 따라서 Nginx_Linux에서는 N/A로 고정한다.
    local diagnosis_result="N/A"
    local status="N/A"
    local inspection_summary="WEB-15는 Tomcat, IIS, JEUS를 점검 대상으로 하며 Nginx는 비대상입니다(docs/guideline_metadata.json WEB-15 target). 불필요한 스크립트 매핑 점검은 Nginx에 적용되지 않습니다."
    local command_result="WEB-15 target: Tomcat, IIS, JEUS. Nginx is out of scope."
    local command_executed="docs/guideline_metadata.json WEB-15 target platform review"

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
