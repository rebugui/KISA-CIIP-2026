#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : WEB-23
# @Category    : Web Server
# @Platform    : Nginx_Linux
# @Severity    : 중
# @Title       : LDAP 알고리즘 적절하게 구성
# @Description : LDAP 연결 시 안전한 비밀번호 다이제스트 알고리즘 사용 여부 점검. 점검 대상: Tomcat (Nginx 비대상)
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

ITEM_ID="WEB-23"
ITEM_NAME="LDAP 알고리즘 적절하게 구성"
SEVERITY="중"

GUIDELINE_PURPOSE="LDAP 연결 시 안전한 비밀번호 다이제스트 알고리즘을 사용하여 비밀번호 평문 전송 시 발생할 수 있는 스니핑 등의 공격에 대비하기 위함"
GUIDELINE_THREAT="취약한 다이제스트 알고리즘을 사용하는 경우 공격자의 스니핑, 무차별 공격 등을 통해 인증 정보가 노출될 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="LDAP 연결 인증 시 안전한 비밀번호 다이제스트 알고리즘을 사용하는 경우"
GUIDELINE_CRITERIA_BAD="LDAP 연결 인증 시 안전한 비밀번호 다이제스트 알고리즘을 사용하지 않는 경우"
GUIDELINE_REMEDIATION="LDAP 연결 인증 시 SHA-256 이상의 알고리즘을 사용하도록 설정"

diagnose() {
    echo "진단 항목: ${ITEM_ID} - ${ITEM_NAME}"

    # WEB-23(LDAP 알고리즘 적절하게 구성) 점검 대상은 Tomcat 이며 Nginx는 비대상(out-of-target)이다.
    # (docs/guideline_metadata.json WEB-23 target: "Tomcat")
    # 따라서 Nginx_Linux에서는 N/A로 고정한다. (기존 웹쉘 파일 스캔 로직은 WEB-23 항목과 무관하여 제거함)
    local diagnosis_result="N/A"
    local status="N/A"
    local inspection_summary="WEB-23(LDAP 다이제스트 알고리즘 점검)은 Tomcat을 점검 대상으로 하며 Nginx는 비대상입니다(docs/guideline_metadata.json WEB-23 target). LDAP 연결 알고리즘 점검은 Nginx에 적용되지 않습니다."
    local command_result="WEB-23 target: Tomcat. Nginx is out of scope."
    local command_executed="docs/guideline_metadata.json WEB-23 target platform review"

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
