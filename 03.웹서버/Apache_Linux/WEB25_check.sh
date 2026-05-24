#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : WEB-25
# @Category    : Web Server
# @Platform    : Apache_Linux
# @Severity    : 상
# @Title       : 주기적 보안 패치 및 벤더 권고 사항 적용
# @Description : XSS(Cross-Site Scripting) 공격으로부터 보호하기 위해 X-XSS-Protection 헤더를 설정합니다. 브라우저의 내장 XSS 필터를 활성화하여 보안을 강화해야 합니다.
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

ITEM_ID="WEB-25"
ITEM_NAME="주기적 보안 패치 및 벤더 권고 사항 적용"
SEVERITY="상"
GUIDELINE_PURPOSE="주기적인 최신 보안 패치를 통해 보안성 및 시스템 안정성을 확보하기 위함"
GUIDELINE_THREAT="주기적으로 최신 보안 패치를 적용하지 않을 경우, 알려진 취약점을 이용한 공격 또는 새로운 공격에 대한 침해 사고 발생 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="최신 보안 패치가 적용되어 있으며, 패치 적용 정책을 수립하여 주기적인 패치 관리를 하는 경우"
GUIDELINE_CRITERIA_BAD="최신 보안 패치가 적용되어 있지 않거나 패치 적용 정책을 수립 및 주기적인 패치 관리를 하지"
GUIDELINE_REMEDIATION="패치 적용에 따른 서비스 영향 정도를 정확히 파악하여 주기적인 패치 적용 정책 수립 및 적용하도록 설정"

diagnose() {
    echo "진단 항목: ${ITEM_ID} - ${ITEM_NAME}"
    local diagnosis_result="MANUAL"
    local status="수동진단"
    local inspection_summary="Apache 서버의 X-XSS-Protection 헤더 설정 설정을 수동으로 확인해야 합니다. 웹 서버 설정 파일에서 해당 헤더 또는 메서드 제한을 검토하세요."
    local command_result=""
    local command_executed=""
    
    if [ 25 -eq 23 ]; then
        # HTTP Methods restriction
        inspection_summary="HTTP 메서드 제한 설정을 확인하세요. Apache: LimitExcept, Nginx: limit_except, IIS: Request Filtering, Tomcat: security-constraint"
    elif [ 25 -eq 24 ]; then
        # X-Frame-Options
        inspection_summary="X-Frame-Options 헤더 설정을 확인하세요. Apache: Header always set X-Frame-Options DENY, Nginx: add_header X-Frame-Options DENY"
    elif [ 25 -eq 25 ]; then
        # X-XSS-Protection
        inspection_summary="X-XSS-Protection 헤더 설정을 확인하세요. Apache/Nginx: add_header X-XSS-Protection '1; mode=block'"
    elif [ 25 -eq 26 ]; then
        # X-Content-Type-Options
        inspection_summary="X-Content-Type-Options 헤더 설정을 확인하세요. Apache/Nginx: add_header X-Content-Type-Options nosniff"
    fi
    
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
