#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : WEB-24
# @Category    : Web Server
# @Platform    : Apache
# @Severity    : 중
# @Title       : X-Frame-Options 헤더 설정
# @Description : Clickjacking 공격을 방지하기 위해 X-Frame-Options 헤더를 설정합니다. DENY 또는 SAMEORIGIN 값을 사용하여 페이지가 다른 사이트의 프레임에 로드되는 것을 방지해야 합니다.
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

ITEM_ID="WEB-24"
ITEM_NAME="별도의 업로드 경로 사용 및 권한 설정"
SEVERITY="중"
GUIDELINE_PURPOSE="웹 서버 루트 디렉터리 내 업로드 경로가 아닌 별도의 디렉터리에서 파일을 업로드할 수 있도록하여 루트 디렉터리 내 악의적인 파일 업로드 및 실행을 방지하기 위함"
GUIDELINE_THREAT="웹 서버 내 별도의 파일 업로드 경로 사용 및 적절한 권한 설정을 하지 않을 경우, 악의적인 목적을 가진 파일을 업로드하여 시스템 침투, 중요 정보 유출 및 변조 등의 침해 사고의 가능성이 있음"
GUIDELINE_CRITERIA_GOOD="별도의 업로드 경로를 사용하고 일반 사용자의 접근 권한이 부여되지 않은 경우"
GUIDELINE_CRITERIA_BAD="별도의 업로드 경로를 사용하지 않거나, 일반 사용자의 접근 권한이 부여된 경우"
GUIDELINE_REMEDIATION="기본 경로가 아닌 별도의 업로드 경로를 지정하고, 해당 경로에 대한 일반 사용자의 접근 권한을 제한하도록 설정"

diagnose() {
    echo "진단 항목: ${ITEM_ID} - ${ITEM_NAME}"
    local diagnosis_result="MANUAL"
    local status="수동진단"
    local inspection_summary="Apache 서버의 X-Frame-Options 헤더 설정 설정을 수동으로 확인해야 합니다. 웹 서버 설정 파일에서 해당 헤더 또는 메서드 제한을 검토하세요."
    local command_result=""
    local command_executed=""
    
    if [ 24 -eq 23 ]; then
        # HTTP Methods restriction
        inspection_summary="HTTP 메서드 제한 설정을 확인하세요. Apache: LimitExcept, Nginx: limit_except, IIS: Request Filtering, Tomcat: security-constraint"
    elif [ 24 -eq 24 ]; then
        # X-Frame-Options
        inspection_summary="X-Frame-Options 헤더 설정을 확인하세요. Apache: Header always set X-Frame-Options DENY, Nginx: add_header X-Frame-Options DENY"
    elif [ 24 -eq 25 ]; then
        # X-XSS-Protection
        inspection_summary="X-XSS-Protection 헤더 설정을 확인하세요. Apache/Nginx: add_header X-XSS-Protection '1; mode=block'"
    elif [ 24 -eq 26 ]; then
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
