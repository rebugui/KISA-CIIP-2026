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
# @Platform    : Nginx_Linux
# @Severity    : 상
# @Title       : 주기적 보안 패치 및 벤더 권고 사항 적용
# @Description : 주기적 보안 패치 및 벤더 권고 사항 적용 여부 점검
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
    local inspection_summary=""
    local command_result=""
    local command_executed=""

    # Process check
    if command -v pgrep >/dev/null; then
    if ! pgrep -x "nginx" > /dev/null; then
        diagnosis_result="N/A"
        status="N/A"
        inspection_summary="Nginx 웹 서버가 실행 중이 아닙니다."
        command_result="Nginx process not found"
        command_executed="pgrep -x nginx"
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
    fi
    else
        echo "[INFO] pgrep command missing, skipping process check."
    fi

    # Get Nginx version
    local nginx_version=""
    local version_output=""

    if command -v nginx >/dev/null 2>&1; then
        version_output=$(nginx -v 2>&1 || true)
        nginx_version=$(echo "${version_output}" | grep -oE "nginx/[0-9]+\.[0-9]+\.[0-9]+" || echo "version detection failed")
        command_executed="nginx -v"
        command_result="${version_output}"
    else
        command_executed="nginx -v"
        command_result="nginx command not found"
    fi

    # Version check guidance (this is MANUAL diagnosis)
    local manual_check_guidance=""
    manual_check_guidance=$'\n'"[수동진단 가이드]"$'\n'
    manual_check_guidance+="1. 현재 버전: ${nginx_version}"$'\n'
    manual_check_guidance+="2. Nginx 공식 웹사이트(https://nginx.org)에서 최신 안정 버전 확인"$'\n'
    manual_check_guidance+="3. Nginx 보안 권고사항 확인: https://nginx.org/en/security_advisories.html"$'\n'
    manual_check_guidance+="4. 주요 보안 업데이트 확인"$'\n'
    manual_check_guidance+="   - 1.18.0 이상: 안정 버전 권장"$'\n'
    manual_check_guidance+="   - 1.20.0+ 이상: 최신 보안 패치 포함"$'\n'
    manual_check_guidance+="5. OS 패키지 매니저로 업데이트: apt-get upgrade nginx 또는 yum update nginx"

    inspection_summary="Nginx 버전 확인 및 주기적 보안 패치는 수동 진단이 필요합니다.${manual_check_guidance}"

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
