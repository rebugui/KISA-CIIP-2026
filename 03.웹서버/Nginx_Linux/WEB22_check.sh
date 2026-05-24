#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : WEB-22
# @Category    : Web Server
# @Platform    : Nginx
# @Severity    : 상
# @Title       : 에러페이지관리
# @Description : 커스텀 에러 페이지 설정 여부 점검
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

ITEM_ID="WEB-22"
ITEM_NAME="에러 페이지 관리"
SEVERITY="하"

GUIDELINE_PURPOSE="에러 페이지에서 웹 서버 버전 및 종류, OS 정보 등 웹 서버와 관련된 불필요한 정보 및 에러 코드를 통한 기술적 취약점이 노출되는 것을 최소화하기 위함"
GUIDELINE_THREAT="에러 페이지에서 불필요한 정보가 노출될 경우 공격자에 의해 해당 버전의 알려진 취약점 등을 이용하여 시스템 구조와 특성 노출 및 해당 취약점을 통한 공격의 위험이 존재함 필수 에러 코드에 대해 일원화된 에러 페이지로 관리하지 않는 경우 에러 코드를 통해 각종 정보 유추의 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="웹 서비스 에러 페이지가 별도로 지정된 경우"
GUIDELINE_CRITERIA_BAD="웹 서비스 에러 페이지가 별도로 지정되지 않거나 에러 발생 시 중요 정보가 노출되는 경우"
GUIDELINE_REMEDIATION="필수 에러 코드에 대해 일원화된 에러 페이지 사용 및 에러 페이지 내 불필요 정보 노출 제한 설정"

diagnose() {
    echo "진단 항목: ${ITEM_ID} - ${ITEM_NAME}"

    local diagnosis_result="UNKNOWN"
    local status="미진단"
    local inspection_summary=""
    local command_result=""
    local command_executed=""
    local error_page_count=0

    # Process check (Updated for Docker)
    if command -v pgrep >/dev/null; then
        if ! pgrep -x "nginx" >/dev/null 2>&1; then
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

    local nginx_conf_locations=(
        "/etc/nginx/nginx.conf"
        "/etc/nginx/conf.d/*.conf"
        "/etc/nginx/sites-enabled/*.conf"
    )

    local error_pages=""

    for conf_pattern in "${nginx_conf_locations[@]}"; do
        for conf_file in $conf_pattern; do
            if [ -f "${conf_file}" ]; then
                local found_errorpage=$(grep -E "^\s*error_page" "${conf_file}" 2>/dev/null | grep -v "^\s*#" || true)
                if [ -n "${found_errorpage}" ]; then
                    error_pages="${error_pages}"$'\n'"${found_errorpage}"
                    error_page_count=$((error_page_count + 1))
                fi
            fi
        done
    done

    command_executed="grep -E '^\\s*error_page' /etc/nginx/nginx.conf /etc/nginx/conf.d/*.conf 2>/dev/null | grep -v '^\\s*#' | head -5"
    command_result="${error_pages:-No error_page found}"

    if [ ${error_page_count} -eq 0 ]; then
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="error_page 설정이 발견되지 않았습니다 (기본 에러 페이지 사용). 커스텀 에러 페이지 설정 권장."
    elif [ ${error_page_count} -ge 3 ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="에러 페이지가 ${error_page_count}개 설정되어 있습니다. (보안 권고사항 준수)"
    else
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="에러 페이지가 ${error_page_count}개 설정되어 있습니다. 주요 에러 코드 추가 설정 권장."
    fi

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
