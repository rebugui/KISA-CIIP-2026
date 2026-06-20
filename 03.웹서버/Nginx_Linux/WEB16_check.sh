#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : WEB-16
# @Category    : Web Server
# @Platform    : Nginx_Linux
# @Severity    : 중
# @Title       : 웹 서비스 헤더 정보 노출 제한
# @Description : HTTP 응답 헤더에서 웹서버 버전 정보 등 불필요한 정보 노출 제한 여부 점검
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

ITEM_ID="WEB-16"
ITEM_NAME="웹 서비스 헤더 정보 노출 제한"
SEVERITY="중"

GUIDELINE_PURPOSE="HTTP 응답 헤더에서 웹 서버 버전 및 종류,OS 정보 등 웹 서버와 관련된 정보가 불필요하게 노출되는 것을 최소화하기 위함"
GUIDELINE_THREAT="웹 서버 및 OS 정보가 노출될 경우 공격자에 의해 해당 버전의 알려진 취약점을 이용하여 시스템 구조와 특성 노출 및 해당 취약점을 통한 공격의 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="HTTP 응답 헤더에서 웹 서버 정보가 노출되지 않는 경우"
GUIDELINE_CRITERIA_BAD="HTTP 응답 헤더에서 웹 서버 정보가 노출되는 경우"
GUIDELINE_REMEDIATION="응답 헤더에 표시되는 정보를 최소한으로 제한하여 설정"

diagnose() {
    echo "진단 항목: ${ITEM_ID} - ${ITEM_NAME}"

    local diagnosis_result="UNKNOWN"
    local status="미진단"
    local inspection_summary=""
    local command_result=""
    local command_executed=""
    local server_tokens_off=false

        # Process check (Updated for Docker)
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

    # 확장자 없는 vhost(예: 데비안/우분투의 sites-enabled/default 심볼릭 링크)도
    # 포함되도록 .conf 글롭과 확장자 없는 디렉터리 글롭을 함께 사용한다.
    local nginx_conf_locations=(
        "/etc/nginx/nginx.conf"
        "/etc/nginx/conf.d/*.conf"
        "/etc/nginx/conf.d/*"
        "/etc/nginx/sites-enabled/*.conf"
        "/etc/nginx/sites-enabled/*"
    )

    local header_settings=""

    for conf_pattern in "${nginx_conf_locations[@]}"; do
        for conf_file in $conf_pattern; do
            if [ -f "${conf_file}" ]; then
                local found_tokens=$(grep -E "^\s*server_tokens" "${conf_file}" 2>/dev/null | grep -v "^\s*#" || true)
                if [ -n "${found_tokens}" ]; then
                    header_settings="${header_settings}"$'\n'"${found_tokens}"
                    if echo "${found_tokens}" | grep -iq "off"; then
                        server_tokens_off=true
                    fi
                fi
            fi
        done
    done

    command_executed="grep -E '^\\s*server_tokens' /etc/nginx/nginx.conf /etc/nginx/conf.d/*.conf 2>/dev/null | grep -v '^\\s*#' | head -3"
    command_result="${header_settings:-server_tokens not set (default: on)}"

    if [ "${server_tokens_off}" = true ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="server_tokens가 off로 설정되어 있습니다. (보안 권고사항 준수)"
    else
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="server_tokens가 on이거나 설정되지 않았습니다 (기본값: on). 헤더 정보 노출 제한 권장."
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
