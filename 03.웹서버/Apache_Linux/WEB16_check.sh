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
# @Platform    : Apache_Linux
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
    local apache_conf=""
    local server_tokens_value=""
    local server_signature_value=""
    local has_secure_header=false

    # Apache process check
    if command -v pgrep >/dev/null; then
        if ! pgrep -x "httpd" > /dev/null && ! pgrep -x "apache2" > /dev/null; then
            diagnosis_result="N/A"
            status="N/A"
            inspection_summary="Apache 웹 서버가 실행 중이 아닙니다."
            command_result="Apache process not found"
            command_executed="pgrep -x httpd; pgrep -x apache2"
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

    # Find Apache configuration file
    local apache_conf_locations=(
        "/etc/apache2/apache2.conf"
        "/etc/httpd/conf/httpd.conf"
        "/usr/local/apache2/conf/httpd.conf"
    )

    for conf_file in "${apache_conf_locations[@]}"; do
        if [ -f "${conf_file}" ]; then
            apache_conf="${conf_file}"
            break
        fi
    done

    if [ -z "${apache_conf}" ]; then
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="Apache 설정 파일을 찾을 수 없습니다. httpd.conf 또는 apache2.conf 파일에서 ServerTokens, ServerSignature 설정을 수동으로 확인하세요."
        command_result="Apache configuration file not found"
        command_executed="ls -la /etc/apache2/apache2.conf /etc/httpd/conf/httpd.conf /usr/local/apache2/conf/httpd.conf"
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

    # Check ServerTokens directive
    local server_tokens_settings=$(grep -r "ServerTokens" "${apache_conf}" /etc/apache2/conf-available/ /etc/apache2/sites-available/ 2>/dev/null | grep -v "^\s*#" | head -5 || true)
    local server_signature_settings=$(grep -r "ServerSignature" "${apache_conf}" /etc/apache2/conf-available/ /etc/apache2/sites-available/ 2>/dev/null | grep -v "^\s*#" | head -5 || true)

    command_executed="grep -r 'ServerTokens' ${apache_conf} /etc/apache2/conf-available/ 2>/dev/null | grep -v '^\\s*#'; grep -r 'ServerSignature' ${apache_conf} /etc/apache2/conf-available/ 2>/dev/null | grep -v '^\\s*#'"

    # Analyze ServerTokens setting
    if echo "${server_tokens_settings}" | grep -iq "ServerTokens.*Prod"; then
        server_tokens_value="Prod"
        has_secure_header=true
    elif echo "${server_tokens_settings}" | grep -iq "ServerTokens.*Minimal"; then
        server_tokens_value="Minimal"
    elif echo "${server_tokens_settings}" | grep -iq "ServerTokens.*OS"; then
        server_tokens_value="OS"
    elif echo "${server_tokens_settings}" | grep -iq "ServerTokens.*Full"; then
        server_tokens_value="Full"
    else
        server_tokens_value="Not set (default: Full)"
    fi

    # Analyze ServerSignature setting
    if echo "${server_signature_settings}" | grep -iq "ServerSignature.*Off"; then
        server_signature_value="Off"
    elif echo "${server_signature_settings}" | grep -iq "ServerSignature.*On"; then
        server_signature_value="On"
    elif echo "${server_signature_settings}" | grep -iq "ServerSignature.*Email"; then
        server_signature_value="Email"
    else
        server_signature_value="Not set (default: On)"
    fi

    command_result="ServerTokens: ${server_tokens_value}$'\n'ServerSignature: ${server_signature_value}"

    # Determine security status
    if [ "${server_tokens_value}" = "Prod" ] && [ "${server_signature_value}" = "Off" ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="ServerTokens가 Prod로 설정되어 있고 ServerSignature가 Off로 설정되어 있습니다. 헤더 정보 노출이 최소화됩니다. (보안 권고사항 준수)"
    elif [ "${server_tokens_value}" = "Prod" ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="ServerTokens가 Prod로 설정되어 있습니다. ServerSignature 설정도 확인하세요. (보안 권고사항 준수)"
    elif [ "${server_tokens_value}" = "Full" ] || [ "${server_tokens_value}" = "Not set (default: Full)" ]; then
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="ServerTokens가 Full(또는 미설정 기본값)입니다. 서버 버전 정보가 노출됩니다. ServerTokens Prod로 설정을 권장합니다."
    else
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="ServerTokens가 ${server_tokens_value}로 설정되어 있습니다. 추가 보안 강화를 위해 ServerTokens Prod 설정을 권장합니다."
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
