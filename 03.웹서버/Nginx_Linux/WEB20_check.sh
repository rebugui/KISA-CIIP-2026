#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : WEB-20
# @Category    : Web Server
# @Platform    : Nginx_Linux
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

    local diagnosis_result="UNKNOWN"
    local status="미진단"
    local inspection_summary=""
    local command_result=""
    local command_executed=""
    local has_ssl=false
    local has_https=false
    local has_ssl_protocols=false
    local has_weak_protocols=false
    local protocol_settings=""

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

    local nginx_conf_locations=(
        "/etc/nginx/nginx.conf"
        "/etc/nginx/conf.d/*.conf"
        "/etc/nginx/sites-enabled/*.conf"
    )

    local ssl_settings=""

    for conf_pattern in "${nginx_conf_locations[@]}"; do
        for conf_file in $conf_pattern; do
            if [ -f "${conf_file}" ]; then
                # SSL 인증서 설정 확인
                local found_ssl=$(grep -E "^\s*ssl_certificate" "${conf_file}" 2>/dev/null | grep -v "^\s*#" || true)
                if [ -n "${found_ssl}" ]; then
                    ssl_settings="${ssl_settings}"$'\n'"${found_ssl}"
                    has_ssl=true
                fi

                # 443 포트 Listen 확인
                local found_https=$(grep -E "(listen.*443|listen.*ssl)" "${conf_file}" 2>/dev/null | grep -v "^\s*#" || true)
                if [ -n "${found_https}" ]; then
                    has_https=true
                fi

                # ssl_protocols 지시자 확인 (약한 프로토콜 포함 여부 점검)
                local found_protocols=$(grep -E "^\s*ssl_protocols" "${conf_file}" 2>/dev/null | grep -v "^\s*#" || true)
                if [ -n "${found_protocols}" ]; then
                    has_ssl_protocols=true
                    protocol_settings="${protocol_settings}"$'\n'"${found_protocols}"
                    # SSLv2/SSLv3/TLSv1/TLSv1.1 은 약한 프로토콜
                    if echo "${found_protocols}" | grep -qiE "SSLv2|SSLv3|TLSv1([^.]|$)|TLSv1\.1"; then
                        has_weak_protocols=true
                    fi
                fi
            fi
        done
    done

    command_executed="grep -E '(ssl_certificate|listen.*443|listen.*ssl|ssl_protocols)' /etc/nginx/nginx.conf /etc/nginx/conf.d/*.conf 2>/dev/null | grep -v '^\\s*#' | head -5"
    command_result="${ssl_settings:-No SSL found}${protocol_settings}"

    if [ "${has_ssl}" != true ] || [ "${has_https}" != true ]; then
        # SSL 인증서 또는 443/ssl 리스너가 없으면 SSL/TLS 미활성화 → 취약
        diagnosis_result="VULNERABLE"
        status="취약"
        if [ "${has_ssl}" = true ]; then
            inspection_summary="SSL 인증서가 설정되었으나 HTTPS(443) 리스너가 발견되지 않았습니다. SSL/TLS 설정을 완료하세요."
        else
            inspection_summary="HTTPS가 활성화되어 있지 않습니다. SSL/TLS 설정 권장."
        fi
    elif [ "${has_weak_protocols}" = true ]; then
        # WEB-20 판단 기준은 SSL/TLS 활성화 여부(활성화↔비활성화)로 한정됨.
        # 프로토콜 버전 강화(TLSv1.2/1.3 전용)는 본 항목의 합격 기준이 아니라 권고 예시이므로,
        # SSL/TLS가 활성화된 상태(인증서+443/ssl 리스너 존재)는 약한 프로토콜 포함 여부와 무관하게 양호로 판단한다.
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="HTTPS(SSL/TLS)가 활성화되어 있어 SSL/TLS 활성화 기준을 충족합니다. (참고: ssl_protocols에 레거시 프로토콜(SSLv2/SSLv3/TLSv1/TLSv1.1)이 포함되어 있어 TLSv1.2 TLSv1.3 만 허용하도록 강화 권고) 설정값:${protocol_settings}"
    elif [ "${has_ssl_protocols}" != true ]; then
        # SSL은 활성화되었으나 ssl_protocols 미지정. Nginx 기본값(1.18 이전)은 TLSv1/TLSv1.1을 포함하므로
        # 약한 프로토콜 차단 여부를 정적으로 단정할 수 없어 수동진단으로 분류한다.
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="SSL/TLS는 활성화되어 있으나 ssl_protocols 지시자가 명시되어 있지 않습니다. Nginx 기본 프로토콜에는 TLSv1/TLSv1.1이 포함될 수 있으므로(버전에 따라 상이), 사용 중인 Nginx 버전의 기본 프로토콜과 실제 허용 프로토콜을 수동으로 확인하고 ssl_protocols TLSv1.2 TLSv1.3; 명시를 권장합니다."
    else
        # ssl_protocols가 명시되어 있고 약한 프로토콜이 없음(현대 프로토콜 전용) → 양호
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="HTTPS(SSL/TLS)가 활성화되어 있으며 ssl_protocols에 취약한 프로토콜 없이 현대 프로토콜만 설정되어 있습니다. (보안 권고사항 준수) 설정값:${protocol_settings}"
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
