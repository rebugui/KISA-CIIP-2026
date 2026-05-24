#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : WEB-10
# @Category    : Web Server
# @Platform    : Apache
# @Severity    : 상
# @Title       : 불필요한프록시설정제한
# @Description : 불필요한 프록시 설정 제한 여부 점검
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

ITEM_ID="WEB-10"
ITEM_NAME="불필요한 프 록 시 설정 제한"
SEVERITY="상"

GUIDELINE_PURPOSE="불필요한 Proxy 설정을 제한하여 자원 낭비 예방 및 관리의 복잡성을 감소시키며, 중간자 공격 등의 해킹 공격으로부터 시스템 관련 정보가 노출되거나 악용되는 것을 방지하기 위함"
GUIDELINE_THREAT="불필요한 Proxy 설정을 제한하지 않는 경우 공격자가 Proxy 서버를 이용하여 원래 의도되지 않은 방식으로 시스템에 접근하거나 시스템 관련 정보가 유출될 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="불필요한 Proxy 설정을 제한한 경우"
GUIDELINE_CRITERIA_BAD="불필요한 Proxy 설정을 제한하지 않은 경우"
GUIDELINE_REMEDIATION="불필요한 Proxy 설정 존재 여부 점검 및 제한 설정"

diagnose() {
    echo "진단 항목: ${ITEM_ID} - ${ITEM_NAME}"

    local diagnosis_result="UNKNOWN"
    local status="미진단"
    local inspection_summary=""
    local command_result=""
    local command_executed=""
    local proxy_settings=""
    local proxy_count=0

    # Apache 프로세스 확인
        # Process check
    if command -v pgrep >/dev/null; then
        if ! pgrep -x "httpd" > /dev/null && ! pgrep -x "apache2" > /dev/null; then
            diagnosis_result="N/A"
            status="N/A"
            inspection_summary="Apache 웹 서버가 실행 중이 아닙니다."
            command_result="Apache process not found"
            command_executed="pgrep -x httpd; pgrep -x apache2"
            # Run-all 모드 확인

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

    local apache_conf_locations=(
        "/etc/apache2/apache2.conf"
        "/etc/httpd/conf/httpd.conf"
        "/usr/local/apache2/conf/httpd.conf"
        "/etc/apache2/sites-enabled/*.conf"
        "/etc/httpd/conf.d/*.conf"
    )

    # Apache 설정 파일에서 Proxy 지시어 확인
    for conf_pattern in "${apache_conf_locations[@]}"; do
        for conf_file in $conf_pattern; do
            if [ -f "${conf_file}" ]; then
                # ProxyPass, ProxyPassReverse, ProxyRequests 지시어 확인 (주석 제외)
                local found_proxy=$(grep -E "^\s*(ProxyPass|ProxyPassReverse|ProxyRequests)" "${conf_file}" 2>/dev/null | grep -v "^\s*#" || true)
                if [ -n "${found_proxy}" ]; then
                    proxy_settings="${proxy_settings}"$'\n'"${found_proxy}"
                    proxy_count=$((proxy_count + 1))
                fi
            fi
        done
    done

    command_executed="grep -E '^\s*(ProxyPass|ProxyPassReverse|ProxyRequests)' /etc/apache2/apache2.conf /etc/httpd/conf/httpd.conf /etc/apache2/sites-enabled/*.conf 2>/dev/null | grep -v '^\s*#'"

    if [ ${proxy_count} -eq 0 ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="불필요한 Proxy 설정이 발견되지 않았습니다. (보안 권고사항 준수)"
        command_result="No proxy settings found"
    else
        # ProxyRequests On인 경우 취약
        if echo "${proxy_settings}" | grep -iq "ProxyRequests.*On"; then
            diagnosis_result="VULNERABLE"
            status="취약"
            inspection_summary="ProxyRequests On 설정이 발견되었습니다. Forward Proxy 활성화로 인한 보안 위험."
            command_result="${proxy_settings}"
        else
            # ProxyPass/ProxyPassReverse만 있는 경우 (Reverse Proxy)
            diagnosis_result="GOOD"
            status="양호"
            inspection_summary="Reverse Proxy 설정만 존재합니다 (${proxy_count}개). Forward Proxy는 비활성화되어 있습니다."
            command_result="${proxy_settings}"
        fi
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

if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi
