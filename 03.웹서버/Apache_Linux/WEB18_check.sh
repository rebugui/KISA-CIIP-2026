#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : WEB-18
# @Category    : Web Server
# @Platform    : Apache
# @Severity    : 상
# @Title       : 웹서비스WebDAV비활성화
# @Description : WebDAV 모듈 비활성화 여부 점검
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

ITEM_ID="WEB-18"
ITEM_NAME="웹 서비스 WebDAV 비활성화"
SEVERITY="상"

GUIDELINE_PURPOSE="WebDAV 서비스를 비활성화하여,WebDAV에서 발견되는 다수의 인증 우회 취약점을 제거하고자함"
GUIDELINE_THREAT="WebDAV가 활성화되어 있는 경우 웹 서비스에 악의적으로 작성된 요청을 이용하여 인증을 우회함으로써 비밀번호로 보호된 WebDAV의 자원에 접근 (디렉터리 열람, 파일 다운로드 등)이 가능하며, WebDAV에 의해 호출된 일부 구성 요소에 매개 변수를 정확하게 점검하지 않는 결함이 존재하여, 이로 인해 버퍼 오버 런이 발생할 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="WebDAV 서비스를 비활성화하고 있는 경우"
GUIDELINE_CRITERIA_BAD="WebDAV 서비스를 활성화하고 있는 경우"
GUIDELINE_REMEDIATION="WebDAV 서비스 비활성화 설정"

diagnose() {
    echo "진단 항목: ${ITEM_ID} - ${ITEM_NAME}"

    local diagnosis_result="UNKNOWN"
    local status="미진단"
    local inspection_summary=""
    local command_result=""
    local command_executed=""
    local dav_enabled=false

        # Process check
    if command -v pgrep >/dev/null; then
        if ! pgrep -x "httpd" > /dev/null && ! pgrep -x "apache2" > /dev/null; then
            diagnosis_result="N/A"
            status="N/A"
            inspection_summary="Apache \xec\x9b\xb9 \xec\x84\x9c\xeb\xb2\x84\xea\xb0\x80 \xec\x8b\xa4\xed\x96\x89 \xec\xa4\x91\xec\x9d\xb4 \xec\x95\x84\xeb\x8b\x99\xeb\x8b\x88\xeb\x8b\xa4."
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
        )

        for conf_pattern in "${apache_conf_locations[@]}"; do
            for conf_file in $conf_pattern; do
                if [ -f "${conf_file}" ]; then
                    local found_dav=$(grep -E "^\s*DAV\s+(On|off)" "${conf_file}" 2>/dev/null | grep -v "^\s*#" || true)
                    if [ -n "${found_dav}" ]; then
                        if echo "${found_dav}" | grep -iq "On"; then
                            dav_enabled=true
                        fi
                        break 2
                    fi
                fi
            done
        done

        command_executed="grep -r 'DAV.*On' /etc/apache2 /etc/httpd 2>/dev/null | grep -v '^\s*#' | head -3"

    command_result="${dav_enabled:+DAV enabled}"

    if [ "${dav_enabled}" = true ]; then
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="WebDAV가 활성화되어 있습니다. 불필요한 경우 비활성화 권장."
    else
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="WebDAV가 비활성화되어 있거나 로드되지 않았습니다. (보안 권고사항 준수)"
        command_result="DAV disabled or not loaded"
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
