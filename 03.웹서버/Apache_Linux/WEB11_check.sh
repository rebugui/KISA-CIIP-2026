#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : WEB-11
# @Category    : Web Server
# @Platform    : Apache_Linux
# @Severity    : 중
# @Title       : 웹 서비스 경로 설정
# @Description : 웹 서비스 경로 설정 적절성 여부 점검
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

ITEM_ID="WEB-11"
ITEM_NAME="웹 서비스 경로 설정"
SEVERITY="중"

GUIDELINE_PURPOSE="웹 서비스 영역 내 불필요한 경로를 분리해 웹 서비스의 침해가 시스템 영역으로 확장될 가능성을 최소화하기 위함"
GUIDELINE_THREAT="웹 서비스 경로를 기타 업무와 영역이 분리되지 않은 경로로 설정하거나, 불필요한 경로가 존재할 경우 외부에서 시스템 중요 파일이나 기능에 비인가 접근이 발생할 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="웹 서버 경로를 기타 업무와 영역이 분리된 경로로 설정 및 불필요한 경로가 존재하지 않는 경우"
GUIDELINE_CRITERIA_BAD="웹 서버 경로를 기타 업무와 영역이 분리되지 않은 경로로 설정하거나 불필요한 경로가 있는 경우"
GUIDELINE_REMEDIATION="웹 서버의 경로를 별도의 경로로 변경 및 불필요한 경로 제거 설정"

diagnose() {
    echo "진단 항목: ${ITEM_ID} - ${ITEM_NAME}"

    local diagnosis_result="UNKNOWN"
    local status="미진단"
    local inspection_summary=""
    local command_result=""
    local command_executed=""
    local doc_root=""

    # Apache 프로세스 확인
        # Process check
    if command -v pgrep >/dev/null; then
        if ! pgrep -x "httpd" > /dev/null && ! pgrep -x "apache2" > /dev/null; then
            diagnosis_result="N/A"
            status="N/A"
            inspection_summary="Apache \xec\x9b\xb9 \xec\x84\x9c\xeb\xb2\x84\xea\xb0\x80 \xec\x8b\xa4\xed\x96\x89 \xec\xa4\x91\xec\x9d\xb4 \xec\x95\x84\xeb\x8b\x99\xeb\x8b\x88\xeb\x8b\xa4."
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

    local apache_conf_locations=(
        "/etc/apache2/sites-enabled/000-default.conf"
        "/etc/apache2/apache2.conf"
        "/etc/httpd/conf/httpd.conf"
        "/usr/local/apache2/conf/httpd.conf"
        "/etc/apache2/sites-available/*.conf"
    )

    # DocumentRoot 설정 확인
    for conf_pattern in "${apache_conf_locations[@]}"; do
        for conf_file in $conf_pattern; do
            if [ -f "${conf_file}" ]; then
                # DocumentRoot 지시어 확인 (주석 제외)
                local found_docroot=$(grep -E "^\s*DocumentRoot" "${conf_file}" 2>/dev/null | grep -v "^\s*#" | head -1 || true)
                if [ -n "${found_docroot}" ]; then
                    doc_root=$(echo "${found_docroot}" | awk '{print $2}' | tr -d '"')
                    break 2
                fi
            fi
        done
    done

    command_executed="grep -E '^\s*DocumentRoot' /etc/apache2/sites-enabled/*.conf /etc/apache2/apache2.conf /etc/httpd/conf/httpd.conf 2>/dev/null | grep -v '^\s*#' | head -1"
    command_result="${doc_root:-Not found}"

    if [ -z "${doc_root}" ]; then
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="DocumentRoot 설정을 찾을 수 없습니다. 수동 확인이 필요합니다."
    else
        # 기본 경로인지 확인
        if [[ "${doc_root}" =~ ^/var/www/html?$ ]] || [[ "${doc_root}" =~ ^/srv/www/html?$ ]] || [[ "${doc_root}" =~ ^/usr/local/apache2/htdocs$ ]]; then
            diagnosis_result="VULNERABLE"
            status="취약"
            inspection_summary="DocumentRoot가 기본 경로(${doc_root})로 설정되어 있습니다. 별도의 분리된 경로로 변경 권장."
        else
            diagnosis_result="GOOD"
            status="양호"
            inspection_summary="DocumentRoot가 별도 경로(${doc_root})로 설정되어 있습니다. (보안 권고사항 준수)"
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

if true; then
    main "$@"
fi
