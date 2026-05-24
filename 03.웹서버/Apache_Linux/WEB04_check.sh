#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : WEB-04
# @Category    : Web Server
# @Platform    : Apache_Linux
# @Severity    : 상
# @Title       : 웹 서비스 디렉터리 리 스팅 방지 설정
# @Description : 디렉터리 리스팅 기능 차단 여부 점검
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

ITEM_ID="WEB-04"
ITEM_NAME="웹 서비스 디렉터리 리 스팅 방지 설정"
SEVERITY="상"

GUIDELINE_PURPOSE="웹 서버에 대한 디렉터리 리스 팅 기능을 차단하여 디렉터리 내의 모든 파일에 대한 접근 및 정보 노출을 차단하기 위함"
GUIDELINE_THREAT="디렉터리 리스 팅 기능이 차단되지 않은 경우, 비인가자가 해당 디렉터리 내의 모든 파일의 리스트 확인 및 접근이 가능하고, 웹 서버의 구조 및 백업 파일이나 소스 파일 등 공개되면 안 되는 중요 파일들이 노출될 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="디렉터리 리스팅이 설정되지 않은 경우"
GUIDELINE_CRITERIA_BAD="디렉터리 리스팅이 설정된 경우"
GUIDELINE_REMEDIATION="디렉터리 리스팅 기능 차단 설정"

diagnose() {
    echo "진단 항목: ${ITEM_ID} - ${ITEM_NAME}"

    local diagnosis_result="VULNERABLE"
    local status="취약"
    local inspection_summary=""
    local command_result=""
    local command_executed=""
    local indexes_found=""
    local indexes_disabled=""
    local apache_conf=""

    # Apache process check
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
        inspection_summary="Apache 설정 파일을 찾을 수 없습니다. httpd.conf 또는 apache2.conf 파일에서 Options Indexes 설정을 수동으로 확인하세요."
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

    # Check for Options Indexes (enabled)
    indexes_found=$(grep -r "Options.*Indexes" "${apache_conf}" /etc/apache2/sites-available/ /etc/apache2/conf-available/ 2>/dev/null | grep -v "^\s*#" | grep -v "Options.*-Indexes" || true)

    # Check for Options -Indexes (explicitly disabled)
    indexes_disabled=$(grep -r "Options.*-Indexes" "${apache_conf}" /etc/apache2/sites-available/ /etc/apache2/conf-available/ 2>/dev/null | grep -v "^\s*#" | head -5 || true)

    command_executed="grep -r 'Options.*Indexes' ${apache_conf} /etc/apache2/sites-available/ /etc/apache2/conf-available/ 2>/dev/null | grep -v '^\\s*#'"

    if [ -n "${indexes_disabled}" ] && [ -z "${indexes_found}" ]; then
        # Indexes explicitly disabled
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="디렉터리 리스팅이 명시적으로 비활성화되어 있습니다 (Options -Indexes 설정). 설정 파일: ${apache_conf}"
        command_result="Options -Indexes found"
    elif [ -z "${indexes_found}" ]; then
        # No Indexes found (default is disabled in modern Apache)
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="디렉터리 리스팅 설정이 발견되지 않았습니다 (기본값 비활성화). Apache 2.4+에서는 Indexes 옵션이 명시되지 않은 경우 디렉터리 리스팅이 비활성화됩니다."
        command_result="No Options Indexes found"
    else
        # Indexes enabled
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="디렉터리 리스팅이 활성화되어 있습니다 (Options Indexes 또는 Options +Indexes). 보안 위험이 있으므로 'Options -Indexes'로 변경하거나 Indexes 옵션을 제거하세요."
        command_result="${indexes_found}"
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
