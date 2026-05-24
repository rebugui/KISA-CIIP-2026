#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : WEB-15
# @Category    : Web Server
# @Platform    : Apache
# @Severity    : 상
# @Title       : 웹서비스의불필요한스크립트매핑제거
# @Description : 불필요한 CGI 스크립트 핸들러 매핑 제거 여부 점검
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

ITEM_ID="WEB-15"
ITEM_NAME="웹 서비스의 불필요한 스크립트 매핑 제거"
SEVERITY="상"

GUIDELINE_PURPOSE="웹 서비스에서 사용하지 않는 불필요 스크립트 매핑이 존재하는지 점검하여 잠재적 보안 위협을 방지하기 위함"
GUIDELINE_THREAT="웹 서비스에서 불필요한 스크립트 매핑을 제거하지 않은 경우, 버퍼오버플로우(Buffer Overflow), 서비스 거부 공격(Denial of Service), 크로스 사이트 스크립 팅(CrossSiteScripting) 등의 공격 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="불필요한 스크립트 매핑이 존재하지 않는 경우"
GUIDELINE_CRITERIA_BAD="불필요한 스크립트 매핑이 존재하는 경우"
GUIDELINE_REMEDIATION="불필요한 스크립트 매핑 존재 여부 점검 및 제거 설정"

diagnose() {
    echo "진단 항목: ${ITEM_ID} - ${ITEM_NAME}"

    local diagnosis_result="VULNERABLE"
    local status="취약"
    local inspection_summary=""
    local command_result=""
    local command_executed=""
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
        inspection_summary="Apache 설정 파일을 찾을 수 없습니다. httpd.conf 또는 apache2.conf 파일에서 스크립트 매핑 설정을 수동으로 확인하세요."
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

    # Check for script handler mappings (AddHandler, AddType, Action, ScriptAlias)
    local addhandler_found=$(grep -rE "^\s*AddHandler\s+(cgi-script|script)" "${apache_conf}" /etc/apache2/sites-available/ /etc/apache2/conf-available/ 2>/dev/null | grep -v "^\s*#" | head -5 || true)
    local addtype_found=$(grep -rE "^\s*AddType\s+(application/x-httpd-php|application/x-httpd-cgi)" "${apache_conf}" /etc/apache2/sites-available/ /etc/apache2/conf-available/ 2>/dev/null | grep -v "^\s*#" | head -5 || true)
    local action_found=$(grep -rE "^\s*Action\s+" "${apache_conf}" /etc/apache2/sites-available/ /etc/apache2/conf-available/ 2>/dev/null | grep -v "^\s*#" | head -5 || true)
    local scriptalias_found=$(grep -rE "^\s*ScriptAlias\s+" "${apache_conf}" /etc/apache2/sites-available/ /etc/apache2/conf-available/ 2>/dev/null | grep -v "^\s*#" | grep -v "/cgi-bin/" | head -5 || true)

    command_executed="grep -rE '^\s*(AddHandler|AddType|Action|ScriptAlias)' ${apache_conf} /etc/apache2/sites-available/ 2>/dev/null | grep -v '^\\s*#' | head -10"

    # Collect all found mappings
    local all_mappings=""
    [ -n "${addhandler_found}" ] && all_mappings="${all_mappings}"$'\n'"AddHandler:${addhandler_found}"
    [ -n "${addtype_found}" ] && all_mappings="${all_mappings}"$'\n'"AddType:${addtype_found}"
    [ -n "${action_found}" ] && all_mappings="${all_mappings}"$'\n'"Action:${action_found}"
    [ -n "${scriptalias_found}" ] && all_mappings="${all_mappings}"$'\n'"ScriptAlias(non-cgi-bin):${scriptalias_found}"

    command_result="${all_mappings:-No script handler mappings found}"

    if [ -z "${addhandler_found}" ] && [ -z "${addtype_found}" ] && [ -z "${action_found}" ] && [ -z "${scriptalias_found}" ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="불필요한 스크립트 매핑이 발견되지 않았습니다. CGI/스크립트 핸들러가 제한적으로 설정되어 있습니다."
    elif [ -n "${scriptalias_found}" ]; then
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="/cgi-bin/ 외의 ScriptAlias가 발견되었습니다. 불필요한 스크립트 실행 경로가 존재할 수 있으니 검토 후 제거하세요."
    elif [ -n "${addhandler_found}" ] || [ -n "${action_found}" ]; then
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="AddHandler 또는 Action 지시어로 스크립트 매핑이 발견되었습니다. 사용하지 않는 핸들러는 제거하세요."
    else
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="일부 스크립트 매핑이 발견되었으나 필수적인 것으로 보입니다 (PHP 등). 수동 확인 권장."
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
