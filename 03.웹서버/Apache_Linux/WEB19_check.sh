#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : WEB-19
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

ITEM_ID="WEB-19"
ITEM_NAME="웹 서비스 SSI(Server Side Includes)사용 제한"
SEVERITY="중"

GUIDELINE_PURPOSE="웹 서비스 내 SSI 사용을 제한하여 불법적인 데이터 접근을 차단하여 웹 서버의 보안을 강화하기 위함"
GUIDELINE_THREAT="웹 서비스 내 SSI 사용을 제한하지 않을 경우, 공격자가 SSI 기능을 이용하여 시스템 명령 실행 및 중요 파일 탈취 등 공격이 가능하며, 이를 통해 서버 시스템 침해, 데이터 유출 등이 발생할 위험이 존재함 SSI 공격 시 HTML 페이지에 스크립트를 삽입하거나 원격으로 코드를 실행하여 웹 서비스를 악용할 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="웹 서비스 SSI 사용 설정이 비활성화되어 있는 경우"
GUIDELINE_CRITERIA_BAD="웹 서비스 SSI 사용 설정이 활성화되어 있는 경우"
GUIDELINE_REMEDIATION="웹 서비스 내 불필요한 SSI 사용 제한 설정"

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
        inspection_summary="Apache 설정 파일을 찾을 수 없습니다. httpd.conf 또는 apache2.conf 파일에서 WebDAV 설정을 수동으로 확인하세요."
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

    # Check for WebDAV module loading
    local dav_module_loaded=$(grep -rE "LoadModule\s+dav_module|LoadModule\s+dav_fs_module" "${apache_conf}" /etc/apache2/mods-enabled/*.load 2>/dev/null | grep -v "^\s*#" | head -3 || true)

    # Check for DAV directive (enables WebDAV for directories)
    local dav_enabled=$(grep -rE "^\s*DAV\s+(On|on)" "${apache_conf}" /etc/apache2/sites-available/ /etc/apache2/conf-available/ 2>/dev/null | grep -v "^\s*#" | head -5 || true)

    command_executed="grep -rE 'LoadModule.*dav' ${apache_conf} /etc/apache2/mods-enabled/ 2>/dev/null | grep -v '^\\s*#'; grep -rE '^\\s*DAV\\s+On' ${apache_conf} /etc/apache2/sites-available/ 2>/dev/null | grep -v '^\\s*#'"

    if [ -n "${dav_module_loaded}" ]; then
        command_result="WebDAV module loaded: ${dav_module_loaded}"
        if [ -n "${dav_enabled}" ]; then
            command_result="${command_result}"$'\n'"DAV enabled: ${dav_enabled}"
        fi
    elif [ -n "${dav_enabled}" ]; then
        command_result="DAV enabled (module check failed): ${dav_enabled}"
    else
        command_result="No WebDAV module or DAV directive found"
    fi

    if [ -n "${dav_module_loaded}" ] || [ -n "${dav_enabled}" ]; then
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="WebDAV가 활성화되어 있습니다. LoadModule dav_module/dav_fs_module이 로드되었거나 DAV On 지시어가 설정되어 있습니다. WebDAV는 악의적인 파일 업로드 경로가 될 수 있으므로 비활성화하세요."
    else
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="WebDAV가 비활성화되어 있습니다. mod_dav 모듈이 로드되지 않았거나 DAV 지시어가 설정되지 않았습니다. (보안 권고사항 준수)"
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
