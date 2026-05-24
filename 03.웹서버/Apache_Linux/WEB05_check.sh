#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : WEB-05
# @Category    : Web Server
# @Platform    : Apache
# @Severity    : 상
# @Title       : 지정하지 않은 CGI/ISAPI 실행 제한
# @Description : 웹서비스 CGI 실행 제한 설정 여부 점검
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

ITEM_ID="WEB-05"
ITEM_NAME="지정하지 않은 CGI/ISAPI 실행 제한"
SEVERITY="상"

GUIDELINE_PURPOSE="CGI 스크립트를 정해진 디렉터리에서만 실행되도록하여 악의적인 파일의 업로드 및 실행을 방지하기 위함"
GUIDELINE_THREAT="게시판이나 자료실과 같이 업로드되는 파일이 저장되는 디렉터리에 CGI 스크립트가 실행 가능한 경우 악의적인 파일을 업로드하고 이를 실행하여 시스템의 중요 정보가 노출될 수 있으며 침해 사고의 경로로 이용될 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="CGI 스크립트를 사용하지 않거나 CGI 스크립트가 실행 가능한 디렉터리를 제한한 경우"
GUIDELINE_CRITERIA_BAD="CGI 스크립트를 사용하고 CGI 스크립트가 실행 가능한 디렉터리를 제한하지 않은 경우"
GUIDELINE_REMEDIATION="CGI 스크립트를 정해진 디렉터리 내에서만 실행할 수 있도록 설정"

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
        inspection_summary="Apache 설정 파일을 찾을 수 없습니다. httpd.conf 또는 apache2.conf 파일에서 ScriptAlias 및 Options ExecCGI 설정을 수동으로 확인하세요."
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

    # Check for CGI module loaded
    local cgi_module_loaded=""
    cgi_module_loaded=$(grep -E "LoadModule.*cgi_module|LoadModule.*cgid_module" "${apache_conf}" /etc/apache2/mods-enabled/*.load 2>/dev/null | grep -v "^\s*#" | head -3 || true)

    # Check for ScriptAlias (restricts CGI to specific directories)
    local scriptalias_found=""
    scriptalias_found=$(grep -r "ScriptAlias" "${apache_conf}" /etc/apache2/sites-available/ /etc/apache2/conf-available/ 2>/dev/null | grep -v "^\s*#" | head -5 || true)

    # Check for Options ExecCGI (enables CGI execution in directories)
    local exec_cgi_found=""
    exec_cgi_found=$(grep -r "Options.*ExecCGI" "${apache_conf}" /etc/apache2/sites-available/ /etc/apache2/conf-available/ 2>/dev/null | grep -v "^\s*#" | grep -v "Options.*-ExecCGI" | head -5 || true)

    command_executed="grep -E 'LoadModule.*cgi' ${apache_conf}; grep -r 'ScriptAlias' ${apache_conf} /etc/apache2/sites-available/; grep -r 'Options.*ExecCGI' ${apache_conf} /etc/apache2/sites-available/"

    if [ -z "${cgi_module_loaded}" ] && [ -z "${exec_cgi_found}" ]; then
        # CGI module not loaded and no ExecCGI found
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="CGI 모듈이 로드되지 않았으며 Options ExecCGI 설정도 없습니다. CGI 스크립트 실행이 비활성화되어 있습니다."
        command_result="No CGI module or ExecCGI found"
    elif [ -n "${scriptalias_found}" ] && [ -n "${exec_cgi_found}" ]; then
        # ScriptAlias found and ExecCGI found (CGI is restricted to specific directories)
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="CGI 실행이 ScriptAlias로 지정된 디렉터리(/cgi-bin/ 등)로 제한되어 있습니다. CGI 스크립트 실행이 적절하게 제한됩니다."
        command_result="ScriptAlias: ${scriptalias_found}"
    elif [ -n "${exec_cgi_found}" ]; then
        # ExecCGI found without ScriptAlias (potential unrestricted CGI execution)
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="Options ExecCGI가 설정되어 있으나 ScriptAlias 제한이 없습니다. 모든 디렉터리에서 CGI 실행이 가능할 수 있어 보안 위험이 있습니다. ScriptAlias로 제한하거나 ExecCGI를 제거하세요."
        command_result="ExecCGI found without ScriptAlias restriction"
    else
        # ScriptAlias found but no ExecCGI (CGI likely properly restricted)
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="CGI 실행이 ScriptAlias로 지정된 디렉터리로 제한되어 있습니다. Options ExecCGI가 명시되지 않았으나 ScriptAlias가 CGI 실행 경로를 제한합니다."
        command_result="ScriptAlias found: ${scriptalias_found}"
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
