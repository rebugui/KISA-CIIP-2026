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
# @Platform    : Apache_Linux
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

    # Build the complete set of configuration files/directories to scan.
    # The main config plus Debian (mods-enabled/sites-available/conf-available)
    # AND RHEL/EL drop-in dirs (conf.d/conf.modules.d), and any files pulled in
    # via Include/IncludeOptional directives. RHEL httpd loads mod_cgi and per-app
    # config from these drop-in dirs (httpd.conf only has `Include conf.modules.d/*.conf`),
    # so scanning the main config alone misses genuinely unrestricted CGI.
    local apache_root=""
    apache_root="$(dirname "$(dirname "${apache_conf}")")"   # /etc/httpd/conf/httpd.conf -> /etc/httpd

    local -a scan_targets=("${apache_conf}")
    local -a candidate_dirs=(
        "/etc/apache2/mods-enabled"
        "/etc/apache2/sites-available"
        "/etc/apache2/conf-available"
        "/etc/apache2/sites-enabled"
        "/etc/apache2/conf-enabled"
        "/etc/httpd/conf.d"
        "/etc/httpd/conf.modules.d"
        "${apache_root}/conf.d"
        "${apache_root}/conf.modules.d"
    )
    local enumeration_complete=1
    local d="" f="" inc_path="" g=""
    for d in "${candidate_dirs[@]}"; do
        if [ -d "${d}" ]; then
            while IFS= read -r f; do
                [ -n "${f}" ] && scan_targets+=("${f}")
            done < <(find "${d}" -type f \( -name "*.conf" -o -name "*.load" \) 2>/dev/null || true)
        fi
    done

    # Resolve Include / IncludeOptional directives from the main config (best effort).
    # Relative globs are resolved against the server root (dir-of-dir of the config).
    while IFS= read -r inc_path; do
        [ -z "${inc_path}" ] && continue
        case "${inc_path}" in
            /*) g="${inc_path}" ;;
            *)  g="${apache_root}/${inc_path}" ;;
        esac
        local matched=0
        for f in ${g}; do
            if [ -f "${f}" ]; then
                scan_targets+=("${f}")
                matched=1
            fi
        done
        # An Include target that resolved to nothing readable means the CGI
        # configuration cannot be fully enumerated from this host context.
        [ "${matched}" -eq 0 ] && enumeration_complete=0
    done < <(grep -hE "^[[:space:]]*Include(Optional)?[[:space:]]+" "${apache_conf}" 2>/dev/null \
             | grep -v "^[[:space:]]*#" \
             | sed -E 's/^[[:space:]]*Include(Optional)?[[:space:]]+//; s/[[:space:]]*$//; s/^"//; s/"$//' || true)

    # Check for CGI module loaded
    local cgi_module_loaded=""
    cgi_module_loaded=$(grep -E "LoadModule.*cgi_module|LoadModule.*cgid_module" "${scan_targets[@]}" 2>/dev/null | grep -v "^\s*#" | head -3 || true)

    # Check for ScriptAlias (restricts CGI to specific directories)
    local scriptalias_found=""
    scriptalias_found=$(grep -E "ScriptAlias" "${scan_targets[@]}" 2>/dev/null | grep -v "^\s*#" | head -5 || true)

    # Check for Options ExecCGI (enables CGI execution in directories)
    local exec_cgi_found=""
    exec_cgi_found=$(grep -E "Options.*ExecCGI" "${scan_targets[@]}" 2>/dev/null | grep -v "^\s*#" | grep -v "Options.*-ExecCGI" | head -5 || true)

    # Check for AddHandler/SetHandler cgi-script (enables CGI without ScriptAlias)
    local cgi_handler_found=""
    cgi_handler_found=$(grep -E "(AddHandler|SetHandler).*cgi-script" "${scan_targets[@]}" 2>/dev/null | grep -v "^\s*#" | head -5 || true)

    command_executed="grep -E 'LoadModule.*cgi|ScriptAlias|Options.*ExecCGI|(Add|Set)Handler.*cgi-script' ${apache_conf} + conf.d/conf.modules.d + Include-resolved *.conf"

    if [ -z "${cgi_module_loaded}" ] && [ -z "${exec_cgi_found}" ] && [ -z "${cgi_handler_found}" ]; then
        # CGI not in use: no module loaded, no ExecCGI, no cgi-script handler.
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="CGI 모듈이 로드되지 않았으며 Options ExecCGI 및 cgi-script 핸들러 설정도 없습니다. CGI 스크립트 실행이 비활성화되어 있습니다."
        command_result="No CGI module, ExecCGI, or cgi-script handler found"
    elif [ -n "${exec_cgi_found}" ] && [ -z "${scriptalias_found}" ]; then
        # ExecCGI enabled without ScriptAlias (unrestricted CGI execution).
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="Options ExecCGI가 설정되어 있으나 ScriptAlias 제한이 없습니다. 모든 디렉터리에서 CGI 실행이 가능할 수 있어 보안 위험이 있습니다. ScriptAlias로 제한하거나 ExecCGI를 제거하세요."
        command_result="ExecCGI found without ScriptAlias restriction: ${exec_cgi_found}"
    elif [ -n "${cgi_handler_found}" ] && [ -z "${scriptalias_found}" ]; then
        # cgi-script handler configured without ScriptAlias (unrestricted CGI execution).
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="AddHandler/SetHandler cgi-script가 설정되어 있으나 ScriptAlias 제한이 없습니다. 지정되지 않은 디렉터리에서 CGI 실행이 가능할 수 있어 보안 위험이 있습니다. ScriptAlias로 제한하거나 cgi-script 핸들러를 제거하세요."
        command_result="cgi-script handler found without ScriptAlias restriction: ${cgi_handler_found}"
    elif [ "${enumeration_complete}" -eq 0 ]; then
        # CGI is in use and a ScriptAlias exists, but Include/IncludeOptional targets
        # could not be fully resolved on this host, so we cannot prove every CGI-enabled
        # path is restricted. Route to manual judgment rather than asserting GOOD.
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="CGI가 사용 중이나 Include/IncludeOptional로 포함된 설정 파일을 모두 확인할 수 없어 CGI 실행 디렉터리 제한 여부를 자동으로 판단할 수 없습니다. 포함된 모든 설정 파일에서 Options ExecCGI 및 cgi-script 핸들러가 ScriptAlias로 지정된 디렉터리에 한정되는지 수동으로 확인하세요."
        command_result="CGI in use but configuration could not be fully enumerated (unresolved Include directives)"
    else
        # CGI is in use but ScriptAlias restricts execution to designated directories.
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="CGI 실행이 ScriptAlias로 지정된 디렉터리로 제한되어 있습니다. CGI 스크립트 실행이 적절하게 제한됩니다."
        command_result="ScriptAlias restriction found: ${scriptalias_found}"
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
