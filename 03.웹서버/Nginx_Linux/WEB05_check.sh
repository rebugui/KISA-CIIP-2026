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
# @Platform    : Nginx_Linux
# @Severity    : 상
# @Title       : 지정하지 않은 CGI/ISAPI 실행 제한
# @Description : 웹서비스 CGI 실행 제한 설정 여부 점검
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

    local diagnosis_result="UNKNOWN"
    local status="미진단"
    local inspection_summary=""
    local command_result=""
    local command_executed=""
    local cgi_locations=""
    local cgi_count=0
    local has_unrestricted_cgi=false
    local config_readable=false

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

    # 시드 설정 위치. 확장자 없는 vhost(예: 데비안/우분투의 sites-enabled/default
    # 심볼릭 링크)도 포함되도록 .conf 글롭과 확장자 없는 디렉터리 글롭을 함께 사용한다.
    local nginx_conf_locations=(
        "/etc/nginx/nginx.conf"
        "/etc/nginx/conf.d/*.conf"
        "/etc/nginx/conf.d/*"
        "/etc/nginx/sites-enabled/*.conf"
        "/etc/nginx/sites-enabled/*"
    )

    # 이미 스캔한 파일을 다시 열지 않도록 추적한다.
    local scanned_files=""

    scan_nginx_conf_file() {
        local conf_file="$1"
        if [ ! -f "${conf_file}" ] || [ ! -r "${conf_file}" ]; then
            return 0
        fi
        case "${scanned_files}" in
            *"|${conf_file}|"*) return 0 ;;
        esac
        scanned_files="${scanned_files}|${conf_file}|"

        config_readable=true
        # Check for FastCGI/SCGI/UWSGI/CGI configurations
        local found_cgi
        found_cgi=$(grep -E "^\s*(fastcgi_pass|scgi_pass|uwsgi_pass|cgi_pass)" "${conf_file}" 2>/dev/null | grep -v "^\s*#" || true)
        if [ -n "${found_cgi}" ]; then
            cgi_locations="${cgi_locations}"$'\n'"${conf_file}: ${found_cgi}"
            ((cgi_count++)) || true
        fi

        # include 지시자를 해석하여 외부/확장자 없는 vhost의 *_pass 설정도 스캔한다.
        # (Windows 형제 스크립트의 include-following ActiveLines와 동일한 의도)
        local include_targets
        include_targets=$(grep -E "^\s*include\s+" "${conf_file}" 2>/dev/null | grep -v "^\s*#" \
            | sed -E 's/^\s*include\s+//; s/;\s*$//' || true)
        if [ -n "${include_targets}" ]; then
            local inc
            while IFS= read -r inc; do
                [ -n "${inc}" ] || continue
                # 상대 경로는 nginx 기본 prefix(/etc/nginx) 기준으로 해석한다.
                case "${inc}" in
                    /*) : ;;
                    *) inc="/etc/nginx/${inc}" ;;
                esac
                local inc_file
                for inc_file in $inc; do
                    if [ -f "${inc_file}" ] && [ -r "${inc_file}" ]; then
                        scan_nginx_conf_file "${inc_file}"
                    fi
                done
            done <<< "${include_targets}"
        fi
    }

    for conf_pattern in "${nginx_conf_locations[@]}"; do
        for conf_file in $conf_pattern; do
            scan_nginx_conf_file "${conf_file}"
        done
    done

    command_executed="grep -E '^\\s*(fastcgi_pass|scgi_pass|uwsgi_pass|cgi_pass)' /etc/nginx/nginx.conf /etc/nginx/conf.d/*.conf 2>/dev/null | grep -v '^\\s*#' | head -10"
    command_result="${cgi_locations:-No CGI configurations found}"

    # CGI/FastCGI 매핑이 존재하면 (백엔드 주소와 무관하게) 실행 가능 디렉터리 제한 여부를
    # 정적 설정만으로 확인할 수 없으므로 양호로 단정하지 않고 수동진단으로 분류한다.
    # (location ~ \.php$ 등 catch-all 매핑은 제한 없는 취약 사례이며, grep 기반
    # 위치 추론은 include 파일 미추적·블록 경계 모호성으로 신뢰할 수 없음 → Windows 형제 스크립트와 정렬)
    if [ "${cgi_count}" -eq 0 ] && [ "${config_readable}" = false ]; then
        # nginx 프로세스는 실행 중이나 설정 파일을 읽을 수 없거나 존재하지 않음.
        # 읽지 못한 설정에 제한 없는 fastcgi/scgi/uwsgi/cgi_pass가 포함될 수 있으므로
        # GOOD로 단정할 수 없어 수동진단으로 분류. (WEB-04 Linux / WEB-05 Windows 형제와 정렬)
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="Nginx가 실행 중이나 점검 가능한 설정 파일(/etc/nginx/nginx.conf, conf.d, sites-enabled)을 찾거나 읽을 수 없습니다. fastcgi/scgi/uwsgi/cgi_pass 실행이 승인된 디렉터리로 제한되었는지 수동으로 확인하세요."
        command_result="No readable nginx configuration file found while nginx is running"
    elif [ "${cgi_count}" -eq 0 ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="CGI 스크립트가 사용되지 않습니다."
    else
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="CGI/FastCGI 실행이 설정되어 있습니다. 실행이 승인된 디렉터리로 제한되었는지(업로드/게시판 경로가 아닌지) 확인이 필요하며, 정적 설정만으로는 디렉터리 제한 여부를 단정할 수 없습니다."
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
