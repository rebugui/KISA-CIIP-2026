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
# @Platform    : Nginx_Linux
# @Severity    : 상
# @Title       : 웹 서비스 디렉터리 리 스팅 방지 설정
# @Description : 디렉터리 리스팅 기능 차단 여부 점검
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

    local diagnosis_result="UNKNOWN"
    local status="미진단"
    local inspection_summary=""
    local command_result=""
    local command_executed=""
    local has_autoindex_on=false
    local autoindex_settings=""
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
        # 주석을 먼저 제거한 뒤 autoindex 지시자를 단어 경계로 탐지한다.
        # 데비안 기본 vhost처럼 한 줄에 `location / { autoindex on; }` 형태로
        # 인라인 작성된 경우도 포함되도록 줄 시작 고정(^\s*) 대신 \bautoindex\b 사용.
        local found_autoindex
        found_autoindex=$(sed -E 's/#.*$//' "${conf_file}" 2>/dev/null | grep -E "\bautoindex\b" || true)
        if [ -n "${found_autoindex}" ]; then
            autoindex_settings="${autoindex_settings}"$'\n'"${found_autoindex}"
            # 디렉터리 리스팅이 켜진 경우(autoindex on)만 취약으로 판정한다.
            if echo "${found_autoindex}" | grep -Eqi "\bautoindex\b[[:space:]]+on\b"; then
                has_autoindex_on=true
            fi
        fi

        # include 지시자를 해석하여 외부/확장자 없는 vhost의 autoindex 설정도 스캔한다.
        # (Windows 라이브러리 Get-NginxWindowsConfigText와 동일한 의도)
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

    command_executed="grep -E '^\\s*autoindex' /etc/nginx/nginx.conf /etc/nginx/conf.d/* /etc/nginx/sites-enabled/* (include 지시자로 참조되는 vhost 포함) 2>/dev/null | grep -v '^\\s*#' | head -5"
    command_result="${autoindex_settings:-autoindex not set (default: off)}"

    if [ "${has_autoindex_on}" = true ]; then
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="autoindex가 on으로 설정되어 있습니다. 디렉터리 내 파일 목록이 노출될 수 있습니다. autoindex off; 설정 권장."
    elif [ "${config_readable}" = false ]; then
        # nginx 프로세스는 실행 중이나 설정 파일을 읽을 수 없거나 존재하지 않음.
        # 읽지 못한 설정에 autoindex on이 포함될 수 있으므로 GOOD로 단정할 수 없어 수동진단으로 분류.
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="Nginx가 실행 중이나 점검 가능한 설정 파일(/etc/nginx/nginx.conf, conf.d, sites-enabled)을 찾거나 읽을 수 없습니다. autoindex 설정 여부를 수동으로 확인하세요."
        command_result="No readable nginx configuration file found while nginx is running"
    else
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="autoindex가 off로 설정되었거나 설정되지 않았습니다 (기본값: off). 디렉터리 리스팅이 차단되어 있습니다."
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
