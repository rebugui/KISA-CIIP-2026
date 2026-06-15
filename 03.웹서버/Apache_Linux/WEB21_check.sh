#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : WEB-21
# @Category    : Web Server
# @Platform    : Apache_Linux
# @Severity    : 중
# @Title       : HTTP 리디렉션
# @Description : 동적 페이지 요청 및 응답값에 대한 입력값 검증 구현 여부 점검
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

ITEM_ID="WEB-21"
ITEM_NAME="HTTP 리디렉션"
SEVERITY="중"

GUIDELINE_PURPOSE="HTTP 차단 및 HTTPS로 Redirection 활성화를 통해 평문으로 전송되는 데이터를 암호화하여 공격자의 데이터 스니 핑에 대비하기 위함"
GUIDELINE_THREAT="HTTP 통신은 암호화 전송이 아닌 평문 전송을 하므로 공격자가 스니핑을 시도할 경우 관리자의 ID, 비밀번호가 노출되어 악의적 사용자가 관리자 계정을 탈취할 수 있는 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="HTTP 접근 시 HTTPSRedirection이 활성화된 경우"
GUIDELINE_CRITERIA_BAD="HTTP 접근 시 HTTPSRedirection이 비활성화된 경우"
GUIDELINE_REMEDIATION="HTTP Redirection 활성화 설정"

diagnose() {
    echo "진단 항목: ${ITEM_ID} - ${ITEM_NAME}"

    local diagnosis_result="MANUAL"
    local status="수동진단"
    local inspection_summary=""
    local command_result=""
    local command_executed=""

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

    # WEB-21: HTTP -> HTTPS Redirection 활성화 여부 점검 (config 기반 자동 진단)
    local apache_conf_locations=(
        "/usr/local/apache2/conf/httpd.conf"
        "/usr/local/apache2/conf/extra/"*.conf
        "/etc/httpd/conf/httpd.conf"
        "/etc/httpd/conf.d/"*.conf
        "/etc/apache2/apache2.conf"
        "/etc/apache2/sites-enabled/"*.conf
        "/etc/apache2/conf-enabled/"*.conf
    )

    local conf_seen=false
    local has_redirect=false
    local matched_line=""
    local scanned_files=""
    # RewriteRule 기반 리디렉션은 'RewriteEngine On'이 적용된 경우에만 유효하다.
    # (Redirect/RedirectMatch 지시어는 RewriteEngine 없이도 동작하므로 별도 처리)
    local rewrite_engine_on=false
    for conf_pattern in "${apache_conf_locations[@]}"; do
        for conf_file in $conf_pattern; do
            if [ -f "${conf_file}" ]; then
                if grep -niE '^[[:space:]]*RewriteEngine[[:space:]]+On' "${conf_file}" 2>/dev/null | grep -vqE '^[0-9]+:[[:space:]]*#'; then
                    rewrite_engine_on=true
                fi
            fi
        done
    done

    for conf_pattern in "${apache_conf_locations[@]}"; do
        for conf_file in $conf_pattern; do
            if [ -f "${conf_file}" ]; then
                conf_seen=true
                scanned_files="${scanned_files}${conf_file} "
                # 주석(#)이 아닌 줄에서 https:// 로의 Redirect/RedirectMatch 탐지
                # (이 지시어들은 RewriteEngine 활성화 여부와 무관하게 동작)
                local hit
                hit=$(grep -niE '^[[:space:]]*Redirect(Match)?([[:space:]]+(permanent|seeother|temp|301|302))?[[:space:]]+.*https://' "${conf_file}" 2>/dev/null | grep -vE '^[0-9]+:[[:space:]]*#' | head -1 || true)
                if [ -n "${hit}" ]; then
                    has_redirect=true
                    matched_line="${conf_file}: ${hit}"
                    break 2
                fi
                # RewriteRule 기반 https 리디렉션은 RewriteEngine On일 때만 유효로 간주
                if [ "${rewrite_engine_on}" = true ]; then
                    hit=$(grep -niE '^[[:space:]]*RewriteRule[[:space:]]+.*https://' "${conf_file}" 2>/dev/null | grep -vE '^[0-9]+:[[:space:]]*#' | head -1 || true)
                    if [ -n "${hit}" ]; then
                        has_redirect=true
                        matched_line="${conf_file}: ${hit} (RewriteEngine On)"
                        break 2
                    fi
                fi
            fi
        done
    done

    command_executed="grep -niE 'Redirect.*https://|RewriteRule.*https://' <apache conf files>"

    if [ "${conf_seen}" = false ]; then
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="Apache 설정 파일을 찾을 수 없어 HTTP->HTTPS Redirection 활성화 여부를 자동으로 판단할 수 없습니다. 설정 파일에서 80 포트 접근 시 https:// 로의 Redirect/RewriteRule 설정 여부를 수동으로 확인하세요."
        command_result="No readable Apache configuration file found"
    elif [ "${has_redirect}" = true ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="HTTP 접근 시 HTTPS로의 Redirection이 활성화되어 있습니다. (${matched_line})"
        command_result="HTTPS redirection directive found: ${matched_line}"
    else
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="HTTP 접근 시 HTTPS로의 Redirection이 비활성화되어 있습니다. 검사한 설정 파일: ${scanned_files}"
        command_result="No HTTPS redirection directive found in: ${scanned_files}"
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
