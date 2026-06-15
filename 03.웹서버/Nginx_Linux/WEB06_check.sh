#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : WEB-06
# @Category    : Web Server
# @Platform    : Nginx_Linux
# @Severity    : 상
# @Title       : 웹 서비스 상위 디렉터리 접근 제한 설정
# @Description : '..'와 같은 문자 사용 등을 통한 상위 디렉터리 접근 제한 여부 점검
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

ITEM_ID="WEB-06"
ITEM_NAME="웹 서비스 상위 디렉터리 접근 제한 설정"
SEVERITY="상"

GUIDELINE_PURPOSE="상위 디렉터리 접근 제한 설정을 통해 비인가자의 특정 디렉터리에 대한 접근 및 열람을 제한하여 중요 파일 및 데이터를 보호하고,Unicode 버그 및 서비스 거부 공격 등을 방지하기 위함"
GUIDELINE_THREAT="상위 디렉터리로 이동하는 것이 가능할 경우 접근하고자하는 디렉터리의 하위 경로에서 상위로 이동하며 정보 탐색이 가능하여 중요 정보가 노출될 위험이 존재함 악의적인 목적을 가진 사용자가 중요 파일 및 디렉터리의 접근이 가능하여 데이터가 유출될 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="상위 디렉터리 접근 기능을 제거한 경우"
GUIDELINE_CRITERIA_BAD="상위 디렉터리 접근 기능을 제거하지 않은 경우"
GUIDELINE_REMEDIATION="상위 디렉터리 접근 기능 제거 설정"

diagnose() {
    echo "진단 항목: ${ITEM_ID} - ${ITEM_NAME}"

    local diagnosis_result="MANUAL"
    local status="수동진단"
    local inspection_summary=""
    local command_result=""
    local command_executed=""
    local has_try_files=false
    local path_traversal_protection=""

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

    local nginx_conf_locations=(
        "/etc/nginx/nginx.conf"
        "/etc/nginx/conf.d/*.conf"
        "/etc/nginx/sites-enabled/*.conf"
    )

    local conf_files_read=0
    local alias_directives=""
    for conf_pattern in "${nginx_conf_locations[@]}"; do
        for conf_file in $conf_pattern; do
            if [ -f "${conf_file}" ]; then
                conf_files_read=$((conf_files_read + 1))
                # try_files 지시어 (참고용 — traversal 방어의 충분조건이 아님)
                local found_try_files=$(grep -E "^\s*try_files" "${conf_file}" 2>/dev/null | grep -v "^\s*#" || true)
                if [ -n "${found_try_files}" ]; then
                    path_traversal_protection="${path_traversal_protection}"$'\n'"${conf_file}: ${found_try_files}"
                    has_try_files=true
                fi
                # alias 지시어 (off-by-slash traversal의 주요 원인) 수집
                local found_alias=$(grep -E "^\s*alias\s+" "${conf_file}" 2>/dev/null | grep -v "^\s*#" || true)
                if [ -n "${found_alias}" ]; then
                    alias_directives="${alias_directives}"$'\n'"${conf_file}: ${found_alias}"
                fi
            fi
        done
    done

    command_executed="grep -E '^\\s*(try_files|alias)' /etc/nginx/nginx.conf /etc/nginx/conf.d/*.conf /etc/nginx/sites-enabled/*.conf 2>/dev/null | grep -v '^\\s*#' | head -10"
    command_result="try_files:${path_traversal_protection:-none}"$'\n'"alias:${alias_directives:-none}"

    # 판단 원칙:
    #  - try_files 존재만으로는 양호로 단정하지 않는다(alias off-by-slash traversal을 막지 못함).
    #  - 설정 파일을 읽지 못한 경우/alias 존재 시 → 수동진단(경로 조작 테스트 필요).
    if [ ${conf_files_read} -eq 0 ]; then
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="Nginx가 실행 중이나 설정 파일을 찾거나 읽을 수 없습니다. alias/root 설정 및 상위 디렉터리 접근(../) 차단 여부를 수동으로 확인하세요."
    elif [ -n "${alias_directives}" ]; then
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="alias 지시어가 발견되었습니다. alias는 경계(trailing slash) 설정 오류 시 상위 디렉터리 접근(off-by-slash) 우회가 가능하므로, location 경계와 traversal 차단 여부를 수동으로 점검하세요."
    else
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="Nginx는 기본적으로 상위 디렉터리 접근(../)을 차단하지만, try_files 존재만으로 traversal 차단을 단정할 수 없습니다. alias/root 설정의 적절성과 경로 조작 테스트를 통한 수동 검토가 필요합니다."
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
