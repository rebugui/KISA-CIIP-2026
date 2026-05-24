#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : WEB-17
# @Category    : Web Server
# @Platform    : Nginx_Linux
# @Severity    : 중
# @Title       : 웹 서비스 가상 디렉터리 삭제
# @Description : 불필요한 가상 디렉토리 삭제 여부 점검
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

ITEM_ID="WEB-17"
ITEM_NAME="웹 서비스 가상 디렉터리 삭제"
SEVERITY="중"

GUIDELINE_PURPOSE="불필요한 가상 디렉터리를 삭제하여 공격이 가능한 영역을 최소화하고 정보 노출 방지 및 권한 상승 공격 등의 위험을 제거하기 위함"
GUIDELINE_THREAT="불필요한 가상 디렉터리를 삭제하지 않은 경우, 취약한 가상 디렉터리를 통해 시스템 권한 탈취 및 시스템 구조 등의 중요 정보가 노출될 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="불필요한 가상 디렉터리가 존재하지 않는 경우"
GUIDELINE_CRITERIA_BAD="불필요한 가상 디렉터리가 존재하는 경우"
GUIDELINE_REMEDIATION="불필요한 가상 디렉터리 존재 여부 점검 및 삭제하도록 설정"

diagnose() {
    echo "진단 항목: ${ITEM_ID} - ${ITEM_NAME}"

    local diagnosis_result="UNKNOWN"
    local status="미진단"
    local inspection_summary=""
    local command_result=""
    local command_executed=""
    local alias_count=0

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

    local alias_settings=""

    for conf_pattern in "${nginx_conf_locations[@]}"; do
        for conf_file in $conf_pattern; do
            if [ -f "${conf_file}" ]; then
                local found_alias=$(grep -E "^\s*alias" "${conf_file}" 2>/dev/null | grep -v "^\s*#" || true)
                if [ -n "${found_alias}" ]; then
                    alias_settings="${alias_settings}"$'\n'"${found_alias}"
                    alias_count=$((alias_count + 1))
                fi
            fi
        done
    done

    command_executed="grep -E '^\\s*alias' /etc/nginx/nginx.conf /etc/nginx/conf.d/*.conf 2>/dev/null | grep -v '^\\s*#' | head -5"
    command_result="${alias_settings:-No alias found}"

    if [ ${alias_count} -eq 0 ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="alias 설정이 발견되지 않았습니다. (보안 권고사항 준수)"
    elif [ ${alias_count} -le 3 ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="alias가 ${alias_count}개 설정되어 있습니다. 최소한의 alias만 유지 권장."
    else
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="다수의 alias(${alias_count}개)가 발견되었습니다. 불필요한 alias 제거 권장."
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
