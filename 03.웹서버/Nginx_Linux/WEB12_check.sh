#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : WEB-12
# @Category    : Web Server
# @Platform    : Nginx
# @Severity    : 상
# @Title       : 웹서비스링크사용금지
# @Description : 웹 서비스에서의 심볼릭 링크 사용 금지 여부 점검
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

ITEM_ID="WEB-12"
ITEM_NAME="웹 서비스 링크 사용 금지"
SEVERITY="중"

GUIDELINE_PURPOSE="무분별한 심볼 릭 링크, 별칭(aliases) 등을 제거하여 허용하지 않은 경로에서의 접근을 차단해 경로 검증을 우회한 시스템 파일 접근을 방지하기 위함"
GUIDELINE_THREAT="보안상 민감한 내용이 포함되어 있는 파일이 악의적인 사용자에게 노출될 경우 침해 사고로 이어질 위험이 존재함 접근을 허용한 웹 디렉터리 내에 서버의 다른 디렉터리나 파일들에 접근할 수 있는 심볼 릭 링크, aliases, 바로가기 등이 존재하는 경우 해당 링크를 통해 허용하지 않은 다른 디렉터리에 액세스할 수 있는 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="심볼 릭 링크,aliases, 바로가기 등의 링크 사용을 허용하지 않는 경우"
GUIDELINE_CRITERIA_BAD="심볼 릭 링크,aliases, 바로가기 등의 링크 사용을 허용하는 경우"
GUIDELINE_REMEDIATION="웹 서비스 링크 사용 제한 설정"

diagnose() {
    echo "진단 항목: ${ITEM_ID} - ${ITEM_NAME}"

    local diagnosis_result="MANUAL"
    local status="수동진단"
    local inspection_summary=""
    local command_result=""
    local command_executed=""
    local symlink_settings=""
    local has_symlink_protection=false

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

    # Check document roots for symbolic links
    local doc_roots=$(grep -rhE "^\s*root\s+" /etc/nginx/ 2>/dev/null | grep -v "^\s*#" | awk '{print $2}' | sed 's/;//' | sort -u | head -5 || true)

    if [ -z "${doc_roots}" ]; then
        doc_roots="/usr/share/nginx/html /var/www/html"
    fi

    local symlink_count=0

    for doc_root in ${doc_roots}; do
        if [ -d "${doc_root}" ]; then
            # Count symbolic links in document root
            local found_symlinks=$(find "${doc_root}" -type l 2>/dev/null | head -10 || true)
            if [ -n "${found_symlinks}" ]; then
                symlink_count=$(echo "${found_symlinks}" | wc -l)
                symlink_settings="${symlink_settings}"$'\n'"${doc_root}:"$'\n'"${found_symlinks}"
            fi
        fi
    done

    # Check for disable_symlinks directive
    for conf_pattern in "${nginx_conf_locations[@]}"; do
        for conf_file in $conf_pattern; do
            if [ -f "${conf_file}" ]; then
                local found_disable=$(grep -E "^\s*disable_symlinks" "${conf_file}" 2>/dev/null | grep -v "^\s*#" || true)
                if [ -n "${found_disable}" ]; then
                    symlink_settings="${symlink_settings}"$'\n'"${conf_file}: ${found_disable}"
                    has_symlink_protection=true
                fi
            fi
        done
    done

    command_executed="find /usr/share/nginx/html /var/www/html -type l 2>/dev/null | head -10; grep -E '^\\s*disable_symlinks' /etc/nginx/nginx.conf"
    command_result="${symlink_settings:-No symbolic links found and no disable_symlinks directive}"

    if [ "${has_symlink_protection}" = true ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="disable_symlinks 지시어가 설정되어 있어 심볼릭 링크 사용이 제한됩니다."
    elif [ "${symlink_count}" -gt 0 ]; then
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="${symlink_count}개의 심볼릭 링크가 발견되었습니다. 불필요한 링크 제거 및 disable_symlinks 설정 권장."
    else
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="심볼릭 링크가 발견되지 않았습니다. disable_symlinks on; 설정 추가로 강화 권장."
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
