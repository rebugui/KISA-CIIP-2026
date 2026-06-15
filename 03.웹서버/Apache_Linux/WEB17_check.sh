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
# @Platform    : Apache_Linux
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

        # Process check
    if command -v pgrep >/dev/null; then
        if ! pgrep -x "httpd" > /dev/null && ! pgrep -x "apache2" > /dev/null; then
            diagnosis_result="N/A"
            status="N/A"
            inspection_summary="Apache \xec\x9b\xb9 \xec\x84\x9c\xeb\xb2\x84\xea\xb0\x80 \xec\x8b\xa4\xed\x96\x89 \xec\xa4\x91\xec\x9d\xb4 \xec\x95\x84\xeb\x8b\x99\xeb\x8b\x88\xeb\x8b\xa4."
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

    local apache_conf_locations=(
        "/etc/apache2/apache2.conf"
        "/etc/httpd/conf/httpd.conf"
        "/usr/local/apache2/conf/httpd.conf"
        "/etc/apache2/sites-enabled/*.conf"
        "/etc/httpd/conf.d/*.conf"
    )

    local alias_settings=""
    local readable_conf_found=false
    for conf_pattern in "${apache_conf_locations[@]}"; do
        for conf_file in $conf_pattern; do
            if [ -f "${conf_file}" ] && [ -r "${conf_file}" ]; then
                readable_conf_found=true
                # Alias / ScriptAlias / AliasMatch 등 가상 디렉터리 지시자 확인
                local found_alias=$(grep -E "^\s*(Alias|AliasMatch|ScriptAlias|ScriptAliasMatch)\s" "${conf_file}" 2>/dev/null | grep -v "^\s*#" || true)
                if [ -n "${found_alias}" ]; then
                    # 발견된 각 Alias 라인을 개별 카운트
                    local line_count
                    line_count=$(echo "${found_alias}" | grep -cE "^\s*(Alias|AliasMatch|ScriptAlias|ScriptAliasMatch)\s" || true)
                    alias_count=$((alias_count + line_count))
                    alias_settings="${alias_settings}"$'\n'"${found_alias}"
                fi
            fi
        done
    done

    command_executed="grep -E '^\s*(Alias|ScriptAlias)' /etc/apache2/apache2.conf /etc/httpd/conf/httpd.conf /etc/apache2/sites-enabled/*.conf 2>/dev/null | grep -v '^\s*#' | head -10"
    command_result="${alias_settings#$'\n'}"
    [ -z "${command_result}" ] && command_result="No Alias directives found"

    if [ "${readable_conf_found}" != true ]; then
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="Apache 설정 파일을 읽을 수 없어 가상 디렉터리(Alias) 설정을 확인할 수 없습니다. 설정 파일에서 Alias/ScriptAlias 지시자를 수동으로 확인하세요."
    elif [ ${alias_count} -eq 0 ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="가상 디렉토리(Alias) 설정이 발견되지 않았습니다. (보안 권고사항 준수)"
    else
        # Alias가 존재하는 경우, 정당성(불필요 여부)은 정적으로 판단할 수 없으므로 수동진단
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="가상 디렉토리(Alias) ${alias_count}개가 발견되었습니다. 각 Alias가 업무상 필요한지 수동으로 확인하고 불필요한 가상 디렉터리는 제거하세요. (발견된 Alias: ${alias_settings#$'\n'})"
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

if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi
