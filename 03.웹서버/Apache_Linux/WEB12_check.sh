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
# @Platform    : Apache_Linux
# @Severity    : 중
# @Title       : 웹 서비스 링크 사용 금지
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

    local diagnosis_result="UNKNOWN"
    local status="미진단"
    local inspection_summary=""
    local command_result=""
    local command_executed=""
    local followsymlinks_found=false
    local followsymlinks_disabled=false

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

    local options_settings=""
    local alias_settings=""
    local readable_conf_found=false
    local options_directive_found=false
    for conf_pattern in "${apache_conf_locations[@]}"; do
        for conf_file in $conf_pattern; do
            if [ -f "${conf_file}" ] && [ -r "${conf_file}" ]; then
                readable_conf_found=true
                # Options 지시어 확인 (주석 제외)
                local found_options=$(grep -E "^\s*Options" "${conf_file}" 2>/dev/null | grep -v "^\s*#" || true)
                if [ -n "${found_options}" ]; then
                    options_directive_found=true
                    options_settings="${options_settings}"$'\n'"${found_options}"
                fi
                # Alias 지시어 확인 (가이드라인: aliases 링크 사용 점검 대상)
                local found_alias=$(grep -E "^\s*(Alias|ScriptAlias)\s" "${conf_file}" 2>/dev/null | grep -v "^\s*#" || true)
                if [ -n "${found_alias}" ]; then
                    alias_settings="${alias_settings}"$'\n'"${found_alias}"
                fi
            fi
        done
    done

    command_executed="grep -E '^\s*(Options|Alias|ScriptAlias)' /etc/apache2/apache2.conf /etc/httpd/conf/httpd.conf /etc/apache2/sites-enabled/*.conf 2>/dev/null | grep -v '^\s*#'"

    # FollowSymLinks / Includes 등 위험 옵션이 명시적으로 활성화되어 있는지 확인
    # (마지막 토큰 기준이 아니라 '+Opt' 또는 '-Opt' 부호 없는 활성화를 위험으로 간주)
    # 'All'(=MultiViews를 제외한 모든 옵션, FollowSymLinks 포함) 별칭도 활성화로 간주
    if echo "${options_settings}" | grep -qE "(^|[[:space:]])\+?(FollowSymLinks|All)([[:space:]]|\$)"; then
        followsymlinks_found=true
    fi
    if echo "${options_settings}" | grep -qE "\-(FollowSymLinks|All)([[:space:]]|\$)"; then
        followsymlinks_disabled=true
    fi

    local alias_present=false
    [ -n "${alias_settings}" ] && alias_present=true

    command_result="Options:${options_settings:-(none)}"$'\n'"Alias:${alias_settings:-(none)}"

    if [ "${readable_conf_found}" != true ]; then
        # 설정 파일을 읽을 수 없음 -> 판단 불가
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="Apache 설정 파일을 읽을 수 없어 링크(FollowSymLinks/Alias) 설정을 확인할 수 없습니다. 설정 파일에서 Options 및 Alias 지시자를 수동으로 확인하세요."
    elif [ "${followsymlinks_found}" = true ] && [ "${followsymlinks_disabled}" = true ]; then
        # +FollowSymLinks와 -FollowSymLinks가 함께 존재 -> 각 Directory 블록별 유효 설정을 정적으로 판단 불가
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="Options에 +FollowSymLinks와 -FollowSymLinks가 함께 설정되어 있습니다. 각 Directory 블록별 유효 설정을 수동으로 확인하세요."
    elif [ "${followsymlinks_found}" = true ] && [ "${followsymlinks_disabled}" = false ]; then
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="Options에 FollowSymLinks가 활성화되어 있습니다. 심볼릭 링크 사용 제한이 필요합니다."
    elif [ "${alias_present}" = true ]; then
        # Alias/ScriptAlias가 존재하면 정당성은 정적으로 판단 불가 -> 수동진단
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="Alias/ScriptAlias 링크 설정이 발견되었습니다. 해당 링크가 업무상 필요한지 수동으로 확인하세요. (발견된 Alias: ${alias_settings#$'\n'})"
    elif [ "${followsymlinks_disabled}" = true ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="Options -FollowSymLinks가 설정되어 있고 불필요한 Alias가 없습니다. (보안 권고사항 준수)"
    elif echo "${options_settings}" | grep -q "SymLinksIfOwnerMatch"; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="SymLinksIfOwnerMatch가 설정되어 있습니다. 소유자 검증 후 심볼릭 링크 허용. (보안 권고사항 준수)"
    elif [ "${options_directive_found}" != true ]; then
        # Options 지시자 자체가 없음 -> 컴파일 기본값이 FollowSymLinks를 포함할 수 있어 판단 불가
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="Options 지시자가 설정 파일에 명시되어 있지 않습니다. Apache 컴파일 기본값에 FollowSymLinks가 포함될 수 있으므로 각 Directory 블록의 유효 Options를 수동으로 확인하세요."
    else
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="FollowSymLinks 활성화 및 불필요한 Alias가 발견되지 않았습니다. (보안 권고사항 준수)"
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
