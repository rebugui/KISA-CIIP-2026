#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : WEB-08
# @Category    : Server
# @Platform    : Tomcat_Linux
# @Severity    : 하
# @Title       : 웹 서비스 파일 업로드 및 다운로드 용량 제한
# @Description : 파일 업로드/다운로드 용량 제한(maxPostSize/multipart) 설정 여부 점검
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

ITEM_ID="WEB-08"
ITEM_NAME="웹 서비스 파일 업로드 및 다운로드 용량 제한"
SEVERITY="하"

GUIDELINE_PURPOSE="기반 시설 시스템은 원칙적으로 파일 업로드 및 다운로드를 금지하지만 불가피하게 파일의 업로드 및 다운로드 기능이 필요한 경우, 파일의 용량 제한을 설정하여 불필요한 업로드 및 다운로드를 방지해 서버의 과부하를 예방하고, 웹 서버 자원을 효율적으로 관리하기 위함"
GUIDELINE_THREAT="웹 서비스의 파일 업로드 및 다운로드의 용량을 제한하지 않은 경우, 악의적인 목적을 가진 사용자가 반복 업로드 및 웹 쉘 공격 등으로 시스템 권한을 탈취하거나 대용량 파일의 업로드 및 다운로드로 서버 자원을 고갈시켜 서비스 장애를 발생시킬 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="파일 업로드 및 다운로드 용량을 제한한 경우"
GUIDELINE_CRITERIA_BAD="파일 업로드 및 다운로드 용량을 제한하지 않은 경우"
GUIDELINE_REMEDIATION="파일 업로드 및 다운로드 용량을 허용 가능한 최소 범위로 제한하여 설정"

diagnose() {
    echo "진단 항목: ${ITEM_ID} - ${ITEM_NAME}"

    local diagnosis_result="MANUAL"
    local status="수동진단"
    local inspection_summary=""
    local command_result=""
    local command_executed=""

        # Process check (Updated for Docker)
    if command -v pgrep >/dev/null; then
    if ! pgrep -f "catalina|tomcat" > /dev/null; then
        diagnosis_result="N/A"
        status="N/A"
        inspection_summary="Tomcat 웹 서버가 실행 중이 아닙니다."
        command_result="Tomcat process not found"
        command_executed="pgrep -f 'catalina|tomcat'"

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

    # 파일 업로드 용량 제한 점검
    # 가이드라인 기준: server.xml Connector의 maxPostSize 설정 또는
    # web.xml multipart-config의 max-file-size/max-request-size 설정으로 업로드 용량 제한
    # (criteria_bad: 파일 업로드 및 다운로드 용량을 제한하지 않은 경우 = 무제한 업로드)
    # 참고: Tomcat에서 maxPostSize <= 0 은 무제한을 의미하므로 취약
    local server_xml_locations=(
        "/etc/tomcat*/server.xml"
        "/var/lib/tomcat*/conf/server.xml"
        "/usr/share/tomcat*/conf/server.xml"
    )
    local web_xml_locations=(
        "/etc/tomcat*/web.xml"
        "/var/lib/tomcat*/conf/web.xml"
        "/usr/share/tomcat*/conf/web.xml"
    )

    local upload_config=""
    local has_upload_limit=false
    local has_unlimited=false
    local config_found=false

    # server.xml: maxPostSize 점검
    for xml_pattern in "${server_xml_locations[@]}"; do
        for xml_file in $xml_pattern; do
            if [ -f "${xml_file}" ]; then
                config_found=true
                local found_maxpost=$(grep -iE "maxPostSize" "${xml_file}" 2>/dev/null | grep -v "^\s*<!--" || true)
                if [ -n "${found_maxpost}" ]; then
                    upload_config="${upload_config}"$'\n'"[server.xml] ${found_maxpost}"
                    # maxPostSize 값 추출 (음수 또는 0 이면 무제한 = 취약)
                    local maxpost_val=$(echo "${found_maxpost}" | grep -oiE 'maxPostSize\s*=\s*"-?[0-9]+"' | grep -oE '\-?[0-9]+' | head -1 || true)
                    if [ -n "${maxpost_val}" ]; then
                        if [ "${maxpost_val}" -gt 0 ] 2>/dev/null; then
                            has_upload_limit=true
                        else
                            has_unlimited=true
                        fi
                    fi
                fi
                break 2
            fi
        done
    done

    # web.xml: multipart-config max-file-size / max-request-size 점검
    for xml_pattern in "${web_xml_locations[@]}"; do
        for xml_file in $xml_pattern; do
            if [ -f "${xml_file}" ]; then
                config_found=true
                local found_multipart=$(grep -iE "max-file-size|max-request-size|multipart-config" "${xml_file}" 2>/dev/null | grep -v "^\s*<!--" || true)
                if [ -n "${found_multipart}" ]; then
                    # max-file-size 또는 max-request-size에 양수 값이 설정되어 있는지 확인
                    local size_val=$(grep -ioE "<max-(file|request)-size>\s*[0-9]+\s*</max-(file|request)-size>" "${xml_file}" 2>/dev/null | grep -oE '[0-9]+' | head -1 || true)
                    if [ -n "${size_val}" ] && [ "${size_val}" -gt 0 ] 2>/dev/null; then
                        upload_config="${upload_config}"$'\n'"[web.xml] ${found_multipart}"
                        has_upload_limit=true
                    fi
                fi
                break 2
            fi
        done
    done

    command_executed="grep -iE 'maxPostSize' /etc/tomcat*/server.xml 2>/dev/null; grep -iE 'max-file-size|max-request-size' /etc/tomcat*/web.xml 2>/dev/null | head -5"
    command_result="${upload_config:-No upload size limit (maxPostSize / multipart max-file-size) found}"

    if [ "${config_found}" = false ]; then
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="Tomcat 설정 파일(server.xml/web.xml)을 찾을 수 없습니다. Connector의 maxPostSize 또는 web.xml multipart-config의 max-file-size 설정으로 업로드 용량이 제한되어 있는지 수동으로 확인하세요."
    elif [ "${has_upload_limit}" = true ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="파일 업로드 용량 제한(maxPostSize 또는 multipart max-file-size)이 설정되어 있습니다. (보안 권고사항 준수)"
    elif [ "${has_unlimited}" = true ]; then
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="maxPostSize가 0 이하(무제한)로 설정되어 있어 파일 업로드 용량이 제한되지 않습니다. maxPostSize를 양수 값으로 설정하거나 web.xml multipart-config로 용량 제한 권장."
    else
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="파일 업로드 용량 제한(maxPostSize 또는 multipart max-file-size)이 설정되지 않았습니다. 업로드/다운로드 용량 제한 설정 권장."
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
