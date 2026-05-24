#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : WEB-16
# @Category    : Server
# @Platform    : Tomcat_Linux
# @Severity    : 중
# @Title       : 웹 서비스 헤더 정보 노출 제한
# @Description : HTTP 응답 헤더에서 웹서버 버전 정보 등 불필요한 정보 노출 제한 여부 점검
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

ITEM_ID="WEB-16"
ITEM_NAME="웹 서비스 헤더 정보 노출 제한"
SEVERITY="중"

GUIDELINE_PURPOSE="HTTP 응답 헤더에서 웹 서버 버전 및 종류,OS 정보 등 웹 서버와 관련된 정보가 불필요하게 노출되는 것을 최소화하기 위함"
GUIDELINE_THREAT="웹 서버 및 OS 정보가 노출될 경우 공격자에 의해 해당 버전의 알려진 취약점을 이용하여 시스템 구조와 특성 노출 및 해당 취약점을 통한 공격의 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="HTTP 응답 헤더에서 웹 서버 정보가 노출되지 않는 경우"
GUIDELINE_CRITERIA_BAD="HTTP 응답 헤더에서 웹 서버 정보가 노출되는 경우"
GUIDELINE_REMEDIATION="응답 헤더에 표시되는 정보를 최소한으로 제한하여 설정"

diagnose() {
    echo "진단 항목: ${ITEM_ID} - ${ITEM_NAME}"

    local diagnosis_result="UNKNOWN"
    local status="미진단"
    local inspection_summary=""
    local command_result=""
    local command_executed=""
    local server_hidden=false

    # Process check (Updated for Docker)
    if command -v pgrep >/dev/null; then
        if ! pgrep -f "catalina|tomcat" > /dev/null; then
            diagnosis_result="N/A"
            status="N/A"
            inspection_summary="Tomcat 웹 서버가 실행 중이 아닙니다."
            command_result="Tomcat process not found"
            command_executed="pgrep -f 'catalina|tomcat'"

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

    local server_xml_locations=(
        "/etc/tomcat*/server.xml"
        "/var/lib/tomcat*/conf/server.xml"
        "/usr/share/tomcat*/conf/server.xml"
    )

    local connector_config=""

    for xml_pattern in "${server_xml_locations[@]}"; do
        for xml_file in $xml_pattern; do
            if [ -f "${xml_file}" ]; then
                # Connector server 속성 확인
                local server_attr=$(grep -E "Connector.*server=" "${xml_file}" 2>/dev/null | grep -v "^\s*<!--" || true)
                if [ -n "${server_attr}" ]; then
                    connector_config="${server_attr}"
                    if echo "${server_attr}" | grep -q 'server=""'; then
                        server_hidden=true
                    fi
                fi
                break 2
            fi
        done
    done

    command_executed="grep -E 'Connector.*server=' /etc/tomcat*/server.xml 2>/dev/null | grep -v '^\\s*<!--' | head -2"
    command_result="${connector_config:-No server attribute found (default: Apache-Coyote/1.1)}"

    if [ "${server_hidden}" = true ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="Connector에 server=\"\" 설정이 되어 있습니다. Server 헤더 정보가 숨겨집니다. (보안 권고사항 준수)"
    else
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="Server 헤더에 Tomcat 버전 정보가 노출될 수 있습니다. server=\"\" 설정으로 Server 헤더 숨김 권장."
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
