#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : WEB-04
# @Category    : Server
# @Platform    : Tomcat
# @Severity    : 상
# @Title       : 웹서비스디렉터리리스팅방지설정
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
    local has_listings_true=false
    local listings_config=""

    # Tomcat 프로세스 확인
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

    # web.xml 위치 찾기
    local web_xml_locations=(
        "/etc/tomcat*/web.xml"
        "/var/lib/tomcat*/conf/web.xml"
        "/usr/share/tomcat*/conf/web.xml"
    )

    local found_file=""

    for xml_pattern in "${web_xml_locations[@]}"; do
        for xml_file in $xml_pattern; do
            if [ -f "${xml_file}" ]; then
                found_file="${xml_file}"
                # default servlet의 listings 설정 확인
                listings_config=$(grep -A2 "<servlet-name>default</servlet-name>" "${xml_file}" 2>/dev/null | grep -B1 -A1 "<param-name>listings</param-name>" || echo "")

                # listings=true 확인
                if echo "${listings_config}" | grep -q "<param-value>true</param-value>"; then
                    has_listings_true=true
                fi
                break 2
            fi
        done
    done

    if [ -n "${found_file}" ]; then
        command_executed="grep -A2 '<servlet-name>default</servlet-name>' ${found_file} 2>/dev/null | grep -B1 -A1 'listings' | head -5"
        command_result="${listings_config:-No listings configuration found (default: false)}"
    else
        command_executed="ls /etc/tomcat*/web.xml /var/lib/tomcat*/conf/web.xml 2>/dev/null"
        command_result="web.xml file not found"
        diagnosis_result="UNKNOWN"
        status="파일없음"
        inspection_summary="web.xml 파일을 찾을 수 없습니다."

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

    if [ "${has_listings_true}" = true ]; then
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="디렉터리 리스팅이 true로 설정되어 있습니다. listings=false로 변경 권장."
    else
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="디렉터리 리스팅이 비활성화되어 있거나 설정되지 않았습니다 (기본값: false). (보안 권고사항 준수)"
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
