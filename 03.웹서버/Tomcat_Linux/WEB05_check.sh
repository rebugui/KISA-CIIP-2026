#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : WEB-05
# @Category    : Server
# @Platform    : Tomcat_Linux
# @Severity    : 상
# @Title       : 지정하지 않은 CGI/ISAPI 실행 제한
# @Description : 웹서비스 CGI 실행 제한 설정 여부 점검
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

ITEM_ID="WEB-05"
ITEM_NAME="지정하지 않은 CGI/ISAPI 실행 제한"
SEVERITY="상"

GUIDELINE_PURPOSE="CGI 스크립트를 정해진 디렉터리에서만 실행되도록하여 악의적인 파일의 업로드 및 실행을 방지하기 위함"
GUIDELINE_THREAT="게시판이나 자료실과 같이 업로드되는 파일이 저장되는 디렉터리에 CGI 스크립트가 실행 가능한 경우 악의적인 파일을 업로드하고 이를 실행하여 시스템의 중요 정보가 노출될 수 있으며 침해 사고의 경로로 이용될 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="CGI 스크립트를 사용하지 않거나 CGI 스크립트가 실행 가능한 디렉터리를 제한한 경우"
GUIDELINE_CRITERIA_BAD="CGI 스크립트를 사용하고 CGI 스크립트가 실행 가능한 디렉터리를 제한하지 않은 경우"
GUIDELINE_REMEDIATION="CGI 스크립트를 정해진 디렉터리 내에서만 실행할 수 있도록 설정"

diagnose() {
    echo "진단 항목: ${ITEM_ID} - ${ITEM_NAME}"

    local diagnosis_result="UNKNOWN"
    local status="미진단"
    local inspection_summary=""
    local command_result=""
    local command_executed=""
    local has_cgi_enabled=false
    local cgi_config=""

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

                # CGI servlet 정의 확인 (주석 제외)
                local cgi_servlet=$(grep "<servlet-name>cgi</servlet-name>" "${xml_file}" 2>/dev/null | grep -v "^\s*<!--" || true)

                # CGI servlet 매핑 확인 (주석 제외)
                local cgi_mapping=$(grep -A1 "<servlet-name>cgi</servlet-name>" "${xml_file}" 2>/dev/null | grep "<url-pattern>" | grep -v "^\s*<!--" || true)

                if [ -n "${cgi_servlet}" ] && [ -n "${cgi_mapping}" ]; then
                    cgi_config="CGI Servlet: ${cgi_servlet}\\nMapping: ${cgi_mapping}"
                    has_cgi_enabled=true
                fi
                break 2
            fi
        done
    done

    if [ -n "${found_file}" ]; then
        command_executed="grep -A1 '<servlet-name>cgi</servlet-name>' ${found_file} 2>/dev/null | grep -v '^\\s*<!--' | head -5"
        command_result="${cgi_config:-CGI not configured or commented out}"
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

    if [ "${has_cgi_enabled}" = true ]; then
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="CGI servlet이 활성화되어 있습니다. CGI servlet 및 매핑을 주석 처리하거나 제거하여 CGI 실행을 제한하세요."
    else
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="CGI servlet이 비활성화되어 있거나 설정되지 않았습니다. (보안 권고사항 준수)"
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
