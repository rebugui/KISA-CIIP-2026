#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : WEB-15
# @Category    : Server
# @Platform    : Tomcat_Linux
# @Severity    : 상
# @Title       : 웹 서비스의 불필요한 스크립트 매핑 제거
# @Description : 불필요한 CGI 스크립트 핸들러 매핑 제거 여부 점검
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

ITEM_ID="WEB-15"
ITEM_NAME="웹 서비스의 불필요한 스크립트 매핑 제거"
SEVERITY="상"

GUIDELINE_PURPOSE="웹 서비스에서 사용하지 않는 불필요 스크립트 매핑이 존재하는지 점검하여 잠재적 보안 위협을 방지하기 위함"
GUIDELINE_THREAT="웹 서비스에서 불필요한 스크립트 매핑을 제거하지 않은 경우, 버퍼오버플로우(Buffer Overflow), 서비스 거부 공격(Denial of Service), 크로스 사이트 스크립 팅(CrossSiteScripting) 등의 공격 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="불필요한 스크립트 매핑이 존재하지 않는 경우"
GUIDELINE_CRITERIA_BAD="불필요한 스크립트 매핑이 존재하는 경우"
GUIDELINE_REMEDIATION="불필요한 스크립트 매핑 존재 여부 점검 및 제거 설정"

diagnose() {
    echo "진단 항목: ${ITEM_ID} - ${ITEM_NAME}"

    local diagnosis_result="MANUAL"
    local status="수동진단"
    local inspection_summary=""
    local command_result=""
    local command_executed=""
    local mapping_count=0
    local unnecessary_mappings=0
    local config_found=false

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

    local web_xml_locations=(
        "/etc/tomcat*/web.xml"
        "/var/lib/tomcat*/conf/web.xml"
        "/usr/share/tomcat*/conf/web.xml"
    )

    # 불필요한 스크립트 매핑 점검
    # 가이드라인 기준: 불필요한 스크립트 매핑(CGI/SSI/Invoker 등) 존재 여부 점검.
    # DefaultServlet, JspServlet은 Tomcat 표준 필수 서블릿이므로 불필요 매핑으로 판단하지 않음.
    # (criteria_bad: 불필요한 스크립트 매핑이 존재하는 경우)
    local servlet_mappings=""
    local unnecessary_detail=""

    for xml_pattern in "${web_xml_locations[@]}"; do
        for xml_file in $xml_pattern; do
            if [ -f "${xml_file}" ]; then
                config_found=true
                # 불필요 스크립트 매핑(CGI/SSI/Invoker)만 점검 (주석 제외)
                local found_unnecessary=$(grep -iE "CGIServlet|SSIServlet|InvokerServlet|<servlet-name>\s*(cgi|ssi|invoker)\s*</servlet-name>" "${xml_file}" 2>/dev/null | grep -v "^\s*<!--" || true)
                if [ -n "${found_unnecessary}" ]; then
                    unnecessary_detail="${unnecessary_detail}"$'\n'"${found_unnecessary}"
                    local hits=$(echo "${found_unnecessary}" | grep -c . || true)
                    unnecessary_mappings=$((unnecessary_mappings + hits))
                fi

                # 전체 servlet-mapping 개수(참고용 evidence)
                local found_mappings=$(grep -E "servlet-mapping" "${xml_file}" 2>/dev/null | grep -v "^\s*<!--" || true)
                if [ -n "${found_mappings}" ]; then
                    mapping_count=$(echo "${found_mappings}" | grep -c "servlet-mapping" || true)
                fi
                servlet_mappings="${unnecessary_detail}"
                break 2
            fi
        done
    done

    command_executed="grep -iE 'CGIServlet|SSIServlet|InvokerServlet|<servlet-name>\\s*(cgi|ssi|invoker)\\s*</servlet-name>' /etc/tomcat*/web.xml 2>/dev/null | grep -v '^\\s*<!--' | head -10"
    command_result="${servlet_mappings:-No unnecessary (CGI/SSI/Invoker) script mappings found}"

    if [ "${config_found}" = false ]; then
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="Tomcat web.xml을 찾을 수 없습니다. 불필요한 스크립트 매핑(CGI/SSI/Invoker)이 존재하는지 수동으로 확인하세요."
    elif [ ${unnecessary_mappings} -gt 0 ]; then
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="${unnecessary_mappings}개의 불필요한 스크립트 매핑(CGI/SSI/Invoker)이 발견되었습니다. 제거 권장."
    else
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="불필요한 스크립트 매핑(CGI/SSI/Invoker)이 발견되지 않았습니다(표준 서블릿 DefaultServlet/JspServlet은 제외). (보안 권고사항 준수)"
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

if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi
