#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : WEB-14
# @Category    : Server
# @Platform    : Tomcat_Linux
# @Severity    : 상
# @Title       : 웹 서비스 경로 내 파일의 접근 통제
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

ITEM_ID="WEB-14"
ITEM_NAME="웹 서비스 경로 내 파일의 접근 통제"
SEVERITY="상"

GUIDELINE_PURPOSE="웹 서비스 경로의 파일들에 관리자를 제외한 일반 사용자의 파일 접근 권한을 제거함으로써 인가되지 않은 사용자가 허용되지 않는 파일에 접근하는 것을 차단하기 위함"
GUIDELINE_THREAT="웹 서비스 경로 파일에 비인가자가 접근 가능한 경우, 해당 파일의 수정 및 삭제로 인해 웹 서비스 운영 장애 및 계정 비밀번호 정보 등의 중요한 정보가 노출될 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="주요 설정 파일 및 디렉터리에 불필요한 접근 권한이 부여되지 않은 경우"
GUIDELINE_CRITERIA_BAD="주요 설정 파일 및 디렉터리에 불필요한 접근 권한이 부여된 경우"
GUIDELINE_REMEDIATION="주요 설정 파일 및 디렉터리에 불필요한 접근 권한 제거 설정"

diagnose() {
    echo "진단 항목: ${ITEM_ID} - ${ITEM_NAME}"

    local diagnosis_result="UNKNOWN"
    local status="미진단"
    local inspection_summary=""
    local command_result=""
    local command_executed=""
    local cgi_count=0
    local jsp_count=0

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

    local script_mappings=""

    for xml_pattern in "${web_xml_locations[@]}"; do
        for xml_file in $xml_pattern; do
            if [ -f "${xml_file}" ]; then
                # CGI Servlet 확인
                local found_cgi=$(grep -i "CGIServlet|cgi" "${xml_file}" 2>/dev/null | grep -E "servlet|servlet-mapping" | grep -v "^\s*<!--" || true)
                if [ -n "${found_cgi}" ]; then
                    script_mappings="${script_mappings}"$'\n'"CGI: ${found_cgi}"
                    cgi_count=$((cgi_count + 1))
                fi

                # JSP Servlet 확인 (Jasper)
                local found_jsp=$(grep -i "JspServlet|jsp" "${xml_file}" 2>/dev/null | grep -E "servlet|servlet-mapping" | grep -v "^\s*<!--" || true)
                if [ -n "${found_jsp}" ]; then
                    script_mappings="${script_mappings}"$'\n'"JSP: ${found_jsp}"
                    jsp_count=$((jsp_count + 1))
                fi

                break 2
            fi
        done
    done

    local total_mappings=$((cgi_count + jsp_count))

    command_executed="grep -E 'CGIServlet|JspServlet' /etc/tomcat*/web.xml 2>/dev/null | grep -v '^\\s*<!--' | head -5"
    command_result="${script_mappings:-No script mappings found}"

    if [ ${total_mappings} -eq 0 ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="스크립트 매핑이 발견되지 않았습니다 (정적 리소스 전용)."
    elif [ ${cgi_count} -eq 0 ] && [ ${jsp_count} -le 2 ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="필수적인 JSP 매핑만 존재합니다. CGI Servlet은 비활성화되어 있습니다. (보안 권고사항 준수)"
    elif [ ${cgi_count} -gt 0 ]; then
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="CGI Servlet이 활성화되어 있습니다(${cgi_count}개). CGI는 취약할 수 있으므로 비활성화 권장."
    else
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="스크립트 매핑이 ${total_mappings}개 발견되었습니다. 불필요한 매핑 제거 권장."
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
