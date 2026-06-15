#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : WEB-19
# @Category    : Server
# @Platform    : Tomcat_Linux
# @Severity    : 중
# @Title       : 웹 서비스 SSI(Server Side Includes)사용 제한
# @Description : SSI(Server Side Includes) 사용 제한 여부 점검
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

ITEM_ID="WEB-19"
ITEM_NAME="웹 서비스 SSI(Server Side Includes)사용 제한"
SEVERITY="중"

GUIDELINE_PURPOSE="웹 서비스 내 SSI 사용을 제한하여 불법적인 데이터 접근을 차단하여 웹 서버의 보안을 강화하기 위함"
GUIDELINE_THREAT="웹 서비스 내 SSI 사용을 제한하지 않을 경우, 공격자가 SSI 기능을 이용하여 시스템 명령 실행 및 중요 파일 탈취 등 공격이 가능하며, 이를 통해 서버 시스템 침해, 데이터 유출 등이 발생할 위험이 존재함 SSI 공격 시 HTML 페이지에 스크립트를 삽입하거나 원격으로 코드를 실행하여 웹 서비스를 악용할 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="웹 서비스 SSI 사용 설정이 비활성화되어 있는 경우"
GUIDELINE_CRITERIA_BAD="웹 서비스 SSI 사용 설정이 활성화되어 있는 경우"
GUIDELINE_REMEDIATION="웹 서비스 내 불필요한 SSI 사용 제한 설정"

diagnose() {
    echo "진단 항목: ${ITEM_ID} - ${ITEM_NAME}"

    local diagnosis_result="MANUAL"
    local status="수동진단"
    local inspection_summary=""
    local command_result=""
    local command_executed=""
    local has_ssi=false

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

    local web_xml_locations=(
        "/etc/tomcat*/web.xml"
        "/var/lib/tomcat*/conf/web.xml"
        "/usr/share/tomcat*/conf/web.xml"
    )

    local ssi_config=""

    for xml_pattern in "${web_xml_locations[@]}"; do
        for xml_file in $xml_pattern; do
            if [ -f "${xml_file}" ]; then
                # SSI Servlet 및 SSIFilter 확인 (활성 설정만; 주석 제외)
                # 가이드라인 Step 1: SSIServlet(<servlet-name>SSIServlet</servlet-name>) 또는
                # SSIFilter(<filter-name>SSIFilter</filter-name>) 모두 SSI 활성화 메커니즘
                # 주의: -E(ERE) 사용. BRE에서 | 는 리터럴로 처리되어 alternation이 동작하지 않음
                # 기본 Tomcat conf/web.xml 은 SSI 서블릿을 여러 줄 <!-- ... --> 블록 안에
                # 비활성(주석) 상태로 배포한다. 줄 시작(^\s*<!--) 필터만으로는 블록 내부의
                # <servlet-class>...SSIServlet</servlet-class> 줄을 제거하지 못해 비활성 SSI를
                # VULNERABLE 로 오판한다. 따라서 awk 로 <!-- ... --> 주석 구간(여러 줄/동일 줄)을
                # 먼저 제거한 뒤 매칭하여 활성(미주석) SSI 만 탐지한다. 후행 인라인 주석이 붙은
                # 활성 SSI 라인은 주석 부분만 제거되고 활성 토큰은 남으므로 계속 탐지된다.
                local found_ssi=$(awk '
                    {
                        line = $0; out = ""
                        while (length(line) > 0) {
                            if (incomment) {
                                p = index(line, "-->")
                                if (p == 0) { line = ""; break }
                                line = substr(line, p + 3); incomment = 0
                            } else {
                                p = index(line, "<!--")
                                if (p == 0) { out = out line; line = ""; break }
                                out = out substr(line, 1, p - 1)
                                line = substr(line, p + 4); incomment = 1
                            }
                        }
                        print out
                    }
                ' "${xml_file}" 2>/dev/null | grep -iE "SSIServlet|SSIFilter|<servlet-name>\s*ssi\s*</servlet-name>|<filter-name>\s*SSIFilter\s*</filter-name>" || true)
                if [ -n "${found_ssi}" ]; then
                    ssi_config="${found_ssi}"
                    has_ssi=true
                fi
                break 2
            fi
        done
    done

    command_executed="awk '<!-- ... --> 주석 구간 제거' /etc/tomcat*/web.xml 2>/dev/null | grep -iE 'SSIServlet|SSIFilter|<servlet-name>\\s*ssi\\s*</servlet-name>|<filter-name>\\s*SSIFilter\\s*</filter-name>' | head -3"
    command_result="${ssi_config:-SSI Servlet/Filter not found or commented}"

    if [ "${has_ssi}" = true ]; then
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="SSI Servlet이 활성화되어 있습니다. 코드 삽입 공격 위험으로 비활성화 권장."
    else
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="SSI Servlet이 비활성화되어 있거나 존재하지 않습니다. (보안 권고사항 준수)"
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
