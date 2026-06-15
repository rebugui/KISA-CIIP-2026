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
# @Platform    : Tomcat_Linux
# @Severity    : 상
# @Title       : 웹 서비스 디렉터리 리 스팅 방지 설정
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

    local diagnosis_result="MANUAL"
    local status="수동진단"
    local inspection_summary=""
    local command_result=""
    local command_executed=""
    local has_listings_true=false
    local listings_config=""
    local listings_value=""

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
                # default servlet의 listings init-param 값 확인
                # 라인 윈도(-A2)는 listings 파라미터(<servlet-name>default</servlet-name> 아래
                # 6~9줄)에 도달하지 못하므로, 파일 전체에서 공백/개행에 관대하게
                # <param-name>listings</param-name> 다음의 <param-value>를 추출한다.
                listings_value=$(awk '
                    { line = line " " $0 }
                    END {
                        gsub(/\r/, "", line)
                        gsub(/>[ \t]+</, "><", line)
                        while (match(line, /<param-name>[ \t]*listings[ \t]*<\/param-name>[ \t]*<param-value>[ \t]*(true|false)[ \t]*<\/param-value>/)) {
                            seg = substr(line, RSTART, RLENGTH)
                            line = substr(line, RSTART + RLENGTH)
                            if (seg ~ /<param-value>[ \t]*true[ \t]*<\/param-value>/) { print "true"; exit }
                            val = "false"
                        }
                        if (val == "false") print "false"
                    }
                ' "${xml_file}" 2>/dev/null || echo "")
                listings_config="listings=${listings_value:-unset}"

                # listings=true 확인
                if [ "${listings_value}" = "true" ]; then
                    has_listings_true=true
                fi
                break 2
            fi
        done
    done

    if [ -n "${found_file}" ]; then
        command_executed="awk 'parse <param-name>listings</param-name>/<param-value> pair' ${found_file}"
        command_result="${listings_config:-No listings configuration found (default: false)}"
    else
        command_executed="ls /etc/tomcat*/web.xml /var/lib/tomcat*/conf/web.xml 2>/dev/null"
        command_result="web.xml file not found"
        diagnosis_result="MANUAL"
        status="수동진단"
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
    elif [ "${listings_value}" = "false" ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="디렉터리 리스팅이 false로 명시적으로 비활성화되어 있습니다. (보안 권고사항 준수)"
    else
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="DefaultServlet의 listings init-param이 명시되어 있지 않습니다. web.xml에서 디렉터리 리스팅 정책을 수동으로 확인하십시오."
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
