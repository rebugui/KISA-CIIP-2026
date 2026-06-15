#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : WEB-22
# @Category    : Server
# @Platform    : Tomcat_Linux
# @Severity    : 하
# @Title       : 에러 페이지 관리
# @Description : 커스텀 에러 페이지 설정 여부 점검
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

ITEM_ID="WEB-22"
ITEM_NAME="에러 페이지 관리"
SEVERITY="하"

GUIDELINE_PURPOSE="에러 페이지에서 웹 서버 버전 및 종류, OS 정보 등 웹 서버와 관련된 불필요한 정보 및 에러 코드를 통한 기술적 취약점이 노출되는 것을 최소화하기 위함"
GUIDELINE_THREAT="에러 페이지에서 불필요한 정보가 노출될 경우 공격자에 의해 해당 버전의 알려진 취약점 등을 이용하여 시스템 구조와 특성 노출 및 해당 취약점을 통한 공격의 위험이 존재함 필수 에러 코드에 대해 일원화된 에러 페이지로 관리하지 않는 경우 에러 코드를 통해 각종 정보 유추의 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="웹 서비스 에러 페이지가 별도로 지정된 경우"
GUIDELINE_CRITERIA_BAD="웹 서비스 에러 페이지가 별도로 지정되지 않거나 에러 발생 시 중요 정보가 노출되는 경우"
GUIDELINE_REMEDIATION="필수 에러 코드에 대해 일원화된 에러 페이지 사용 및 에러 페이지 내 불필요 정보 노출 제한 설정"

diagnose() {
    echo "진단 항목: ${ITEM_ID} - ${ITEM_NAME}"

    local diagnosis_result="MANUAL"
    local status="수동진단"
    local inspection_summary=""
    local command_result=""
    local command_executed=""
    local error_page_count=0

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
        "${CATALINA_HOME:-/usr/local/tomcat}/conf/web.xml"
        "/usr/local/tomcat/conf/web.xml"
        "/etc/tomcat*/web.xml"
        "/var/lib/tomcat*/conf/web.xml"
        "/usr/share/tomcat*/conf/web.xml"
    )

    local error_config=""
    local found_web_xml=""

    for xml_pattern in "${web_xml_locations[@]}"; do
        for xml_file in $xml_pattern; do
            if [ -f "${xml_file}" ]; then
                found_web_xml="${xml_file}"
                # 커스텀 <error-page> 엘리먼트 확인 (주석 제외)
                local found_error=$(grep -E "<error-page>" "${xml_file}" 2>/dev/null | grep -v "^\s*<!--" || true)
                if [ -n "${found_error}" ]; then
                    error_config="${found_error}"
                fi
                # 판단기준(가이드): 에러 페이지가 '별도로 지정'되어야 양호.
                # servlet web.xml에서 <location>은 <error-page> 블록에서만 사용되므로
                # 비어있지 않은 <location> 값(커스텀 페이지 경로)의 개수로 판정한다.
                # XML이 여러 줄에 걸쳐 있을 수 있으므로 개행을 공백으로 치환(tr)한 뒤
                # 주석(<!-- ... -->) 블록을 제거하고 유효한 <location>만 계수한다.
                if [ -r "${xml_file}" ]; then
                    error_page_count=$(tr '\n' ' ' < "${xml_file}" 2>/dev/null \
                        | sed -E 's/<!--[^-]*(-[^-]+)*-->/ /g' \
                        | grep -oE '<location>[[:space:]]*[^<[:space:]][^<]*</location>' \
                        | grep -c '<location>' || true)
                fi
                break 2
            fi
        done
    done

    command_executed="tr '\\n' ' ' < ${found_web_xml:-/usr/local/tomcat/conf/web.xml} | grep -oE '<location>[^<]+</location>' | grep -c '<location>'"
    command_result="${error_config:-No <error-page> configuration found}"

    if [ -z "${found_web_xml}" ]; then
        # web.xml을 찾지 못하면 자동 판정 불가 → 증거 기반 MANUAL
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="Tomcat web.xml을 표준 경로 및 CATALINA_HOME에서 찾을 수 없어 자동 판정이 불가합니다. web.xml의 error-page 설정을 수동으로 확인하세요."
        command_result="web.xml not found in standard or CATALINA_HOME locations"
    elif [ ${error_page_count} -gt 0 ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="${error_page_count}개의 커스텀 error-page가 web.xml에 설정되어 있습니다. (보안 권고사항 준수)"
    else
        # docs WEB-22 criteria_bad: 에러 페이지가 별도로 지정되지 않은 경우 취약
        # (커스텀 error-page 미설정 시 Tomcat 기본 에러 페이지가 서버/스택 정보를 노출)
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="web.xml에 커스텀 error-page 설정이 없습니다. Tomcat 기본 에러 페이지는 서버 버전 및 스택 정보를 노출하므로 취약합니다. web.xml에 error-page를 설정하세요."
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
