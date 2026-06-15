#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : WEB-10
# @Category    : Server
# @Platform    : Tomcat_Linux
# @Severity    : 상
# @Title       : 불필요한 프 록 시 설정 제한
# @Description : 불필요한 Proxy 설정(proxyName/proxyPort/AJP Connector) 제한 여부 점검
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

ITEM_ID="WEB-10"
ITEM_NAME="불필요한 프 록 시 설정 제한"
SEVERITY="상"

GUIDELINE_PURPOSE="불필요한 Proxy 설정을 제한하여 자원 낭비 예방 및 관리의 복잡성을 감소시키며, 중간자 공격 등의 해킹 공격으로부터 시스템 관련 정보가 노출되거나 악용되는 것을 방지하기 위함"
GUIDELINE_THREAT="불필요한 Proxy 설정을 제한하지 않는 경우 공격자가 Proxy 서버를 이용하여 원래 의도되지 않은 방식으로 시스템에 접근하거나 시스템 관련 정보가 유출될 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="불필요한 Proxy 설정을 제한한 경우"
GUIDELINE_CRITERIA_BAD="불필요한 Proxy 설정을 제한하지 않은 경우"
GUIDELINE_REMEDIATION="불필요한 Proxy 설정 존재 여부 점검 및 제한 설정"

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

    # 불필요한 Proxy 설정 점검
    # 가이드라인 기준: server.xml Connector 요소의 proxyName/proxyPort 속성 및
    # AJP Connector(protocol="AJP/1.3") 등 불필요한 Proxy 관련 설정 존재 여부 점검
    # (criteria_bad: 불필요한 Proxy 설정을 제한하지 않은 경우)
    local server_xml_locations=(
        "/etc/tomcat*/server.xml"
        "/var/lib/tomcat*/conf/server.xml"
        "/usr/share/tomcat*/conf/server.xml"
    )

    local proxy_config=""
    local has_proxy=false
    local has_insecure_ajp=false
    local config_found=false

    # XML 주석(<!-- ... -->) 영역을 다중 행 포함 제거하여 활성(주석 외) 설정만 추출한다.
    # (라인 선두 <!-- 만 거르는 방식은 다중 행 주석의 내부 라인을 통과시켜 비활성 AJP를 오탐함)
    strip_xml_comments() {
        awk '{
            line=$0; out=""
            while (length(line)>0) {
                if (incmt) {
                    p=index(line,"-->")
                    if (p==0) { line=""; break }
                    line=substr(line,p+3); incmt=0
                } else {
                    p=index(line,"<!--")
                    if (p==0) { out=out line; line=""; break }
                    out=out substr(line,1,p-1); line=substr(line,p+4); incmt=1
                }
            }
            if (length(out)>0) print out
        }' "$1"
    }

    for xml_pattern in "${server_xml_locations[@]}"; do
        for xml_file in $xml_pattern; do
            if [ -f "${xml_file}" ]; then
                config_found=true
                # proxyName / proxyPort 속성 및 AJP Connector 점검 (다중 행 주석 영역 제외)
                local active_xml
                active_xml=$(strip_xml_comments "${xml_file}" 2>/dev/null || true)
                local found_proxy
                found_proxy=$(printf '%s\n' "${active_xml}" | grep -iE "proxyName|proxyPort|protocol\s*=\s*\"AJP" || true)
                if [ -n "${found_proxy}" ]; then
                    proxy_config="${found_proxy}"
                    has_proxy=true
                    # 활성 AJP Connector에 secretRequired="false"가 설정된 경우는 명백히 안전하지 않음(Ghostcat)
                    if printf '%s\n' "${active_xml}" | grep -iqE "secretRequired\s*=\s*\"false\""; then
                        has_insecure_ajp=true
                    fi
                fi
                break 2
            fi
        done
    done

    command_executed="strip_xml_comments /etc/tomcat*/server.xml | grep -iE 'proxyName|proxyPort|protocol=\"AJP'  (다중 행 주석 제외 후 활성 설정만 점검)"
    command_result="${proxy_config:-No proxyName/proxyPort/AJP Connector configuration found}"

    if [ "${config_found}" = false ]; then
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="Tomcat server.xml을 찾을 수 없습니다. Connector 요소의 proxyName/proxyPort 속성 및 불필요한 AJP Connector 설정 존재 여부를 수동으로 확인하세요."
    elif [ "${has_insecure_ajp}" = true ]; then
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="server.xml에 활성 AJP Connector가 secretRequired=\"false\"로 설정되어 있습니다(Ghostcat 등 위험). 불필요 시 제거하거나 secret을 설정하세요."
    elif [ "${has_proxy}" = true ]; then
        # 활성 Proxy/AJP 설정의 필요성(불필요 여부)은 정적으로 판정할 수 없으므로 수동진단으로 처리한다(Windows WEB-10과 동일).
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="server.xml에 활성 Proxy 관련 설정(proxyName/proxyPort 또는 AJP Connector)이 존재합니다. 해당 설정이 업무상 필요한지, 신뢰된 인터페이스에 한정되고 secret으로 보호되는지 수동으로 확인하세요."
    else
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="불필요한 Proxy 설정(proxyName/proxyPort/AJP Connector)이 발견되지 않았습니다. (보안 권고사항 준수)"
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
