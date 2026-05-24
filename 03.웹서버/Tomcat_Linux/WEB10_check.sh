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

    local diagnosis_result="UNKNOWN"
    local status="미진단"
    local inspection_summary=""
    local command_result=""
    local command_executed=""
    local servlet_count=0

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

    local servlet_mappings=""

    for xml_pattern in "${web_xml_locations[@]}"; do
        for xml_file in $xml_pattern; do
            if [ -f "${xml_file}" ]; then
                local found_mapping=$(grep -E "<servlet>|<servlet-mapping>" "${xml_file}" 2>/dev/null | grep -v "^\s*<!--" || true)
                if [ -n "${found_mapping}" ]; then
                    servlet_mappings="${servlet_mappings}"$'\n'"${found_mapping}"
                    servlet_count=$((servlet_count + 1))
                fi
                break 2
            fi
        done
    done

    command_executed="grep -E '<servlet>|<servlet-mapping>' /etc/tomcat*/web.xml 2>/dev/null | grep -v '^\\s*<!--' | head -5"
    command_result="${servlet_mappings:-No servlet mappings found}"

    if [ ${servlet_count} -eq 0 ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="스크립트 매핑이 발견되지 않았습니다 (정적 리소스 전용)."
    elif [ ${servlet_count} -le 5 ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="스크립트 매핑이 ${servlet_count}개 발견되었습니다. 최소한의 매핑만 유지 권장."
    else
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="다수의 스크립트 매핑(${servlet_count}개)이 발견되었습니다. 불필요한 매핑 제거 권장."
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
