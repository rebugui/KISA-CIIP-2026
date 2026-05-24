#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : WEB-21
# @Category    : Server
# @Platform    : Tomcat_Linux
# @Severity    : 중
# @Title       : HTTP 리디렉션
# @Description : HTTP에서 HTTPS로의 리디렉션 설정 여부 점검
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

ITEM_ID="WEB-21"
ITEM_NAME="HTTP 리디렉션"
SEVERITY="중"

GUIDELINE_PURPOSE="HTTP 차단 및 HTTPS로 Redirection 활성화를 통해 평문으로 전송되는 데이터를 암호화하여 공격자의 데이터 스니 핑에 대비하기 위함"
GUIDELINE_THREAT="HTTP 통신은 암호화 전송이 아닌 평문 전송을 하므로 공격자가 스니핑을 시도할 경우 관리자의 ID, 비밀번호가 노출되어 악의적 사용자가 관리자 계정을 탈취할 수 있는 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="HTTP 접근 시 HTTPSRedirection이 활성화된 경우"
GUIDELINE_CRITERIA_BAD="HTTP 접근 시 HTTPSRedirection이 비활성화된 경우"
GUIDELINE_REMEDIATION="HTTP Redirection 활성화 설정"

diagnose() {
    echo "진단 항목: ${ITEM_ID} - ${ITEM_NAME}"

    local diagnosis_result="UNKNOWN"
    local status="미진단"
    local inspection_summary=""
    local command_result=""
    local command_executed=""
    local has_redirect=false

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

    local redirect_config=""

    for xml_pattern in "${web_xml_locations[@]}"; do
        for xml_file in $xml_pattern; do
            if [ -f "${xml_file}" ]; then
                # security-constraint 및 transport-guarantee 확인
                local found_redirect=$(grep -E "security-constraint|transport-guarantee|CONFIDENTIAL" "${xml_file}" 2>/dev/null | grep -v "^\s*<!--" || true)
                if [ -n "${found_redirect}" ]; then
                    redirect_config="${found_redirect}"
                    if echo "${found_redirect}" | grep -q "CONFIDENTIAL"; then
                        has_redirect=true
                    fi
                fi
                break 2
            fi
        done
    done

    command_executed="grep -E 'security-constraint|transport-guarantee|CONFIDENTIAL' /etc/tomcat*/web.xml 2>/dev/null | grep -v '^\\s*<!--' | head -5"
    command_result="${redirect_config:-No security-constraint found}"

    if [ "${has_redirect}" = true ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="HTTP to HTTPS 리디렉션 설정이 되어 있습니다. (보안 권고사항 준수)"
    else
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="HTTP 리디렉션 설정을 수동으로 확인하세요. web.xml에서 security-constraint와 transport-guarantee=CONFIDENTIAL 설정 권장."
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
