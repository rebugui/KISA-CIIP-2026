#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : WEB-23
# @Category    : Server
# @Platform    : Tomcat_Linux
# @Severity    : 중
# @Title       : LDAP 알고리즘 적절하게 구성
# @Description : LDAP 인증 알고리즘 적절한 구성 여부 점검
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

ITEM_ID="WEB-23"
ITEM_NAME="LDAP 알고리즘 적절하게 구성"
SEVERITY="중"

GUIDELINE_PURPOSE="LDAP 연결 시 안전한 비밀번호 다이제스트 알고리즘을 사용하여 비밀번호 평문 전송 시 발생할 수 있는 스니핑 등의 공격에 대비하기 위함"
GUIDELINE_THREAT="취약한 다이제스트 알고리즘을 사용하는 경우 공격자의 스니핑, 무차별 공격 등을 통해 인증 정보가 노출될 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="LDAP 연결 인증 시 안전한 비밀번호 다이제스트 알고리즘을 사용하는 경우"
GUIDELINE_CRITERIA_BAD="LDAP 연결 인증 시 안전한 비밀번호 다이제스트 알고리즘을 사용하지 않는 경우"
GUIDELINE_REMEDIATION="LDAP 연결 인증 시 SHA-256 이상의 알고리즘을 사용하도록 설정"

diagnose() {
    echo "진단 항목: ${ITEM_ID} - ${ITEM_NAME}"

    local diagnosis_result="UNKNOWN"
    local status="미진단"
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

    local server_xml_locations=(
        "/etc/tomcat*/server.xml"
        "/var/lib/tomcat*/conf/server.xml"
        "/usr/share/tomcat*/conf/server.xml"
    )

    local ldap_config=""

    for xml_pattern in "${server_xml_locations[@]}"; do
        for xml_file in $xml_pattern; do
            if [ -f "${xml_file}" ]; then
                # JNDIRealm 또는 LDAP 설정 확인
                local found_ldap=$(grep -iE "JNDIRealm|LDAP|userPattern|connectionURL" "${xml_file}" 2>/dev/null | grep -v "^\s*<!--" || true)
                if [ -n "${found_ldap}" ]; then
                    ldap_config="${found_ldap}"
                fi
                break 2
            fi
        done
    done

    command_executed="grep -iE 'JNDIRealm|LDAP|userPattern' /etc/tomcat*/server.xml 2>/dev/null | grep -v '^\\s*<!--' | head -5"
    command_result="${ldap_config:-No LDAP configuration found}"

    if [ -n "${ldap_config}" ]; then
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="LDAP 설정이 발견되었습니다. 사용 중인 알고리즘을 수동으로 확인하세요. MD5, SHA-1 사용 시 SHA-256 이상으로 변경 권장."
    else
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="LDAP 설정이 발견되지 않았습니다. (해당 사항 없음)"
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
