#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : WEB-02
# @Category    : Server
# @Platform    : Tomcat_Linux
# @Severity    : 상
# @Title       : 취약한 비밀번호 사용 제한
# @Description : 관리자 계정의 취약한 비밀번호 설정 여부 점검
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

ITEM_ID="WEB-02"
ITEM_NAME="취약한 비밀번호 사용 제한"
SEVERITY="상"

GUIDELINE_PURPOSE="관리자 계정의 비밀번호가 복잡 도 기준에 맞게 적용되어 있는지 점검하여, 비인가자에 의한 비밀번호 유추 공격 및 관리자 권한 탈취 등을 방지하기 위함"
GUIDELINE_THREAT="관리자 계정의 비밀번호를 취약하게 설정하여 사용하는 경우, 비인가자의 비밀번호 유추 공격으로 관리자 권한 탈취 및 시스템 침입 등의 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="관리자 비밀번호가 암호화되어 있거나, 유추하기 어려운 비밀번호로 설정된 경우"
GUIDELINE_CRITERIA_BAD="관리자 비밀번호가 암호화되어 있지 않거나, 유추하기 쉬운 비밀번호로 설정된 경우"
GUIDELINE_REMEDIATION="복잡 도 기준에 맞는 추측하기 어려운 비밀번호 설정"

diagnose() {
    echo "진단 항목: ${ITEM_ID} - ${ITEM_NAME}"

    local diagnosis_result="MANUAL"
    local status="수동점검"
    local inspection_summary=""
    local command_result=""
    local command_executed=""

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

    # tomcat-users.xml 위치 확인
    local tomcat_users_locations=(
        "/etc/tomcat*/tomcat-users.xml"
        "/var/lib/tomcat*/conf/tomcat-users.xml"
        "/usr/share/tomcat*/conf/tomcat-users.xml"
    )

    local config_found=false
    local xml_file=""

    for xml_pattern in "${tomcat_users_locations[@]}"; do
        for xml_file in $xml_pattern; do
            if [ -f "${xml_file}" ]; then
                config_found=true
                break 2
            fi
        done
    done

    if [ "${config_found}" = true ]; then
        command_executed="cat ${xml_file}"
        command_result="Configuration file found at: ${xml_file}"

        inspection_summary="Tomcat은 비밀번호를 암호화된 형태로 저장하며 자동으로 복잡도를 확인할 수 없습니다. "
        inspection_summary+="수동으로 tomcat-users.xml 파일(${xml_file})을 확인하여 다음 사항을 점검하세요:\\n"
        inspection_summary+="1. 비밀번호가 SHA-256 이상으로 해시되어 있는지 확인\\n"
        inspection_summary+="2. 영문 대소문자, 숫자, 특수문자가 2종류 이상 조합된 8자 이상인지 확인\\n"
        inspection_summary+="3. 계정명과 동일하거나 유사한 비밀번호 사용 금지\\n"
        inspection_summary+="4. 연속적인 문자나 숫자(1234, abcd 등) 사용 금지\\n"
        inspection_summary+="5. 추측하기 쉬운 정보(전화번호, 생일 등) 사용 금지"
    else
        command_executed="ls /etc/tomcat*/tomcat-users.xml /var/lib/tomcat*/conf/tomcat-users.xml 2>/dev/null"
        command_result="No tomcat-users.xml file found"

        inspection_summary="tomcat-users.xml 파일을 찾을 수 없습니다. Tomcat 구성을 확인하세요."
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
