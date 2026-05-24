#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : WEB-01
# @Category    : Server
# @Platform    : Tomcat_Linux
# @Severity    : 상
# @Title       : Default 관리자 계정 명 변경
# @Description : 웹서비스 설치 시 기본적으로 설정된 관리자 계정의 변경 후 사용 여부 점검
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

ITEM_ID="WEB-01"
ITEM_NAME="Default 관리자 계정 명 변경"
SEVERITY="상"

GUIDELINE_PURPOSE="기본 관리자 계정 명과 같은 알려진 계정 명을 유추하기 어려운 계정 명으로 변경 후 사용하여 공격자에 의한 추측 공격 및 무단 접근 등을 방지하고 보안을 강화하기 위함"
GUIDELINE_THREAT="기본 관리자 계정 명을 변경하지 않고 사용할 경우, 공격자에 의한 계정 및 비밀번호 추측 공격이 가능하고, 이를 통해 불법적인 접근, 데이터 유출, 시스템 장애 등의 보안 사고가 발생할 수 있는 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="관리자 페이지를 사용하지 않거나, 계정 명이 기본 계정 명으로 설정되어 있지 않은 경우"
GUIDELINE_CRITERIA_BAD="계정 명이 기본 계정 명으로 설정되어 있거나, 추측하기 쉬운 문자 조합으로 이루어진 계정 명을 사용하는 경우"
GUIDELINE_REMEDIATION="기본 관리자 계정 명을 추측하기 어려운 계정 명으로 설정"

diagnose() {
    echo "진단 항목: ${ITEM_ID} - ${ITEM_NAME}"

    local diagnosis_result="UNKNOWN"
    local status="미진단"
    local inspection_summary=""
    local command_result=""
    local command_executed=""
    local has_default_account=false

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

    # tomcat-users.xml 위치 찾기
    local tomcat_users_locations=(
        "/etc/tomcat*/tomcat-users.xml"
        "/var/lib/tomcat*/conf/tomcat-users.xml"
        "/usr/share/tomcat*/conf/tomcat-users.xml"
    )

    local user_entries=""

    for xml_pattern in "${tomcat_users_locations[@]}"; do
        for xml_file in $xml_pattern; do
            if [ -f "${xml_file}" ]; then
                # 기본 계정명(tomcat, admin) 확인
                local default_users=$(grep -E 'username="(tomcat|admin)' "${xml_file}" 2>/dev/null | grep -v "^\s*<!--" || true)
                if [ -n "${default_users}" ]; then
                    user_entries="${default_users}"
                    has_default_account=true
                fi
                break 2
            fi
        done
    done

    command_executed="grep -E 'username=\"(tomcat|admin)\"' /etc/tomcat*/tomcat-users.xml 2>/dev/null | grep -v '^\\s*<!--' | head -3"
    command_result="${user_entries:-No default accounts found}"

    if [ "${has_default_account}" = true ]; then
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="기본 관리자 계정명(tomcat, admin)이 사용 중입니다. 추측하기 어려운 계정명으로 변경 권장."
    else
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="기본 관리자 계정명이 사용되고 있지 않습니다. (보안 권고사항 준수)"
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
