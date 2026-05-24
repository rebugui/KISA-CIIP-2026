#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : WEB-03
# @Category    : Server
# @Platform    : Tomcat_Linux
# @Severity    : 상
# @Title       : 비밀번호 파일 권한 관리
# @Description : 비밀번호 파일에 대해 적절한 접근 권한 설정 여부 점검
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

ITEM_ID="WEB-03"
ITEM_NAME="비밀번호 파일 권한 관리"
SEVERITY="상"

GUIDELINE_PURPOSE="비밀번호 파일의 접근 권한을 적절하게 설정하여 비인가자가 비밀번호 파일에 무단 접근 및 유출 등을 방지하기 위함"
GUIDELINE_THREAT="비밀번호 파일의 권한을 적절하게 설정하지 않은 경우, 비인가자에게 비밀번호 정보가 노출될 수 있고 웹 서버에 접속하는 등의 침해 사고가 발생할 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="비밀번호 파일에 권한이 600 이하로 설정된 경우"
GUIDELINE_CRITERIA_BAD="비밀번호 파일에 권한이 600 초과로 설정된 경우"
GUIDELINE_REMEDIATION="비밀번호 파일 권한 600 이하로 설정"

diagnose() {
    echo "진단 항목: ${ITEM_ID} - ${ITEM_NAME}"

    local diagnosis_result="UNKNOWN"
    local status="미진단"
    local inspection_summary=""
    local command_result=""
    local command_executed=""
    local file_permissions=""
    local is_secure=false

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

    local found_file=""

    for xml_pattern in "${tomcat_users_locations[@]}"; do
        for xml_file in $xml_pattern; do
            if [ -f "${xml_file}" ]; then
                found_file="${xml_file}"
                break 2
            fi
        done
    done

    if [ -n "${found_file}" ]; then
        # 파일 권한 확인 (숫자 형태)
        if command -v stat >/dev/null 2>&1; then
            file_permissions=$(stat -c "%a" "${found_file}" 2>/dev/null || echo "")
            command_executed="stat -c '%a' ${found_file}"

            # 권한 확인: 600 또는 400이면 양호
            if [ "${file_permissions}" = "600" ] || [ "${file_permissions}" = "400" ]; then
                is_secure=true
            elif [ "${file_permissions}" = "640" ]; then
                # 640도 허용 (group에 읽기 권한만 있는 경우)
                is_secure=true
            fi
        else
            # stat 명령어가 없는 경우 ls -l 사용
            file_permissions=$(ls -l "${found_file}" 2>/dev/null | awk '{print $1}' || echo "")
            command_executed="ls -l ${found_file}"

            # -rw------- (600) 또는 -r-------- (400) 또는 -rw-r----- (640) 확인
            if [[ "${file_permissions}" == "-rw-------" ]] || [[ "${file_permissions}" == "-r--------" ]] || [[ "${file_permissions}" == "-rw-r-----" ]]; then
                is_secure=true
            fi
        fi

        command_result="File: ${found_file}, Permissions: ${file_permissions}"
    else
        command_executed="ls -la /etc/tomcat*/tomcat-users.xml /var/lib/tomcat*/conf/tomcat-users.xml 2>/dev/null"
        command_result="tomcat-users.xml file not found"
        diagnosis_result="UNKNOWN"
        status="파일없음"
        inspection_summary="tomcat-users.xml 파일을 찾을 수 없습니다."

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

    if [ "${is_secure}" = true ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="비밀번호 파일 권한이 ${file_permissions}으로 설정되어 있습니다. (보안 권고사항 준수)"
    else
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="비밀번호 파일 권한이 ${file_permissions}입니다. 600 이하로 설정 권장. (chmod 600 ${found_file})"
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
