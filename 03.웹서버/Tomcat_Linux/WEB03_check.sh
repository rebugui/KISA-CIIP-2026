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

    local diagnosis_result="MANUAL"
    local status="수동진단"
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

            # 판단기준(가이드): 비밀번호 파일 권한 '600 이하'만 양호.
            # group/other 비트는 모두 0이어야 하며 owner는 최대 rw(6).
            # 640(group read)은 600 초과이므로 취약.
            if [ -n "${file_permissions}" ]; then
                # 선행 특수권한 자리(setuid 등 4자리)를 제거하고 3자리 8진수만 평가
                local perm3="${file_permissions: -3}"
                local owner_digit="${perm3:0:1}"
                local group_digit="${perm3:1:1}"
                local other_digit="${perm3:2:1}"
                if [ "${group_digit}" = "0" ] && [ "${other_digit}" = "0" ] \
                    && [ -n "${owner_digit}" ] && [ "${owner_digit}" -le 6 ] 2>/dev/null; then
                    is_secure=true
                fi
            fi
        else
            # stat 명령어가 없는 경우 ls -l 사용
            file_permissions=$(ls -l "${found_file}" 2>/dev/null | awk '{print $1}' || echo "")
            command_executed="ls -l ${found_file}"

            # 600 이하만 양호: group/other 권한이 전혀 없어야 함.
            # -rw------- (600), -r-------- (400), --------- (000) 등.
            # -rw-r----- (640, group read)은 600 초과이므로 취약.
            if [[ "${file_permissions}" =~ ^-[r-][w-]------- ]]; then
                is_secure=true
            fi
        fi

        command_result="File: ${found_file}, Permissions: ${file_permissions}"
    else
        command_executed="ls -la /etc/tomcat*/tomcat-users.xml /var/lib/tomcat*/conf/tomcat-users.xml 2>/dev/null"
        command_result="tomcat-users.xml file not found"
        diagnosis_result="MANUAL"
        status="수동진단"
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
