#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : WEB-17
# @Category    : Server
# @Platform    : Tomcat_Linux
# @Severity    : 중
# @Title       : 웹 서비스 가상 디렉터리 삭제
# @Description : 불필요한 가상 디렉토리 삭제 여부 점검
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

ITEM_ID="WEB-17"
ITEM_NAME="웹 서비스 가상 디렉터리 삭제"
SEVERITY="중"

GUIDELINE_PURPOSE="불필요한 가상 디렉터리를 삭제하여 공격이 가능한 영역을 최소화하고 정보 노출 방지 및 권한 상승 공격 등의 위험을 제거하기 위함"
GUIDELINE_THREAT="불필요한 가상 디렉터리를 삭제하지 않은 경우, 취약한 가상 디렉터리를 통해 시스템 권한 탈취 및 시스템 구조 등의 중요 정보가 노출될 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="불필요한 가상 디렉터리가 존재하지 않는 경우"
GUIDELINE_CRITERIA_BAD="불필요한 가상 디렉터리가 존재하는 경우"
GUIDELINE_REMEDIATION="불필요한 가상 디렉터리 존재 여부 점검 및 삭제하도록 설정"

diagnose() {
    echo "진단 항목: ${ITEM_ID} - ${ITEM_NAME}"

    local diagnosis_result="UNKNOWN"
    local status="미진단"
    local inspection_summary=""
    local command_result=""
    local command_executed=""
    local context_count=0
    local example_contexts=0

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

    local contexts=""

    for xml_pattern in "${server_xml_locations[@]}"; do
        for xml_file in $xml_pattern; do
            if [ -f "${xml_file}" ]; then
                # Context 정의 확인
                local found_context=$(grep "<Context" "${xml_file}" 2>/dev/null | grep -v "^\s*<!--" || true)
                if [ -n "${found_context}" ]; then
                    contexts="${contexts}"$'\n'"${found_context}"
                    context_count=$(echo "${found_context}" | wc -l)

                    # 예제 Context 확인 (examples, docs, manager, host-manager)
                    if echo "${found_context}" | grep -iqE "examples|docs|sample|test"; then
                        example_contexts=$((example_contexts + 1))
                    fi
                fi
                break 2
            fi
        done
    done

    command_executed="grep '<Context' /etc/tomcat*/server.xml 2>/dev/null | grep -v '^\\s*<!--' | head -5"
    command_result="${contexts:-No Context definitions found}"

    if [ ${context_count} -eq 0 ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="가상 디렉토리(Context) 정의가 없습니다. 기본 webapps만 사용 중입니다."
    elif [ ${example_contexts} -gt 0 ]; then
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="${example_contexts}개의 예제/테스트 Context가 발견되었습니다. 불필요한 가상 디렉토리 제거 권장."
    elif [ ${context_count} -le 3 ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="${context_count}개의 Context 정의가 있습니다. 최소한의 가상 디렉토리만 유지 권장."
    else
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="다수의 가상 디렉토리(${context_count}개)가 정의되어 있습니다. 불필요한 Context 제거 권장."
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
