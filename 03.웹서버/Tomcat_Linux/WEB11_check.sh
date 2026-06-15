#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : WEB-11
# @Category    : Server
# @Platform    : Tomcat_Linux
# @Severity    : 중
# @Title       : 웹 서비스 경로 설정
# @Description : 웹 서비스 경로(appBase/docBase) 분리 설정 여부 점검
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

ITEM_ID="WEB-11"
ITEM_NAME="웹 서비스 경로 설정"
SEVERITY="중"

GUIDELINE_PURPOSE="웹 서비스 영역 내 불필요한 경로를 분리해 웹 서비스의 침해가 시스템 영역으로 확장될 가능성을 최소화하기 위함"
GUIDELINE_THREAT="웹 서비스 경로를 기타 업무와 영역이 분리되지 않은 경로로 설정하거나, 불필요한 경로가 존재할 경우 외부에서 시스템 중요 파일이나 기능에 비인가 접근이 발생할 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="웹 서버 경로를 기타 업무와 영역이 분리된 경로로 설정 및 불필요한 경로가 존재하지 않는 경우"
GUIDELINE_CRITERIA_BAD="웹 서버 경로를 기타 업무와 영역이 분리되지 않은 경로로 설정하거나 불필요한 경로가 있는 경우"
GUIDELINE_REMEDIATION="웹 서버의 경로를 별도의 경로로 변경 및 불필요한 경로 제거 설정"

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

    # 웹 서비스 경로(appBase/docBase) 분리 점검
    # 가이드라인 기준: server.xml Host의 appBase 및 Context의 docBase가 기타 업무와
    # 영역이 분리된 별도 경로로 설정되었는지 점검
    # (criteria_bad: 웹 서버 경로를 기타 업무와 영역이 분리되지 않은 경로로 설정)
    # 기본값(appBase="webapps", docBase 미지정/기본)은 정책적 분리 여부를 자동 판단할 수
    # 없으므로 MANUAL 처리. 절대 경로로 분리된 경우에만 GOOD으로 판단.
    local server_xml_locations=(
        "/etc/tomcat*/server.xml"
        "/var/lib/tomcat*/conf/server.xml"
        "/usr/share/tomcat*/conf/server.xml"
    )

    local path_config=""
    local config_found=false
    local has_default_path=false
    local has_separated_path=false

    for xml_pattern in "${server_xml_locations[@]}"; do
        for xml_file in $xml_pattern; do
            if [ -f "${xml_file}" ]; then
                config_found=true
                local found_paths=$(grep -iE "appBase\s*=|docBase\s*=" "${xml_file}" 2>/dev/null | grep -v "^\s*<!--" || true)
                if [ -n "${found_paths}" ]; then
                    path_config="${found_paths}"
                    # 기본 경로(webapps 상대 경로) 사용 여부
                    if echo "${found_paths}" | grep -qiE 'appBase\s*=\s*"webapps"'; then
                        has_default_path=true
                    fi
                    # 절대 경로(/로 시작)로 분리된 docBase/appBase 존재 여부
                    if echo "${found_paths}" | grep -qiE '(appBase|docBase)\s*=\s*"/'; then
                        has_separated_path=true
                    fi
                fi
                break 2
            fi
        done
    done

    command_executed="grep -iE 'appBase\\s*=|docBase\\s*=' /etc/tomcat*/server.xml 2>/dev/null | grep -v '^\\s*<!--' | head -5"
    command_result="${path_config:-No appBase/docBase configuration found}"

    if [ "${config_found}" = false ]; then
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="Tomcat server.xml을 찾을 수 없습니다. Host appBase 및 Context docBase가 기타 업무 영역과 분리된 별도 경로로 설정되었는지 수동으로 확인하세요."
    elif [ "${has_separated_path}" = true ] && [ "${has_default_path}" = false ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="appBase/docBase가 별도의 절대 경로로 분리되어 설정되어 있습니다. (보안 권고사항 준수)"
    else
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="appBase/docBase가 기본 경로(webapps)를 사용하거나 분리 여부를 자동 판단할 수 없습니다. 웹 서버 경로가 기타 업무 영역과 분리된 별도 경로로 설정되었는지 수동으로 확인하세요."
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
