#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : WEB-24
# @Category    : Server
# @Platform    : Tomcat_Linux
# @Severity    : 중
# @Title       : 별도의 업로드 경로 사용 및 권한 설정
# @Description : 별도의 업로드 경로 사용 및 권한 설정 여부 점검
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

ITEM_ID="WEB-24"
ITEM_NAME="별도의 업로드 경로 사용 및 권한 설정"
SEVERITY="중"

GUIDELINE_PURPOSE="웹 서버 루트 디렉터리 내 업로드 경로가 아닌 별도의 디렉터리에서 파일을 업로드할 수 있도록하여 루트 디렉터리 내 악의적인 파일 업로드 및 실행을 방지하기 위함"
GUIDELINE_THREAT="웹 서버 내 별도의 파일 업로드 경로 사용 및 적절한 권한 설정을 하지 않을 경우, 악의적인 목적을 가진 파일을 업로드하여 시스템 침투, 중요 정보 유출 및 변조 등의 침해 사고의 가능성이 있음"
GUIDELINE_CRITERIA_GOOD="별도의 업로드 경로를 사용하고 일반 사용자의 접근 권한이 부여되지 않은 경우"
GUIDELINE_CRITERIA_BAD="별도의 업로드 경로를 사용하지 않거나, 일반 사용자의 접근 권한이 부여된 경우"
GUIDELINE_REMEDIATION="기본 경로가 아닌 별도의 업로드 경로를 지정하고, 해당 경로에 대한 일반 사용자의 접근 권한을 제한하도록 설정"

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

    local webapp_dirs=(
        "/var/lib/tomcat*/webapps"
        "/usr/share/tomcat*/webapps"
        "/opt/tomcat/webapps"
    )

    local upload_info=""

    for dir_pattern in "${webapp_dirs[@]}"; do
        for webapp_dir in $dir_pattern; do
            if [ -d "${webapp_dir}" ]; then
                # uploads, upload, files 등 업로드 디렉토리 확인
                local found_upload=$(find "${webapp_dir}" -type d -iname "*upload*" 2>/dev/null || true)
                if [ -n "${found_upload}" ]; then
                    upload_info="${upload_info}"$'\n'"${found_upload}"
                fi
            fi
        done
    done

    command_executed="find /var/lib/tomcat*/webapps /usr/share/tomcat*/webapps -type d -iname '*upload*' 2>/dev/null | head -5"
    command_result="${upload_info:-No upload directories found}"

    if [ -n "${upload_info}" ]; then
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="업로드 디렉토리가 발견되었습니다. 별도의 업로드 경로 분리 사용 여부 및 일반 사용자 접근 권한 제한 여부를 수동으로 확인하세요."
    else
        # 업로드 디렉터리 부재는 경로 분리/권한 충족을 증명하지 못함.
        # 업로드 서블릿이 *upload* 이외의 경로(예: /var/data/files, /opt/uploads)를
        # 사용할 수 있으므로 GOOD으로 단정할 수 없음 → MANUAL 처리.
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="*upload* 이름의 업로드 디렉토리가 발견되지 않았습니다. 업로드 디렉터리 부재만으로는 별도 경로 분리 및 접근 권한 제한 충족 여부를 확인할 수 없습니다. 애플리케이션의 실제 업로드 경로(server.xml/context.xml/web.xml 설정 및 비표준 경로 포함)와 권한을 수동으로 확인하세요."
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
