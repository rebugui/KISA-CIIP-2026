#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : WEB-26
# @Category    : Server
# @Platform    : Tomcat
# @Severity    : 상
# @Title       : 로그디렉터리및파일권한설정
# @Description : 로그 디렉터리 및 파일에 대한 적절한 권한 설정 여부 점검
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

ITEM_ID="WEB-26"
ITEM_NAME="로그 디렉터리 및 파일 권한 설정"
SEVERITY="중"

GUIDELINE_PURPOSE="로그 파일에 공격자에게 유용한 정보가 들어 있을 수 있으므로 권한 관리를 통해 비인가자에 의한 정보 유출, 로그 파일의 훼손 및 변조를 방지하기 위함"
GUIDELINE_THREAT="로그 디렉터리 및 파일에 적절한 권한이 설정되어 있지 않은 경우, 비인가자가 로그 파일에 접근할 수 있으므로 사용자 및 시스템 정보 유출, 로그 파일 조작 등의 공격 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="로그 디렉터리 및 파일에 일반 사용자의 접근 권한이 없는 경우"
GUIDELINE_CRITERIA_BAD="로그 디렉터리 및 파일에 일반 사용자의 접근 권한이 있는 경우"
GUIDELINE_REMEDIATION="로그 디렉터리 및 파일에 일반 사용자 접근 권한 제거 설정"

diagnose() {
    echo "진단 항목: ${ITEM_ID} - ${ITEM_NAME}"

    local diagnosis_result="UNKNOWN"
    local status="미진단"
    local inspection_summary=""
    local command_result=""
    local command_executed=""
    local insecure_logs=0

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

    local log_locations=(
        "/var/log/tomcat*"
        "/usr/share/tomcat*/logs"
        "/opt/tomcat/logs"
    )

    local log_info=""

    for log_pattern in "${log_locations[@]}"; do
        for log_dir in $log_pattern; do
            if [ -d "${log_dir}" ]; then
                # 로그 파일 권한 확인
                local found_logs=$(find "${log_dir}" -type f -name "*.log*" -perm /002 2>/dev/null || true)
                if [ -n "${found_logs}" ]; then
                    log_info="${log_info}"$'\n'"${found_logs}"
                    insecure_logs=$((insecure_logs + 1))
                fi

                # 디렉토리 권한 확인
                local dir_perm=$(stat -c "%a" "${log_dir}" 2>/dev/null || echo "000")
                log_info="${log_info}"$'\n'"${log_dir}: ${dir_perm}"
            fi
        done
    done

    command_executed="find /var/log/tomcat* /usr/share/tomcat*/logs -type f -name '*.log*' -perm /002 2>/dev/null | head -5"
    command_result="${log_info:-No log directories found}"

    if [ ${insecure_logs} -gt 0 ]; then
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="${insecure_logs}개의 로그 파일에 other 쓰기 권한이 있습니다. 권한을 640 이하로 변경 권장."
    elif [ -n "${log_info}" ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="로그 파일 권한이 적절하게 설정되어 있습니다. (보안 권고사항 준수)"
    else
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="로그 디렉터리를 수동으로 확인하세요. 로그 파일 권한이 640 이하인지 확인하세요."
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
