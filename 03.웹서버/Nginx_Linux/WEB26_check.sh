#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : WEB-26
# @Category    : Web Server
# @Platform    : Nginx_Linux
# @Severity    : 중
# @Title       : 로그 디렉터리 및 파일 권한 설정
# @Description : 로그 기록 저장 및 검토 설정 여부 점검
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
    local has_access_log=false
    local has_error_log=false
    local all_log_settings=""
    local log_files_checked=""
    local log_dirs_checked=""
    local has_vulnerable_perms=false

    # Process check
    if command -v pgrep >/dev/null; then
    if ! pgrep -x "nginx" > /dev/null; then
        diagnosis_result="N/A"
        status="N/A"
        inspection_summary="Nginx 웹 서버가 실행 중이 아닙니다."
        command_result="Nginx process not found"
        command_executed="pgrep -x nginx"

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

    # Check log file and directory permissions
    local default_log_dirs=("/var/log/nginx" "/usr/local/nginx/logs")
    local log_files=()

    for log_dir in "${default_log_dirs[@]}"; do
        if [ -d "${log_dir}" ]; then
            # Check directory permission
            local dir_perm=$(stat -c "%a" "${log_dir}" 2>/dev/null || echo "")
            if [ -n "${dir_perm}" ]; then
                log_dirs_checked="${log_dirs_checked}"$'\n'"[DIR] ${log_dir}: ${dir_perm}"
                # Check if directory permission is too permissive (not 700 or 750)
                if [ "${dir_perm}" != "700" ] && [ "${dir_perm}" != "750" ]; then
                    has_vulnerable_perms=true
                fi
            fi

            # Check log files in directory
            for log_file in "${log_dir}"/*.log "${log_dir}"/*.log.*; do
                if [ -f "${log_file}" ]; then
                    local file_perm=$(stat -c "%a" "${log_file}" 2>/dev/null || echo "")
                    if [ -n "${file_perm}" ]; then
                        log_files_checked="${log_files_checked}"$'\n'"[FILE] ${log_file}: ${file_perm}"
                        # Check if file permission is too permissive (not 600 or 640)
                        if [ "${file_perm}" != "600" ] && [ "${file_perm}" != "640" ]; then
                            has_vulnerable_perms=true
                        fi
                    fi
                fi
            done
        fi
    done

    command_executed="stat -c '%a' /var/log/nginx/*.log 2>/dev/null; stat -c '%a' /usr/local/nginx/logs/*.log 2>/dev/null; stat -c '%a' /var/log/nginx 2>/dev/null; stat -c '%a' /usr/local/nginx/logs 2>/dev/null"
    command_result="${log_files_checked}${log_dirs_checked:-No log files found}"

    # Determine result based on permission check
    if [ -z "${log_files_checked}" ] && [ -z "${log_dirs_checked}" ]; then
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="로그 파일 또는 디렉터리를 찾을 수 없습니다. Nginx 로그 경로(/var/log/nginx 또는 /usr/local/nginx/logs)를 확인하고 권한을 수동으로 검토하세요. 권장: 파일 600/640, 디렉터리 700/750"
    elif [ "${has_vulnerable_perms}" = true ]; then
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="로그 파일 또는 디렉터리 권한이 기준보다 취약합니다. 로그 파일은 600 또는 640, 로그 디렉터리는 700 또는 750 권한으로 설정하세요. chmod 명령어로 권한을 수정하세요."
    else
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="로그 파일 및 디렉터리 권한이 적절하게 설정되어 있습니다. (보안 권고사항 준수)"
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
