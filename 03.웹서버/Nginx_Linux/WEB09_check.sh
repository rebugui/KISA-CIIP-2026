#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : WEB-09
# @Category    : Web Server
# @Platform    : Nginx_Linux
# @Severity    : 상
# @Title       : 웹 서비스 프로세스 권한 제한
# @Description : 웹 서비스 프로세스의 권한 제한 설정 여부 점검
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

ITEM_ID="WEB-09"
ITEM_NAME="웹 서비스 프로세스 권한 제한"
SEVERITY="상"

GUIDELINE_PURPOSE="웹 프로세스가 웹 서비스 운영에 필요한 최소한의 권한만을 갖도록 제한함으로써 웹 사이트 방문자가 웹 서비스의 취약점을 이용해 시스템에 대한 어떤 권한도 획득할 수 없도록하여 침해 사고 발생 시 피해 범위 확산을 방지하기 위함"
GUIDELINE_THREAT="웹 프로세스 권한을 제한하지 않은 경우, 웹 사이트 방문자가 웹 서비스의 취약점을 이용하여 시스템 권한을 획득할 수 있으며, 웹 취약점을 통해 접속 권한을 획득한 경우에는 관리자 권한을 획득하여 서버에 접속 후 정보의 변경, 훼손 및 유출될 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="웹 프로세스(웹 서비스)가 관리자 권한이 부여된 계정이 아닌 운영에 필요한 최소한의 권한을 가진 별도의 계정으로 구동되고 있는 경우"
GUIDELINE_CRITERIA_BAD="웹 프로세스(웹 서비스)가 운영에 필요한 최소한의 권한을 가진 별도의 계정이 아닌 관리자 권한이 부여된 계정으로 구동되고 있는 경우"
GUIDELINE_REMEDIATION="웹 서비스 프로세스 구동 시 관리자 권한이 아닌 운영에 필요한 최소한의 권한을 가진 계정으로 구동 설정"

diagnose() {
    echo "진단 항목: ${ITEM_ID} - ${ITEM_NAME}"

    local diagnosis_result="UNKNOWN"
    local status="미진단"
    local inspection_summary=""
    local command_result=""
    local command_executed=""

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

    # Check Nginx worker process user
    # Nginx: master process는 root로 실행되는 것이 정상 (port 80 binding)
    # worker process가 root로 실행되면 취약
    local master_process_user=""
    local nginx_conf_user=""
    local worker_root=false

    # Method 1: Check worker process user (most reliable)
    if command -v ps >/dev/null; then
        command_executed="ps aux | grep 'nginx' | grep -v grep | awk '{print \$1, \$NF}'"
        # worker process가 root로 실행되는지 확인
        while IFS= read -r proc_user proc_cmd; do
            if echo "$proc_cmd" | grep -q "worker process"; then
                if [ "$proc_user" = "root" ]; then
                    worker_root=true
                    break
                fi
            fi
        done < <(ps aux | grep '[n]ginx' | grep -v grep)
        master_process_user=$(ps aux | grep 'nginx: master process' | grep -v grep | awk '{print $1}' | head -1 || true)
    fi

    # Method 2: Check nginx.conf user directive (additional context)
    local nginx_conf_files=(
        "/etc/nginx/nginx.conf"
        "/usr/local/nginx/conf/nginx.conf"
    )

    for conf_file in "${nginx_conf_files[@]}"; do
        if [ -f "${conf_file}" ]; then
            local user_directive=$(grep -E "^\s*user\s+" "${conf_file}" 2>/dev/null | grep -v "^\s*#" | head -1 || true)
            if [ -n "${user_directive}" ]; then
                nginx_conf_user="${user_directive}"
                break
            fi
        fi
    done

    if [ -n "${nginx_conf_user}" ]; then
        command_result="nginx.conf: ${nginx_conf_user}"
    fi

    # Determine result
    if [ "${worker_root}" = true ]; then
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="Nginx 워커 프로세스(worker)가 root 권한으로 실행 중입니다. 보안 권고사항 미준수."
        if [ -n "${nginx_conf_user}" ]; then
            inspection_summary="${inspection_summary} (nginx.conf 설정: ${nginx_conf_user})"
        fi
    elif [ -n "${master_process_user}" ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="Nginx 워커 프로세스가 root 이외의 계정으로 구동 중입니다. (보안 권고사항 준수)"
        if [ -n "${nginx_conf_user}" ]; then
            inspection_summary="${inspection_summary} (nginx.conf 설정: ${nginx_conf_user})"
        fi
    else
        diagnosis_result="UNKNOWN"
        status="미진단"
        inspection_summary="Nginx 프로세스 사용자 확인 실패. 수동 점검이 필요합니다."
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
