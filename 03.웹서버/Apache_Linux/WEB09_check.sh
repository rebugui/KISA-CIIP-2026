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
# @Platform    : Apache_Linux
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
GUIDELINE_CRITERIA_BAD=""
GUIDELINE_REMEDIATION="웹 서비스 프로세스 구동 시 관리자 권한이 아닌 운영에 필요한 최소한의 권한을 가진 계정으로 구동 설정"

diagnose() {
    echo "진단 항목: ${ITEM_ID} - ${ITEM_NAME}"

    local diagnosis_result="UNKNOWN"
    local status="미진단"
    local inspection_summary=""
    local command_result=""
    local command_executed=""
    local apache_user=""
    local is_root=false

    # Apache 프로세스 확인
    # Process check (Updated for Docker)
    if command -v pgrep >/dev/null && ! pgrep -x "httpd" > /dev/null && ! pgrep -x "apache2" > /dev/null; then
        diagnosis_result="N/A"
        status="N/A"
        inspection_summary="Apache 웹 서버가 실행 중이 아닙니다."
        command_result="Apache process not found"
        command_executed="pgrep -x httpd; pgrep -x apache2"
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

    # Apache 프로세스 실행 사용자 확인 (httpd 또는 apache2)
    # 부모 프로세스(master)는 root로 실행되는 것이 정상임
    # 자식 프로세스(worker)가 root로 실행되면 취약
    local root_child=false
    local child_count=0

    if pgrep -x "httpd" > /dev/null; then
        # head -1은 부모 프로세스(root)이므로 건너뛰고 나머지 확인
        while IFS= read -r user; do
            child_count=$((child_count + 1))
            if [ "$child_count" -gt 1 ] && [ "$user" = "root" ]; then
                root_child=true
                break
            fi
        done < <(ps aux | grep '[h]ttpd' | awk '{print $1}')
    elif pgrep -x "apache2" > /dev/null; then
        while IFS= read -r user; do
            child_count=$((child_count + 1))
            if [ "$child_count" -gt 1 ] && [ "$user" = "root" ]; then
                root_child=true
                break
            fi
        done < <(ps aux | grep '[a]pache2' | awk '{print $1}')
    fi

    command_executed="ps aux | grep -E 'httpd|apache2' | awk '{print \$1}'"
    command_result="$(ps aux | grep -E '[h]ttpd|[a]pache2' | awk '{print $1}' | tr '\n' ' ')"

    if [ $child_count -le 1 ]; then
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="Apache 프로세스 실행 사용자를 확인할 수 없습니다. 수동 확인이 필요합니다."
    elif [ "$root_child" = true ]; then
        diagnosis_result="VULNERABLE"
        status="취약"
        is_root=true
        inspection_summary="Apache 자식 프로세스(worker)가 root 권한으로 구동 중입니다. 보안 권고사항 미준수."
    else
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="Apache 자식 프로세스가 root 이외의 계정으로 구동 중입니다. (보안 권고사항 준수)"
    fi

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
