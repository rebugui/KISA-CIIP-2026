#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : WEB-09
# @Category    : Server
# @Platform    : Tomcat_Linux
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

    # Tomcat 프로세스 실행 사용자 확인
    local tomcat_user=""
    if pgrep -f "catalina" > /dev/null; then
        tomcat_user=$(ps aux | grep '[c]atalina' | awk '{print $1}' | head -1 || true)
    elif pgrep -f "tomcat" > /dev/null; then
        tomcat_user=$(ps aux | grep '[t]omcat' | awk '{print $1}' | head -1 || true)
    fi

    command_executed="ps aux | grep '[c]atalina|[t]omcat' | awk '{print \$1}' | head -1"
    command_result="${tomcat_user:-Tomcat process not found}"

    if [ -z "${tomcat_user}" ]; then
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="Tomcat 프로세스 사용자를 확인할 수 없습니다."
    elif [ "${tomcat_user}" = "root" ]; then
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="Tomcat 프로세스가 root 권한으로 구동 중입니다. 보안 권고사항 미준수."
    else
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="Tomcat 프로세스가 ${tomcat_user} 계정으로 구동 중입니다. (보안 권고사항 준수)"
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
