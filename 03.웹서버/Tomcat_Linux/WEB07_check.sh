#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : WEB-07
# @Category    : Server
# @Platform    : Tomcat_Linux
# @Severity    : 중
# @Title       : 웹 서비스 경로 내 불필요한 파일 제거
# @Description : 웹 서비스 로그 분석 및 관리 설정 여부 점검
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

ITEM_ID="WEB-07"
ITEM_NAME="웹 서비스 경로 내 불필요한 파일 제거"
SEVERITY="중"

GUIDELINE_PURPOSE="웹 서비스 설치 시 기본으로 생성되는 샘플, 매뉴얼 파일 등 서비스에 불필요한 파일을 제거하여 불필요한 공격 대상으로 이용되는 것을 방지하기 위함"
GUIDELINE_THREAT="웹 서비스 설치 시 기본으로 생성되는 파일 및 디렉터리나 백 업, 테스트 파일 등을 제거하지 않은 경우, 비인가자에게 시스템 관련 정보 및 웹 서버 정보가 노출되거나 해킹에 악용될 수 있음"
GUIDELINE_CRITERIA_GOOD="기본으로 생성되는 불필요한 파일 및 디렉터리가 존재하지 않을 경우"
GUIDELINE_CRITERIA_BAD="기본으로 생성되는 불필요한 파일 및 디렉터리가 존재하는 경우"
GUIDELINE_REMEDIATION="불필요한 파일 및 디렉터리를 제거하도록 설정"

diagnose() {
    echo "진단 항목: ${ITEM_ID} - ${ITEM_NAME}"

    local diagnosis_result="UNKNOWN"
    local status="미진단"
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

    # 로그 파일 존재 확인
    local log_files=(
        "/var/log/tomcat*/localhost_access*log.txt"
        "/var/log/tomcat*/catalina.out"
        "/usr/share/tomcat*/logs/*"
    )

    local has_log=false
    local log_info=""

    for log_pattern in "${log_files[@]}"; do
        if ls ${log_pattern} 1> /dev/null 2>&1; then
            has_log=true
            log_count=$(ls ${log_pattern} 2>/dev/null | wc -l)
            log_info="${log_info}"$'\n'"${log_pattern}: ${log_count} files"
        fi
    done

    # 로그 분석 도구 확인 (logrotate, logwatch 등)
    local has_logrotate=false
    local has_analysis_tool=false

    if command -v logrotate >/dev/null 2>&1; then
        has_logrotate=true
    fi

    if command -v logwatch >/dev/null 2>&1 || command -v goaccess >/dev/null 2>&1; then
        has_analysis_tool=true
    fi

    command_executed="ls -la /var/log/tomcat*/*.txt 2>/dev/null | head -5"
    command_result="${log_info:-No logs found}"

    if [ "${has_log}" = true ]; then
        if [ "${has_logrotate}" = true ] || [ "${has_analysis_tool}" = true ]; then
            diagnosis_result="GOOD"
            status="양호"
            inspection_summary="로그 파일이 존재하며 로그 관리 도구(logrotate 또는 logwatch)가 설치되어 있습니다. (보안 권고사항 준수)"
        else
            diagnosis_result="GOOD"
            status="양호"
            inspection_summary="로그 파일이 존재합니다. 로그 분석 도구 도입 권장."
        fi
    else
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="로그 파일이 발견되지 않았습니다. 로그 기록 및 분석 시스템 구축 권장."
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
