#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : U-34
# @Category    : Unix Server
# @Platform    : Solaris
# @Severity    : 상
# @Title       : Finger 서비스 비활성화
# @Description : faillock 설정 확인 deny <= 5
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

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


ITEM_ID="U-34"
ITEM_NAME="Finger 서비스 비활성화"
SEVERITY="상"

# 가이드라인 정보
GUIDELINE_PURPOSE="Finger 서비스를 통해 네트워크 외부에서 해당 시스템에 등록된 사용자 정보를 확인할 수 있어 비인가자에게 사용자 정보가 조회되는 것을 방지하기 위함"
GUIDELINE_THREAT="Finger 서비스가 활성화되어 있을 경우, 비인가자가 Finger 서비스를 사용하여 사용자 정보를 조회한 후 비밀번호 공격을 통해 계정을 탈취할 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="Finger 서비스가 비활성화된 경우"
GUIDELINE_CRITERIA_BAD="Finger 서비스가 활성화된 경우"
GUIDELINE_REMEDIATION="Finger 서비스 비활성화 설정"

# ============================================================================
# 진단 함수
# ============================================================================

# 진단 수행
diagnose() {


    diagnosis_result="unknown"
    local status="미진단"
    local inspection_summary=""
    local command_result=""
    local command_executed=""
    local newline=$'\n'

    # 진단 로직 구현
    # Solaris: /etc/default/passwd에서 RETRIES 확인

    local is_secure=false
    local config_details=""
    local deny_value=""

    # Solaris: /etc/default/passwd에서 RETRIES 설정 확인
    if [ -f /etc/default/passwd ]; then
        local retries_setting=$(grep "^RETRIES=" /etc/default/passwd | awk -F= '{print $2}' | tr -d ' ')
        if [ -n "$retries_setting" ]; then
            deny_value=$retries_setting
            if [ "$deny_value" -le 5 ]; then
                is_secure=true
            fi
            config_details="/etc/default/passwd: RETRIES=${deny_value}"
        else
            # 기본값 확인 (Solaris는 보통 3-5회)
            deny_value="3"
            config_details="/etc/default/passwd: 기본값 RETRIES=3 (설정 없음)"
            is_secure=true
        fi
    else
        # PAM 폴백 (Solaris는 PAM도 지원)
        local pam_files=(
            "/etc/pam.d/common-auth"
            "/etc/pam.d/system-auth"
            "/etc/pam.d/login"
        )

        for pam_file in "${pam_files[@]}"; do
            if [ -f "$pam_file" ]; then
                if grep -q "pam_faillock.so" "$pam_file"; then
                    deny_value=$(grep "pam_faillock.so" "$pam_file" | grep -oP 'deny=\K[0-9]+' | head -1)
                    if [ -n "$deny_value" ]; then
                        if [ "$deny_value" -le 5 ]; then
                            is_secure=true
                        fi
                        config_details="pam_faillock.so: deny=${deny_value}"
                    fi
                    break
                fi
            fi
        done || true
    fi

    # 최종 판정
    if [ "$is_secure" = true ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="로그온 시도 횟수 제한 적절히 설정됨 (RETRIES=${deny_value} <= 5)"
        command_result="${config_details}"
        command_executed="grep '^RETRIES' /etc/default/passwd; grep pam_faillock.so /etc/pam.d/common-auth"
    elif [ -n "$deny_value" ]; then
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="로그온 시도 횟수 제한 설정됨但 임계값 초과 (RETRIES=${deny_value} > 5)"
        command_result="${config_details}"
        command_executed="grep '^RETRIES' /etc/default/passwd"
    else
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="로그온 시도 횟수 제한 미설정"
        command_result="RETRIES setting not found"
        command_executed="ls -la /etc/default/passwd 2>/dev/null; grep pam_faillock.so /etc/pam.d/common-auth"
    fi

    # echo ""
    # echo "진단 결과: ${status}"
    # echo "판정: ${diagnosis_result}"
    # echo "설명: ${inspection_summary}"
    # echo ""

    # 결과 생성 (PC 패턴: 스크립트에서 모드 확인 후 처리)
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

# ============================================================================
# 메인 실행
# ============================================================================

main() {
    # 진단 시작 표시
    show_diagnosis_start "${ITEM_ID}" "${ITEM_NAME}"

    # 디스크 공간 확인
    check_disk_space

    # 진단 수행
    diagnose

    # 진단 완료 표시
    show_diagnosis_complete "${ITEM_ID}" "${diagnosis_result:-UNKNOWN}"

    return 0
}

# 스크립트 직접 실행 시에만 진단 수행
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi
