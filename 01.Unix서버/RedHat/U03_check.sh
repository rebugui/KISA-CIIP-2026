#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-04-20
# ============================================================================
# [점검 항목 상세]
# @ID          : U-03
# @Category    : UNIX > 1. 계정 관리
# @Platform    : SOLARIS, LINUX, AIX, HP-UX 등
# @Severity    : (상)
# @Title       : 계정 잠금 임계값 설정
# @Description : 계정 접속 시도 실패 시 계정 잠금 임계값 설정 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/metadata_parser.sh"

ITEM_ID="U-03"
ITEM_NAME="계정 잠금 임계값 설정"
SEVERITY="상"

# 가이드라인 정보
GUIDELINE_PURPOSE="계정 탈취 목적의 무차별 대입 공격 시 해당 계정을 잠금으로써 인증 요청에 응답하는 리소스 낭비를 차단하고 대입 공격으로 인한 비밀번호 노출 공격을 무력화하기 위함"
GUIDELINE_THREAT="계정 잠금 임계값이 설정되어 있지 않을 경우, 비밀번호 탈취 공격(무차별 대입 공격, 사전 대입 공격, 추측 공격 등)의 인증 요청에 대해 설정된 비밀번호가 일치할 때까지 지속적으로 응답하여 해당 계정의 비밀번호가 유출될 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="계정 잠금 임계값이 10회 이하의 값으로 설정된 경우"
GUIDELINE_CRITERIA_BAD="계정 잠금 임계값이 설정되어 있지 않거나, 10회 이하의 값으로 설정되지 않은 경우"
GUIDELINE_REMEDIATION="계정 잠금 임계값을 10회 이하로 설정"

diagnose() {
    local status="양호"
    diagnosis_result="GOOD"
    local inspection_summary="계정 잠금 임계값 설정이 적절히 적용되어 있습니다."
    local command_result=""
    local command_executed="grep -E 'pam_faillock|pam_tally2' /etc/pam.d/system-auth"

    # 1. 실제 데이터 추출 (RedHat 기준)
    local pam_file="/etc/pam.d/system-auth"
    # deny 설정값 추출 (첫 번째 매칭되는 숫자만 추출)
    local deny_val=$(grep -E "pam_faillock.so|pam_tally2.so" $pam_file | grep "deny=" | sed 's/.*deny=\([0-9]*\).*/\1/' | head -n 1 || echo "미설정")

    # 2. 판정 로직 (5회 초과 또는 미설정 시 취약)
    if [ "$deny_val" = "미설정" ] || [ "$deny_val" -gt 10 ]; then
        status="취약"
        diagnosis_result="VULNERABLE"
        inspection_summary="계정 잠금 임계값이 설정되지 않았거나 기준(10회)을 초과했습니다."
    fi

    # 3. command_result에 실제 설정값 기록 (개행 제거)
    command_result="[system-auth] deny=${deny_val}"

    # [중요] U-02와 동일하게 12개의 인자를 모두 전달
    save_dual_result \
        "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" \
        "${inspection_summary}" "${command_result}" "${command_executed}" \
        "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" \
        "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
    
    verify_result_saved "${ITEM_ID}"
    return 0
}

main() {
    show_diagnosis_start "${ITEM_ID}" "${ITEM_NAME}"
    [ "$EUID" -ne 0 ] && { echo "root 권한이 필요합니다."; exit 1; }
    diagnose
    show_diagnosis_complete "${ITEM_ID}" "${diagnosis_result}"
    exit 0
}

main "$@"
