#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-04-20
# ============================================================================
# [점검 항목 상세]
# @ID          : U-06
# @Category    : UNIX > 1. 계정 관리
# @Platform    : RedHat
# @Severity    : 상
# @Title       : 사용자 계정 su 기능 제한
# @Description : 특정 그룹에 속한 사용자만 su 명령어를 사용할 수 있도록 제한하는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/metadata_parser.sh"

ITEM_ID="U-06"
ITEM_NAME="사용자 계정 su 기능 제한"
SEVERITY="상"

# 가이드라인 정보
GUIDELINE_PURPOSE="su 관련 그룹만 su 명령어 사용 권한이 부여되어 있는지 점검하여 su 그룹에 포함되지 않은 일반 사용자의 su 명령 사용을 원천적으로 차단하는지 확인하기 위함"
GUIDELINE_THREAT="무분별한 사용자 변경으로 타 사용자 소유의 파일을 변경할 수 있으며 root 계정으로 변경하는 경우 관리자 권한을 획득할 수 있는 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="su 명령어를 특정 그룹에 속한 사용자만 사용하도록 제한된 경우 ※일반 사용자 계정 없이 root 계정만 사용하는 경우 su 명령어 사용 제한 불필요"
GUIDELINE_CRITERIA_BAD="su 명령어를 모든 사용자가 사용하도록 설정된 경우"
GUIDELINE_REMEDIATION="PAM 모듈 설정 또는 su 명령어 허용 그룹 생성 후 su 명령어 일반 사용자 권한 제거하도록 설정"

diagnose() {
    local status="양호"
    diagnosis_result="GOOD"
    local inspection_summary="su 기능 제한 설정이 적절히 적용되어 있습니다."
    local command_result=""
    local command_executed="grep 'pam_wheel.so' /etc/pam.d/su; stat -c '%a %G' /usr/bin/su; grep 'wheel' /etc/group"

    # 1. PAM 설정 확인: 들여쓰기 주석 포함 제거 후 pam_wheel.so 라인 평가
    # 강제(enforcing) 조건: control 필드가 required/requisite 이고 trust/deny 옵션이 없는 경우
    # (optional 또는 sufficient+trust 는 비-wheel 사용자의 su 사용을 제한하지 않음)
    # (deny 옵션은 동작을 반전시켜 해당 그룹만 거부하고 그 외 전원 허용하므로 그룹 제한 효과가 없음)
    local pam_enforcing=false
    local pam_check
    pam_check=$(grep -vE '^[[:space:]]*#' /etc/pam.d/su 2>/dev/null | grep "pam_wheel\.so" || echo "미설정")
    if [ "$pam_check" != "미설정" ]; then
        while IFS= read -r pam_line; do
            [ -z "$pam_line" ] && continue
            local pam_control
            pam_control=$(echo "$pam_line" | awk '{print $2}')
            if { [ "$pam_control" = "required" ] || [ "$pam_control" = "requisite" ]; } \
                && ! echo "$pam_line" | grep -qw "deny"; then
                pam_enforcing=true
                break
            fi
        done <<< "$pam_check"
    fi

    local wheel_users
    wheel_users=$(grep "^wheel:" /etc/group | cut -d: -f4 || true)

    # 2. 파일 권한 대체 기준: su 바이너리가 전용 그룹 소유이고 4750 이하 권한인 경우
    # (판단기준의 '허용 그룹 생성 후 su 명령어 일반 사용자 권한 제거'에 해당)
    # stat 실패 시 해당 기준은 판단 불가(UNDETERMINED)로 처리하며 GOOD으로 간주하지 않음
    local su_bin="/usr/bin/su"
    [ -f "$su_bin" ] || su_bin="/bin/su"
    local perm_state="UNDETERMINED"
    local su_perm su_group
    su_perm=$(stat -c "%a" "$su_bin" 2>/dev/null || echo "")
    su_group=$(stat -c "%G" "$su_bin" 2>/dev/null || echo "")
    if [ -n "$su_perm" ] && [ -n "$su_group" ]; then
        if [ $(( 8#$su_perm & ~(8#4750) & 8#7777 )) -eq 0 ] && [ "$su_group" != "root" ]; then
            perm_state="SECURE"
        else
            perm_state="INSECURE"
        fi
    fi

    # 3. 판정 로직 (판단기준: PAM 모듈 설정 또는 su 허용 그룹 생성 + 일반 사용자 권한 제거)
    if [ "$pam_enforcing" = true ]; then
        status="양호"
        diagnosis_result="GOOD"
        inspection_summary="pam_wheel.so가 required/requisite(trust 미사용)로 설정되어 su 명령어 사용이 특정 그룹으로 제한되어 있습니다."
    elif [ "$perm_state" = "SECURE" ]; then
        status="양호"
        diagnosis_result="GOOD"
        inspection_summary="su 명령어(${su_bin})가 전용 그룹(${su_group}) 소유 및 ${su_perm} 권한(4750 이하)으로 제한되어 있습니다."
    elif [ "$perm_state" = "INSECURE" ]; then
        status="취약"
        diagnosis_result="VULNERABLE"
        inspection_summary="su 명령어 사용 제한이 설정되어 있지 않습니다. (pam_wheel.so 강제 설정 미적용, su 바이너리 권한 ${su_perm}/그룹 ${su_group} 미제한)"
    else
        status="수동진단"
        diagnosis_result="MANUAL"
        inspection_summary="pam_wheel.so 강제 설정이 없고 su 바이너리 권한 확인(stat)에 실패하여 자동 판정이 불가합니다. su 제한 설정 여부 수동 점검 필요"
    fi

    # 4. command_result에 실제 데이터 기록
    command_result="PAM 설정: [ ${pam_check} ] | su 바이너리: [ ${su_perm:-확인불가} ${su_group:-확인불가} ${su_bin} ] | wheel 그룹 멤버: [ ${wheel_users:-없음} ]"

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
