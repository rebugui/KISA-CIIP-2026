#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-18
# ============================================================================
# [점검 항목 상세]
# @ID          : U-06
# @Category    : Unix Server
# @Platform    : Debian
# @Severity    : 상
# @Title       : 사용자 계정 su 기능 제한
# @Description : su 명령어를 특정 그룹에 속한 사용자만 사용할 수 있도록 제한되어 있는지 점검
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

ITEM_ID="U-06"
ITEM_NAME="사용자 계정 su 기능 제한"
SEVERITY="상"

# 가이드라인 정보
GUIDELINE_PURPOSE="su 관련 그룹만 su 명령어 사용 권한이 부여되어 있는지 점검하여 su 그룹에 포함되지 않은 일반 사용자의 su 명령 사용을 원천적으로 차단하는지 확인하기 위함"
GUIDELINE_THREAT="무분별한 사용자 변경으로 타 사용자 소유의 파일을 변경할 수 있으며 root 계정으로 변경하는 경우 관리자 권한을 획득할 수 있는 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="su 명령어를 특정 그룹에 속한 사용자만 사용하도록 제한된 경우 ※일반 사용자 계정 없이 root 계정만 사용하는 경우 su 명령어 사용 제한 불필요"
GUIDELINE_CRITERIA_BAD="su 명령어를 모든 사용자가 사용하도록 설정된 경우"
GUIDELINE_REMEDIATION="PAM 모듈 설정 또는 su 명령어 허용 그룹 생성 후 su 명령어 일반 사용자 권한 제거하도록 설정"

# ============================================================================
# 진단 함수
# ============================================================================

diagnose() {
    diagnosis_result="unknown"
    local status="미진단"
    local inspection_summary=""
    local command_result=""
    local command_executed=""
    local newline=$'\n'

    # 진단 로직 구현
    # Debian: /etc/pam.d/su 파일 설정 확인 (pam_wheel.so)
    
    local pam_file="/etc/pam.d/su"
    local su_bin="/usr/bin/su" # or /bin/su
    if [ ! -f "$su_bin" ]; then su_bin="/bin/su"; fi

    local pam_enforcing=false
    local check_type=""
    local pam_output=""
    local wheel_group_output=""
    local su_perm_output=""
    local details=""

    # 1. PAM 설정 확인 (Primary Check)
    # 강제(enforcing) 조건: control 필드가 required/requisite 이고 trust 옵션이 없는
    # pam_wheel.so 라인 (optional/sufficient 또는 trust 사용 시 비-wheel 사용자 제한 효과 없음)
    if [ -f "$pam_file" ]; then
        pam_output=$(grep -vE '^[[:space:]]*#' "$pam_file" | grep "pam_wheel\.so" || true)

        if [ -n "$pam_output" ]; then
            while IFS= read -r pam_line; do
                [ -z "$pam_line" ] && continue
                local pam_control
                pam_control=$(echo "$pam_line" | awk '{print $2}')
                if { [ "$pam_control" = "required" ] || [ "$pam_control" = "requisite" ]; } \
                    && ! echo "$pam_line" | grep -qw "trust" \
                    && ! echo "$pam_line" | grep -qw "deny"; then
                    # deny 옵션은 동작을 반전시켜(해당 그룹만 거부, 그 외 전원 허용)
                    # wheel 그룹 제한 효과가 없으므로 강제 설정으로 인정하지 않음
                    pam_enforcing=true
                    check_type="PAM"
                    details="pam_wheel.so 강제 설정(required/requisite, trust/deny 미사용) 확인됨"
                    break
                fi
            done <<< "$pam_output"
        fi
    fi

    # 2. 파일 권한 점검 (대체 기준: 전용 그룹 소유 + 4750 이하 권한)
    # stat 실패 시 해당 기준은 판단 불가(UNDETERMINED)로 처리하며 GOOD으로 간주하지 않음
    local perm_state="UNDETERMINED"
    local su_stat su_perm su_group
    su_stat=$(ls -l "$su_bin" 2>/dev/null || echo "확인 실패")
    su_perm=$(stat -c "%a" "$su_bin" 2>/dev/null || echo "")
    su_group=$(stat -c "%G" "$su_bin" 2>/dev/null || echo "")

    su_perm_output="[File: $su_bin]${newline}${su_stat}"

    if [ -n "$su_perm" ] && [ -n "$su_group" ]; then
        if [ $(( 8#$su_perm & ~(8#4750) & 8#7777 )) -eq 0 ] && [ "$su_group" != "root" ]; then
            perm_state="SECURE"
        else
            perm_state="INSECURE"
        fi
    fi
    
    # 3. Wheel Group Check
    if getent group wheel >/dev/null 2>&1; then
        wheel_group_output="[Group: wheel]${newline}$(getent group wheel)"
    else
        wheel_group_output="[Group: wheel]${newline}Group not found"
    fi

    # Construct Raw Output
    command_result="[File: $pam_file]${newline}$(grep "pam_wheel.so" "$pam_file" 2>/dev/null || echo "[pam_wheel.so not configured]")${newline}${newline}${su_perm_output}${newline}${newline}${wheel_group_output}"
    command_executed="grep pam_wheel.so $pam_file; ls -l $su_bin; getent group wheel"

    # 최종 판정 (판단기준: PAM 모듈 설정 또는 su 허용 그룹 생성 + 일반 사용자 권한 제거)
    if [ "$pam_enforcing" = true ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="su 명령어가 특정 그룹(wheel)으로 제한되고 있음 ($check_type: $details)"
    elif [ "$perm_state" = "SECURE" ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="su 명령어(${su_bin})가 전용 그룹(${su_group}) 소유 및 ${su_perm} 권한(4750 이하)으로 제한되고 있음 (File Permission)"
    elif [ "$perm_state" = "INSECURE" ]; then
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="su 명령어 사용 제한이 설정되지 않음 (pam_wheel.so 강제 설정 미적용, su 바이너리 권한 ${su_perm}/그룹 ${su_group} 미제한)"
    else
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="pam_wheel.so 강제 설정이 없고 su 바이너리 권한 확인(stat)에 실패하여 자동 판정이 불가함. su 제한 설정 여부 수동 점검 필요"
    fi

    # 결과 저장
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

    verify_result_saved "${ITEM_ID}"

    return 0
}

# ============================================================================
# 메인 실행
# ============================================================================

main() {
    show_diagnosis_start "${ITEM_ID}" "${ITEM_NAME}"
    check_disk_space
    diagnose
    show_diagnosis_complete "${ITEM_ID}" "${diagnosis_result:-UNKNOWN}"
    return 0
}

if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi
