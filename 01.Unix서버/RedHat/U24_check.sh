#!/bin/bash
# ============================================================================
# @ID          : U-24
# @Title       : 사용자, 시스템 환경변수 파일 소유자 및 권한 설정
# ============================================================================

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; LIB_DIR="${SCRIPT_DIR}/../../lib"
source "${LIB_DIR}/common.sh"; source "${LIB_DIR}/result_manager.sh"; source "${LIB_DIR}/output_mode.sh"; source "${LIB_DIR}/metadata_parser.sh"

ITEM_ID="U-24"; ITEM_NAME="사용자, 시스템 환경변수 파일 소유자 및 권한 설정"; SEVERITY="상"
GUIDELINE_PURPOSE="비인가자의 환경 변수 조작으로 인한 보안 위험이 존재함"
GUIDELINE_THREAT="홈 디렉터리 내의 사용자 파일 및 사용자별 시스템 시작 파일 등과 같은 환경 변수 파일의 접근 권한 설정이 적절하지 않을 경우, 비인가자가 환경 변수 파일을 변조하여 정상 사용 중인 사용자의 서비스가 제한될 수 있는 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="홈 디렉터리 환경 변수 파일 소유자가 root 또는 해당 계정으로 지정되어 있고, 홈 디렉터리 환경 변수 파일에 root 계정과 소유자만 쓰기 권한이 부여된 경우"
GUIDELINE_CRITERIA_BAD="소유자불일치또는others쓰기권한있음"
GUIDELINE_REMEDIATION="환경 변수 파일의 일반 사용자 쓰기 권한 제거하도록 설정"

diagnose() {
    local status="양호"; diagnosis_result="GOOD"
    local inspection_summary="환경변수 파일의 소유자 및 권한 설정이 적절합니다."
    local command_result=""
    local check_files=("/etc/profile" "/etc/bashrc" "$HOME/.bash_profile" "$HOME/.bashrc" "$HOME/.profile")
    local vulnerable=""
    local cmd_output=""

    # Build actual command output
    for f in "${check_files[@]}"; do
        if [ -f "$f" ]; then
            cmd_output+="$(stat -c "%a %U %G %n" "$f")"$'\n'
        fi
    done
    local command_executed="stat -c '%a:%U:%n' /etc/profile /etc/bashrc \$HOME/.bash_profile \$HOME/.bashrc \$HOME/.profile"

    for f in "${check_files[@]}"; do
        if [ -f "$f" ]; then
            local perm=$(stat -c "%a" "$f")
            if [ "${perm:2:1}" -gt 4 ]; then # Other write or read/write check
                vulnerable+="$f "
            fi
        fi
    done

    if [ -n "$vulnerable" ]; then
        status="취약"; diagnosis_result="VULNERABLE"
        inspection_summary="환경변수 파일 중 타인 쓰기 권한이 허용된 파일이 존재합니다."
        command_result="취약 파일: [ $vulnerable ]"
    else
        command_result="환경변수 파일 권한 양호"
    fi

    save_dual_result "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" "${inspection_summary}" "${command_result}" "${command_executed}" "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
}
main() { diagnose; }; main "$@"
