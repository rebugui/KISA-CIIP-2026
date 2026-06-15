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
    local newline=$'\n'
    local env_files=".bashrc .profile .bash_profile .bash_logout .zshrc .zprofile .zshenv .zlogin .zlogout .cshrc .login .logout .tcshrc .kshrc .env .exrc .netrc"
    local vulnerable_files=""; local vulnerable_count=0
    local unparsed_files=""; local unparsed_count=0
    local checked_count=0
    local raw_output=""
    local command_executed="awk -F: '\$3 == 0 || \$3 >= 1000 {print \$1, \$6}' /etc/passwd | while read user home; do find \"\$home\" -maxdepth 1 -name '.*' -type f 2>/dev/null; done | xargs stat -c '%a:%U:%n' 2>/dev/null"

    # /etc/passwd에서 root(UID 0) 및 일반 사용자(UID >= 1000)의 홈 디렉터리 환경변수 파일 점검
    while IFS= read -r user_line; do
        local username=$(echo "$user_line" | cut -d: -f1)
        local uid=$(echo "$user_line" | cut -d: -f3)
        local home_dir=$(echo "$user_line" | cut -d: -f6)

        if [ -d "$home_dir" ] && { [ "$uid" -eq 0 ] || [ "$uid" -ge 1000 ]; } 2>/dev/null; then
            for env_file in $env_files; do
                local file_path="${home_dir}/${env_file}"

                if [ -f "$file_path" ]; then
                    ((checked_count++)) || true
                    local perms=$(stat -c "%a" "$file_path" 2>/dev/null)
                    local owner=$(stat -c "%U" "$file_path" 2>/dev/null)
                    local ls_output=$(ls -ld "$file_path" 2>/dev/null)
                    raw_output="${raw_output}${ls_output}"$'\n'

                    # 권한/소유자 확인 불가 시 양호로 간주하지 않고 확인불가로 집계
                    if [ -z "$perms" ] || [ -z "$owner" ]; then
                        ((unparsed_count++)) || true
                        unparsed_files="${unparsed_files}${file_path}, "
                    else
                        # 그룹 또는 others 쓰기 권한(2,3,6,7) 확인
                        local group_char="${perms: -2:1}"
                        local other_char="${perms: -1}"
                        local write_violation=0
                        case "$group_char" in 2|3|6|7) write_violation=1 ;; esac
                        case "$other_char" in 2|3|6|7) write_violation=1 ;; esac

                        # 소유자가 root 또는 해당 계정이 아니거나, 그룹/others 쓰기 권한이 있는 경우 취약
                        if { [ "$owner" != "$username" ] && [ "$owner" != "root" ]; } || [ "$write_violation" -eq 1 ]; then
                            ((vulnerable_count++)) || true
                            vulnerable_files="${vulnerable_files}${file_path} (권한: ${perms}, 소유자: ${owner}), "
                        fi
                    fi
                fi
            done || true
        fi
    done < /etc/passwd || true

    # 결과 판정
    if [ "$vulnerable_count" -gt 0 ]; then
        status="취약"; diagnosis_result="VULNERABLE"
        inspection_summary="취약한 환경변수 파일 ${vulnerable_count}개 발견: ${vulnerable_files%, }"
        command_result="[Command: find env files]${newline}${raw_output}"
    elif [ "$unparsed_count" -gt 0 ]; then
        status="수동진단"; diagnosis_result="MANUAL"
        inspection_summary="권한/소유자 확인 불가 환경변수 파일 ${unparsed_count}개 존재(수동 확인 필요): ${unparsed_files%, }"
        command_result="[Command: find env files]${newline}${raw_output}"
    elif [ "$checked_count" -eq 0 ]; then
        inspection_summary="사용자 환경변수 파일 없음 또는 모두 안전한 권한으로 설정됨"
        command_result="[Command: find env files]${newline}No environment files found or all checked files are secure"
    else
        inspection_summary="사용자 환경변수 파일 ${checked_count}개 모두 안전한 권한으로 설정됨"
        command_result="[Command: find env files]${newline}${raw_output}"
    fi

    save_dual_result "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" "${inspection_summary}" "${command_result}" "${command_executed}" "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
}
main() { diagnose; }; main "$@"
