#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : U-24
# @Category    : Unix Server
# @Platform    : Solaris
# @Severity    : 상
# @Title       : 사용자, 시스템 환경변수 파일 소유자 및 권한 설정
# @Description : .bashrc, .profile 등 권한 확인
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


ITEM_ID="U-24"
ITEM_NAME="사용자, 시스템 환경변수 파일 소유자 및 권한 설정"
SEVERITY="상"

# 가이드라인 정보
GUIDELINE_PURPOSE="비인가자의 환경 변수 조작으로 인한 보안 위험이 존재함"
GUIDELINE_THREAT="홈 디렉터리 내의 사용자 파일 및 사용자별 시스템 시작 파일 등과 같은 환경 변수 파일의 접근 권한 설정이 적절하지 않을 경우, 비인가자가 환경 변수 파일을 변조하여 정상 사용 중인 사용자의 서비스가 제한될 수 있는 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="홈 디렉터리 환경 변수 파일 소유자가 root 또는 해당 계정으로 지정되어 있고, 홈 디렉터리 환경 변수 파일에 root 계정과 소유자만 쓰기 권한이 부여된 경우"
GUIDELINE_CRITERIA_BAD="소유자불일치또는others쓰기권한있음"
GUIDELINE_REMEDIATION="환경 변수 파일의 일반 사용자 쓰기 권한 제거하도록 설정"

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
    # 사용자 환경변수 파일(.bashrc, .profile, .bash_profile, .bash_logout, etc.) 권한 점검

    local vulnerable_files=""
    local vulnerable_count=0
    local checked_count=0
    local env_files=".bashrc .profile .bash_profile .bash_logout .zshrc .zprofile .zshenv .zlogin .zlogout .cshrc .login .logout .tcshrc .kshrc .profile .env .exrc .netrc"

    # /etc/passwd에서 일반 사용자(UID >= 100)의 홈 디렉터리 확인 (Solaris: UID < 100은 시스템 계정) - 실제 명령어 결과 저장
    local raw_output=""
    while IFS= read -r user_line; do
        local username=$(echo "$user_line" | cut -d: -f1)
        local uid=$(echo "$user_line" | cut -d: -f3)
        local home_dir=$(echo "$user_line" | cut -d: -f6)

        # 홈 디렉터리가 존재하고, UID가 100 이상인 일반 사용자 확인 (Solaris)
        if [ -d "$home_dir" ] && [ "$uid" -ge 100 ] 2>/dev/null; then
            # 환경변수 파일 권한 확인
            for env_file in $env_files; do
                local file_path="${home_dir}/${env_file}"

                if [ -f "$file_path" ]; then
                    ((checked_count++)) || true
                    local perms=$(perl -e 'if (-f $ARGV[0]) { printf "%04o\n", (stat($ARGV[0]))[2] & 07777; }' "$file_path" 2>/dev/null)
                    local owner=$(perl -e 'if (-f $ARGV[0]) { $uid = (stat($ARGV[0]))[4]; $user = getpwuid($uid); print "$user\n"; }' "$file_path" 2>/dev/null)
                    local ls_output=$(ls -ld "$file_path" 2>/dev/null)
                    raw_output="${raw_output}${ls_output}"$'\n'

                    # 취약한 권한 확인: others에 읽기 또는 쓰기 권한이 있는 경우
                    local last_char="${perms: -1}"

                    if [ -n "$perms" ]; then
                        # others에 쓰기 권한이 있거나(2,3,6,7), 소유자가 해당 사용자가 아닌 경우
                        if [ "$owner" != "$username" ] || [ "$last_char" = "2" ] || [ "$last_char" = "3" ] || [ "$last_char" = "6" ] || [ "$last_char" = "7" ]; then
                            ((vulnerable_count++)) || true
                            vulnerable_files="${vulnerable_files}${file_path} (권한: ${perms}, 소유자: ${owner}), "
                        fi
                    fi
                fi
            done || true
        fi
    done < /etc/passwd || true

    # 결과 판정
    if [ "$vulnerable_count" -eq 0 ]; then
        if [ "$checked_count" -eq 0 ]; then
            diagnosis_result="GOOD"
            status="양호"
            inspection_summary="사용자 환경변수 파일 없음 또는 모두 안전한 권한으로 설정됨"
            command_result="[Command: find env files]${newline}No environment files found or all checked files are secure"
            command_executed="awk -F: '\$3 >= 100 {print \$1, \$6}' /etc/passwd | while read user home; do find \"\$home\" -maxdepth 1 -name '.*' -type f 2>/dev/null; done | xargs perl -e 'for $f (@ARGV) { if (-f $f) { printf \"%04o:%s:%s\n\", (stat($f))[2] & 07777, (getpwuid((stat($f))[4]))[0], $f; } }' 2>/dev/null"
        else
            diagnosis_result="GOOD"
            status="양호"
            inspection_summary="사용자 환경변수 파일 ${checked_count}개 모두 안전한 권한으로 설정됨"
            command_result="[Command: find env files]${newline}${raw_output}"
            command_executed="awk -F: '\$3 >= 100 {print \$1, \$6}' /etc/passwd | while read user home; do find \"\$home\" -maxdepth 1 -name '.*' -type f 2>/dev/null; done | xargs perl -e 'for $f (@ARGV) { if (-f $f) { printf \"%04o:%s:%s\n\", (stat($f))[2] & 07777, (getpwuid((stat($f))[4]))[0], $f; } }' 2>/dev/null"
        fi
    else
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="취약한 환경변수 파일 ${vulnerable_count}개 발견: ${vulnerable_files%, }"
        command_result="[Command: find env files]${newline}${raw_output}"
        command_executed="awk -F: '\$3 >= 100 {print \$1, \$6}' /etc/passwd | while read user home; do find \"\$home\" -maxdepth 1 -name '.*' -type f 2>/dev/null; done | xargs perl -e 'for $f (@ARGV) { if (-f $f) { printf \"%04o:%s:%s\n\", (stat($f))[2] & 07777, (getpwuid((stat($f))[4]))[0], $f; } }' 2>/dev/null"
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
