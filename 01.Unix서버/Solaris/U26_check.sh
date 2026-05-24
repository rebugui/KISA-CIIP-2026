#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : U-26
# @Category    : Unix Server
# @Platform    : Solaris
# @Severity    : 상
# @Title       : /dev에 존재하지 않는 device 파일 점검
# @Description : device 파일 무결성 확인
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


ITEM_ID="U-26"
ITEM_NAME="/dev에 존재하지 않는 device 파일 점검"
SEVERITY="상"

# 가이드라인 정보
GUIDELINE_PURPOSE="허용한 호스트만 서비스를 사용하게하여 서비스 취약점을 이용한 외부자 공격을 방지하기 위함"
GUIDELINE_THREAT="공격자는 rootkit 설정 파일들을 서버 관리자가 쉽게 발견하지 못하도록 /dev 디렉터리에 device 파일인 것처럼 위장하는 수법을 사용하는 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="/dev 디렉터리에 대한 파일 점검 후 존재하지 않는 device 파일을 제거한 경우"
GUIDELINE_CRITERIA_BAD="/dev 디렉터리에 대한 파일 미점검 또는 존재하지 않는 device 파일을 방치한 경우"
GUIDELINE_REMEDIATION="major, minor number를 가지지 않는 device 파일 제거하도록 설정"

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
    # /dev 디렉터리 내 존재하지 않는 device 파일(장치 파일 무결성) 점검

    local invalid_dev_files=""
    local invalid_count=0
    local valid_count=0

    # Capture raw find output for /dev directory
    local dev_find_output=$(find /dev -maxdepth 1 2>/dev/null | head -100)
    command_result="[Command: find /dev -maxdepth 1]${newline}${dev_find_output}"

    # /dev 디렉터리가 존재하는지 확인
    if [ ! -d "/dev" ]; then
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="/dev 디렉터리 없음"
        local dev_check=$(ls -ld /dev 2>/dev/null || echo "Directory not found")
        command_result="[Command: ls -ld /dev]${newline}${dev_check}"
        command_executed="ls -ld /dev"
    else
        # /dev 내 파일 검색하여 장치 파일 타입 확인
        while IFS= read -r devfile; do
            if [ -e "$devfile" ]; then
                # 파일 타입 확인 (b: block device, c: character device) - Solaris: perl 사용
                local filetype=$(perl -e 'if (-b $ARGV[0]) { print "block special file"; } elsif (-c $ARGV[0]) { print "character special file"; } elsif (-f $ARGV[0]) { print "regular file"; } elsif (-d $ARGV[0]) { print "directory"; }' "$devfile" 2>/dev/null)

                if [[ "$filetype" =~ "block special file" ]] || [[ "$filetype" =~ "character special file" ]]; then
                    ((valid_count++)) || true
                elif [ -f "$devfile" ] || [ -d "$devfile" ]; then
                    # 일반 파일이나 디렉터리인 경우 (장치 파일 아님)
                    ((invalid_count++)) || true
                    local perms=$(perl -e 'if (-e $ARGV[0]) { printf "%04o\n", (stat($ARGV[0]))[2] & 07777; }' "$devfile" 2>/dev/null)
                    local owner=$(perl -e 'if (-e $ARGV[0]) { $uid = (stat($ARGV[0]))[4]; $gid = (stat($ARGV[0]))[5]; $user = getpwuid($uid); $group = getgrgid($gid); print "$user:$group\n"; }' "$devfile" 2>/dev/null)
                    invalid_dev_files="${invalid_dev_files}${devfile} (타입: ${filetype}, 권한: ${perms}, 소유자: ${owner}), "
                fi
            else
                # 심볼릭 링크 등 깨진 파일
                ((invalid_count++)) || true
                invalid_dev_files="${invalid_dev_files}${devfile} (존재하지 않음 또는 깨진 링크), "
            fi
        done < <(find /dev -maxdepth 1 2>/dev/null | head -100) || true

        # 결과 판정
        if [ "$invalid_count" -eq 0 ]; then
            diagnosis_result="GOOD"
            status="양호"
            inspection_summary="/dev 디렉터리 내 모든 파일이 정상적인 장치 파일임 (확인된 장치 파일: ${valid_count}개)"
            local dev_output=$(find /dev -maxdepth 1 -type b -o -type c 2>/dev/null | head -20 || echo "No devices found")
            command_result="[Command: find /dev -maxdepth 1 -type b -o -type c]${newline}${dev_output}"
            command_executed="find /dev -maxdepth 1 -type b -o -type c 2>/dev/null | wc -l"
        else
            diagnosis_result="VULNERABLE"
            status="취약"
            inspection_summary="/dev 디렉터리 내 비정상 파일 ${invalid_count}개 발견: ${invalid_dev_files%, }"
            local dev_output=$(find /dev -maxdepth 1 ! -type b ! -type c 2>/dev/null | head -20 || echo "No invalid devices found")
            command_result="[Command: find /dev -maxdepth 1 ! -type b ! -type c]${newline}${dev_output}"
            command_executed="find /dev -maxdepth 1 ! -type b ! -type c 2>/dev/null"
        fi
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
