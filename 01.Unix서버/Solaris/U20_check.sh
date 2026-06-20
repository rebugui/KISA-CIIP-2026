#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : U-20
# @Category    : Unix Server
# @Platform    : Solaris
# @Severity    : 상
# @Title       : /etc/(x)inetd.conf 파일 소유자 및 권한 설정
# @Description : root:root 600 확인
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


ITEM_ID="U-20"
ITEM_NAME="/etc/(x)inetd.conf 파일 소유자 및 권한 설정"
SEVERITY="상"

# 가이드라인 정보
GUIDELINE_PURPOSE="/etc/(x)inetd.conf 파일을 관리자만 제어하여 비인가자들의 임의적인 파일 변조를 방지하기 위함"
GUIDELINE_THREAT="/etc/(x)inetd.conf 파일에 소유자 외 쓰기 권한이 부여된 경우, 일반 사용자 권한으로 해당 파일에 등록된 서비스를 변조하거나 악의적인 프로그램(서비스)을 등록할 수 있는 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="/etc/(x)inetd.conf 파일의 소유자가 root이고, 권한이 600 이하인 경우"
GUIDELINE_CRITERIA_BAD="/etc/(x)inetd.conf 파일의 소유자가 root가 아니거나, 권한이 600 이하가 아닌 경우"
GUIDELINE_REMEDIATION="/etc/(x)inetd.conf 파일 소유자 및 권한 변경 설정"

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
    # /etc/(x)inetd.conf 파일 소유자 및 권한 설정 확인 (600, root:root)

    local is_secure=true
    local details=""
    local found_any=false
    local checked_files=""
    local needs_manual=false

    # 존재하는 모든 설정 파일 점검 (inetd.conf와 xinetd.conf 공존 시 둘 다 평가)
    local ls_output=$(ls -l /etc/inetd.conf /etc/xinetd.conf 2>&1)
    local stat_output=""

    local conf_file
    for conf_file in /etc/inetd.conf /etc/xinetd.conf; do
        [ -f "$conf_file" ] || continue
        found_any=true
        checked_files="${checked_files:+${checked_files} }${conf_file}"
        local file_stat=$(perl -e '@s=stat(shift); printf "%04o %s:%s\n", $s[2] & 07777, getpwuid($s[4]), getgrgid($s[5])' "$conf_file" 2>/dev/null)
        stat_output="${stat_output:+${stat_output}${newline}}${conf_file}: ${file_stat}"
        # 파일 권한/소유자 확인 (Solaris: perl stat 사용, GNU stat -c 미지원)
        local file_perms=$(perl -e 'if (-e $ARGV[0]) { printf "%04o\n", (stat($ARGV[0]))[2] & 07777; }' "$conf_file" 2>/dev/null)
        local file_owner=$(perl -e 'if (-e $ARGV[0]) { $uid = (stat($ARGV[0]))[4]; $gid = (stat($ARGV[0]))[5]; $user = getpwuid($uid); $group = getgrgid($gid); print "$user:$group\n"; }' "$conf_file" 2>/dev/null)
        local file_owner_user="${file_owner%%:*}"

        # 권한/소유자 정보 취득 실패 시 수동진단 플래그 설정
        if [ -z "$file_perms" ] || [ -z "$file_owner_user" ]; then
            needs_manual=true
            is_secure=false
            details="${details:+${details}, }파일: $conf_file, 권한: ${file_perms:-확인불가}, 소유자: ${file_owner:-확인불가} (정보취득실패)"
        # 소유자 및 권한 확인 (판단기준: 소유자가 root, 권한이 600 이하)
        # 600 이하 = 600 초과 권한 비트(group/other 접근, 소유자 실행 등)가 없어야 양호
        elif [[ "$file_perms" =~ ^[0-7]{3,4}$ ]] && [ "$file_owner_user" = "root" ] \
            && [ "$(( 8#$file_perms & ~8#600 & 07777 ))" -eq 0 ]; then
            details="${details:+${details}, }파일: $conf_file, 권한: $file_perms, 소유자: $file_owner"
        else
            is_secure=false
            details="${details:+${details}, }파일: $conf_file, 권한: ${file_perms:-확인불가}, 소유자: ${file_owner:-확인불가} (부적절)"
        fi
    done

    # 파일 존재 확인
    if [ "$found_any" = false ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="inetd/xinetd 설정 파일 없음 (서비스 미사용)"
        command_result="[Command: ls -l /etc/inetd.conf /etc/xinetd.conf]${newline}${ls_output}"
        command_executed="ls -l /etc/inetd.conf /etc/xinetd.conf 2>&1"
    else
        # 파일 권한/소유자 확인 (Solaris: perl stat 사용, GNU stat -c 미지원)
        stat_output=$(perl -e 'if (-e $ARGV[0]) { @s = stat($ARGV[0]); $user = getpwuid($s[4]); $group = getgrgid($s[5]); printf "%04o %s:%s\n", $s[2] & 07777, $user, $group; }' "$target_file" 2>/dev/null)
        local file_perms=$(perl -e 'if (-e $ARGV[0]) { printf "%04o\n", (stat($ARGV[0]))[2] & 07777; }' "$target_file" 2>/dev/null)
        local file_owner=$(perl -e 'if (-e $ARGV[0]) { $uid = (stat($ARGV[0]))[4]; $gid = (stat($ARGV[0]))[5]; $user = getpwuid($uid); $group = getgrgid($gid); print "$user:$group\n"; }' "$target_file" 2>/dev/null)
        local file_owner_user="${file_owner%%:*}"
        details="파일: $target_file, 권한: $file_perms, 소유자: $file_owner"

        # 소유자 및 권한 확인 (판단기준: 소유자가 root, 권한이 600 이하)
        # 600 이하 = 600 초과 권한 비트(group/other 접근, 소유자 실행 등)가 없어야 양호
        if [[ "$file_perms" =~ ^[0-7]{3,4}$ ]] && [ "$file_owner_user" = "root" ] \
            && [ "$(( 8#$file_perms & ~8#600 & 07777 ))" -eq 0 ]; then
            is_secure=true
        fi

        # 권한/소유자 정보 취득 실패 시 수동진단 (취약 오탐 방지)
        if [ -z "$file_perms" ] || [ -z "$file_owner_user" ]; then
            diagnosis_result="MANUAL"
            status="수동진단"
            inspection_summary="inetd.conf 권한/소유자 정보 취득 실패 - 수동 확인 필요 ($details)"
            command_result="[Command: ls -l /etc/inetd.conf /etc/xinetd.conf]${newline}${ls_output}${newline}${newline}[Command: perl stat]${newline}${stat_output}"
            command_executed="ls -l /etc/inetd.conf /etc/xinetd.conf; perl -e 'printf \"%04o %s:%s\", (stat)[2] & 07777, getpwuid((stat)[4]), getgrgid((stat)[5])' $target_file"
        # 최종 판정
        elif [ "$is_secure" = true ]; then
            diagnosis_result="GOOD"
            status="양호"
            inspection_summary="inetd.conf 보안 설정 적절 ($details)"
            command_result="[Command: ls -l /etc/inetd.conf /etc/xinetd.conf]${newline}${ls_output}${newline}${newline}[Command: perl stat]${newline}${stat_output}"
            command_executed="ls -l /etc/inetd.conf /etc/xinetd.conf; perl -e 'printf \"%04o %s:%s\", (stat)[2] & 07777, getpwuid((stat)[4]), getgrgid((stat)[5])' $target_file"
        else
            diagnosis_result="VULNERABLE"
            status="취약"
            inspection_summary="inetd.conf 보안 설정 부적절 ($details)"
            command_result="[Command: ls -l /etc/inetd.conf /etc/xinetd.conf]${newline}${ls_output}${newline}${newline}[Command: perl stat]${newline}${stat_output}"
            command_executed="ls -l /etc/inetd.conf /etc/xinetd.conf; perl -e 'printf \"%04o %s:%s\", (stat)[2] & 07777, getpwuid((stat)[4]), getgrgid((stat)[5])' $target_file"
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
