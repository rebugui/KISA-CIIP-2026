#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : U-63
# @Category    : Unix Server
# @Platform    : AIX
# @Severity    : 중
# @Title       : sudo 명령어 접근 관리
# @Description : sudoers 설정 확인
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


ITEM_ID="U-63"
ITEM_NAME="sudo 명령어 접근 관리"
SEVERITY="중"

# 가이드라인 정보
GUIDELINE_PURPOSE="비인가자가 관리자 권한을 남용하여 시스템 손상, 악성 코드 실행, 민감한 데이터 유출 등의 보안 위협을 방지하기 위함"
GUIDELINE_THREAT="sudo 명령어 접근을 제한하지 않을 경우, 비인가자가 관리자 권한으로 허가되지 않은 명령어를 사용하여 루트 권한 오용, 악성 코드 실행, 데이터 유출 등의 시도를 할 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="/etc/sudoers 파일 소유자가 root이고, 파일 권한이 640인 경우"
GUIDELINE_CRITERIA_BAD="/etc/sudoers 파일 소유자가 root가 아니거나, 파일 권한이 640을 초과하는 경우"
GUIDELINE_REMEDIATION="/etc/sudoers 파일 소유자 및 권한 변경 설정"

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
    # sudo 명령어 접근 관리 확인

    local sudo_installed=false
    local sudoers_issues=false
    local issue_details=""

    # 1) sudo 설치 여부 확인
    if command -v sudo >/dev/null 2>&1; then
        sudo_installed=true
    fi

    if [ "$sudo_installed" = false ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="sudo가 설치되지 않음 (root만 권한 관리)"
        local cmd_check=$(command -v sudo 2>/dev/null || echo "sudo command not found")
        local pkg_check=$(lslpp -L | grep -i sudo 2>/dev/null || echo "sudo packages not found")
        command_result="[Command: command -v sudo]${newline}${cmd_check}${newline}${newline}[Command: lslpp -L | grep sudo]${newline}${pkg_check}"
        command_executed="which sudo"
    else
        # 2) sudoers 파일 확인
        local sudoers_files=("/etc/sudoers" "/etc/sudoers.d/*" "/etc/sudoers.tmp")

        # 2-1) sudoers 파일 권한 확인 (AIX: stat -c 미지원, perl 사용)
        for sudoers_file in /etc/sudoers /etc/sudoers.d/*; do
            if [ -f "$sudoers_file" ]; then
                local perms=$(perl -le 'printf "%04o\n", (stat shift)[2] & 07777' "$sudoers_file" 2>/dev/null || echo "0000")
                local owner=$(perl -le 'print +(getpwuid((stat shift)[4]))[0]' "$sudoers_file" 2>/dev/null || echo "unknown")
                local group=$(perl -le 'print +(getgrgid((stat shift)[5]))[0]' "$sudoers_file" 2>/dev/null || echo "unknown")

                # 640 이내 권한(600, 440, 400 등 포함)만 양호. stat 실패(0000 폴백)는 취약으로 안전 처리
                if [ "$perms" = "0000" ] || [ $(( 8#${perms} & ~(8#640) & 8#7777 )) -ne 0 ]; then
                    sudoers_issues=true
                    issue_details="${issue_details}${sudoers_file} 권한 ${perms} (640 이내 권장), "
                fi

                # 판단 기준은 소유자 root (그룹은 증적용으로만 표기)
                if [ "$owner" != "root" ]; then
                    sudoers_issues=true
                    issue_details="${issue_details}${sudoers_file} 소유자 ${owner}:${group} (root 권장), "
                fi
            fi
        done || true

        # 2-2) sudoers 규칙 확인 (정보성)
        # 판단 기준은 파일 소유자/권한이므로 규칙 내용은 취약 판정에 반영하지 않음
        # (%sudo/%admin ALL=(ALL:ALL) ALL 등 표준 기본 규칙으로 과탐 방지)
        local all_privilege=$(grep -v "^#" /etc/sudoers 2>/dev/null | grep -v "^$" | grep -E "ALL=\(ALL\) ALL|ALL=\(ALL:ALL\) ALL" || true)
        if [ -n "$all_privilege" ]; then
            # root는 제외
            local non_root_all=$(echo "$all_privilege" | grep -vE "^[[:space:]]*(root|%sudo|%admin)[[:space:]]" || true)
            if [ -n "$non_root_all" ]; then
                issue_details="${issue_details}[참고] 광범위한 sudo 권한 규칙: ${non_root_all}, "
            fi
        fi

        # 2-3) 암호 없이 sudo 사용 가능한 규칙 확인 (NOPASSWD, 정보성)
        # U-63 판정 기준은 sudoers 파일 권한/소유자이며 규칙 내용은 취약 트리거가 아님
        local nopasswd_rules=$(grep -v "^#" /etc/sudoers 2>/dev/null | grep -i "NOPASSWD" || true)
        if [ -n "$nopasswd_rules" ]; then
            issue_details="${issue_details}[참고] 암호 없는 sudo 규칙: ${nopasswd_rules}, "
        fi

        # 2-4) sudoers.d 디렉토리 내 파일 확인 (AIX: perl 사용)
        if [ -d /etc/sudoers.d ]; then
            local sudoers_d_files=$(ls /etc/sudoers.d/* 2>/dev/null)
            if [ -n "$sudoers_d_files" ]; then
                for file in $sudoers_d_files; do
                    local file_perms=$(perl -le 'printf "%04o\n", (stat shift)[2] & 07777' "$file" 2>/dev/null || echo "0000")
                    if [ "$file_perms" = "0000" ] || [ $(( 8#${file_perms} & ~(8#640) & 8#7777 )) -ne 0 ]; then
                        sudoers_issues=true
                        issue_details="${issue_details}${file} 권한 ${file_perms}, "
                    fi
                done || true
            fi
        fi

        # 2-5) sudo 로깅 설정 확인
        if ! grep -qE "Defaults.*logfile|Defaults.*log_output" /etc/sudoers 2>/dev/null; then
            # 로깅이 설정되지 않음 (정보성, 취약으로 판단하지 않음)
            issue_details="${issue_details}sudo 로깅 설정 없음, "
        fi

        if [ "$sudoers_issues" = true ]; then
            diagnosis_result="VULNERABLE"
            status="취약"
            inspection_summary="sudoers 설정에 보안 문제 존재: ${issue_details%, }"
            command_result="${issue_details%, }"
            command_executed="ls -la /etc/sudoers /etc/sudoers.d/ 2>/dev/null; grep -E 'ALL.*ALL|NOPASSWD' /etc/sudoers 2>/dev/null"
        else
            diagnosis_result="GOOD"
            status="양호"
            local good_perms=$(perl -le 'printf "%04o\n", (stat shift)[2] & 07777' /etc/sudoers 2>/dev/null || echo "unknown")
            local good_owner=$(perl -le 'print +(getpwuid((stat shift)[4]))[0]' /etc/sudoers 2>/dev/null || echo "unknown")
            inspection_summary="sudoers 설정이 안전하게 구성됨 (권한 ${good_perms}, 소유자 ${good_owner})"
            local grep_sudoers=$(grep -v '^#' /etc/sudoers | grep -v '^$' 2>/dev/null | head -20 || echo "sudoers not readable")
            command_result="[Command: grep -v '^#' /etc/sudoers]${newline}${grep_sudoers}"
            command_executed="stat -c '%a:%U:%G' /etc/sudoers 2>/dev/null"
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
