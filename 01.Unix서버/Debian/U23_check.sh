#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : U-23
# @Category    : Unix Server
# @Platform    : Debian
# @Severity    : 상
# @Title       : SUID, SGID, Sticky bit 설정 파일 점검
# @Description : 불필요한 SUID/SGID 파일 확인
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


ITEM_ID="U-23"
ITEM_NAME="SUID, SGID, Sticky bit 설정 파일 점검"
SEVERITY="상"

# 가이드라인 정보
GUIDELINE_PURPOSE="불필요한 SUID, SGID, Stickybit 설정 제거로 악의적인 사용자의 권한 상승을 방지하기 위함"
GUIDELINE_THREAT="SUID, SGID, Sticky bit 설정이 적절하지 않을 경우, SUID, SGID, Sticky bit가 설정된 파일로 특정 명령어를 실행하여 root 권한 획득이 가능한 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="주요 실행 파일의 권한에 SUID와 SGID에 대한 설정이 부여되어 있지 않은 경우"
GUIDELINE_CRITERIA_BAD="주요 실행 파일의 권한에 SUID와 SGID에 대한 설정이 부여된 경우"
GUIDELINE_REMEDIATION="불필요한 SUID,SGID 권한 또는 해당 파일 제거하도록 설정 애플리케이션에서 생성한 파일이나 사용자가 임의로 생성한 파일 등 의심스럽거나 특이한 파일에 SUID 권한이 부여된 경우 제거하도록 설정"

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
    # 중요 시스템 설정 파일의 SUID/SGID 및 권한 점검

    local config_dirs="/etc /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin"
    local world_writable_files=""
    local ww_count=0
    local details=""

    # world-writable 파일 검색 (일반 사용자 쓰기 권한) - 실제 명령어 결과 저장
    local raw_find_output=""
    for dir in $config_dirs; do
        if [ -d "$dir" ]; then
            local dir_output=$(find "$dir" -perm -2 -type f 2>/dev/null | head -20 || true)
            if [ -n "$dir_output" ]; then
                raw_find_output="${raw_find_output}${dir_output}"$'\n'
            fi
            while IFS= read -r file; do
                if [ -n "$file" ]; then
                    ((ww_count++)) || true
                    local perms=$(stat -c "%a" "$file" 2>/dev/null)
                    local owner=$(stat -c "%U:%G" "$file" 2>/dev/null)

                    world_writable_files="${world_writable_files}${file} (권한: ${perms}, 소유자: ${owner}), "
                fi
            done <<< "$dir_output" || true
        fi
    done || true

    # 추가: 중요 설정 파일의 권한 확인 - 실제 명령어 결과 저장
    local important_files="/etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/hosts /etc/services /etc/inetd.conf /etc/rsyslog.conf"
    local important_vulnerable=""
    local important_count=0
    local raw_important_output=""

    for file in $important_files; do
        if [ -f "$file" ]; then
            local perms=$(stat -c "%a" "$file" 2>/dev/null)
            local owner=$(stat -c "%U:%G" "$file" 2>/dev/null)
            raw_important_output="${raw_important_output}${file}: ${perms} ${owner}"$'\n'

            # world-writable 확인 (마지막 숫자가 7, 6, 3, 2인 경우)
            local last_char="${perms: -1}"

            if [ "$last_char" = "7" ] || [ "$last_char" = "6" ] || [ "$last_char" = "3" ] || [ "$last_char" = "2" ]; then
                ((important_count++)) || true
                important_vulnerable="${important_vulnerable}${file} (권한: ${perms}), "
            fi
        fi
    done || true

    # 결과 판정
    if [ "$ww_count" -eq 0 ] && [ "$important_count" -eq 0 ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="world-writable 설정 파일 없음, 중요 설정 파일 보안 양호"
        command_result="[Command: find world-writable files]${newline}${raw_find_output}${newline}${newline}[Command: Check important files]${newline}${raw_important_output}"
        command_executed="find /etc /usr/bin /usr/sbin -perm -2 -type f 2>/dev/null; stat -c '%a:%U:%G' /etc/passwd /etc/shadow /etc/group"
    else
        diagnosis_result="VULNERABLE"
        status="취약"
        details=""

        if [ "$ww_count" -gt 0 ]; then
            details="${details}world-writable 파일 ${ww_count}개 발견: ${world_writable_files%, }. "
        fi

        if [ "$important_count" -gt 0 ]; then
            details="${details}중요 설정 파일 취약 ${important_count}개: ${important_vulnerable%, }. "
        fi

        inspection_summary="취약: ${details}"
        command_result="[Command: find world-writable files]${newline}${raw_find_output}${newline}${newline}[Command: Check important files]${newline}${raw_important_output}"
        command_executed="find /etc /usr/bin /usr/sbin -perm -2 -type f 2>/dev/null; stat -c '%a:%U:%G' /etc/passwd /etc/shadow /etc/group"
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
