#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : U-25
# @Category    : Unix Server
# @Platform    : Debian
# @Severity    : 상
# @Title       : world writable 파일 점검
# @Description : 전체 쓰기 권한 파일 확인
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


ITEM_ID="U-25"
ITEM_NAME="world writable 파일 점검"
SEVERITY="상"

# 가이드라인 정보
GUIDELINE_PURPOSE="worldwritable 파일을 이용한 시스템 접근 및 악의적인 코드 실행을 방지하기 위함"
GUIDELINE_THREAT="시스템 파일과 같은 중요 파일에 world writable이 적용될 경우, 일반 사용자 및 비인가자가 해당 파일을 임의로 수정, 제거할 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="worldwritable 파일이 존재하지 않거나, 존재 시 설정 이유를 인지하고 있는 경우"
GUIDELINE_CRITERIA_BAD="worldwritable 파일이 존재하나 설정 이유를 인지하지 못하고 있는 경우"
GUIDELINE_REMEDIATION="worldwritable 파일 존재 여부를 확인하고 불필요한 경우 제거하도록 설정"

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
    # world-writable 파일 (전체 쓰기 권한) 점검

    local ww_files=""
    local ww_count=0
    local sys_dirs="/ /home /tmp /var /usr /opt /etc /boot"

    # 시스템 주요 디렉터리에서 world-writable 파일 검색 - 실제 명령어 결과 저장
    local raw_files_output=""
    for dir in $sys_dirs; do
        if [ -d "$dir" ]; then
            # 예외 디렉터리(/tmp 등)는 head 절단 이전에 제외해야 비예외 항목이
            # 절단으로 누락되는 false-good을 막을 수 있음. 경계(/|$) 앵커로
            # /tmp_evil, /mnt-backup 같은 유사 경로 오제외 방지.
            local dir_output=$(find "$dir" -perm -2 -type f 2>/dev/null | grep -Ev '^(/tmp|/var/tmp|/var/mail|/dev/shm|/mnt|/media)(/|$)' | head -30 || true)
            if [ -n "$dir_output" ]; then
                raw_files_output="${raw_files_output}${dir_output}"$'\n'
            fi
            while IFS= read -r file; do
                if [ -n "$file" ]; then
                    ((ww_count++)) || true
                    local perms=$(stat -c "%a" "$file" 2>/dev/null)
                    local owner=$(stat -c "%U:%G" "$file" 2>/dev/null)
                    local filetype="file"

                    if [ -d "$file" ]; then
                        filetype="dir"
                    fi

                    ww_files="${ww_files}${file} (${filetype}, 권한: ${perms}, 소유자: ${owner}), "
                fi
            done <<< "$dir_output" || true
        fi
    done || true

    # world-writable 디렉터리 검색 - 실제 명령어 결과 저장
    local ww_dirs=""
    local ww_dir_count=0
    local raw_dirs_output=""

    for dir in $sys_dirs; do
        if [ -d "$dir" ]; then
            # sticky bit 디렉터리(! -perm -1000)와 예외 경로는 head 절단 이전에 제외
            local dir_output=$(find "$dir" -perm -2 -type d ! -perm -1000 2>/dev/null | grep -Ev '^(/tmp|/var/tmp|/var/mail|/dev/shm)$|^(/mnt|/media)(/|$)' | head -20 || true)
            if [ -n "$dir_output" ]; then
                raw_dirs_output="${raw_dirs_output}${dir_output}"$'\n'
            fi
            while IFS= read -r dirpath; do
                if [ -n "$dirpath" ]; then
                    # sticky bit가 설정된 world-writable 디렉터리는 표준 권한 패턴이므로 예외 처리
                    if [ -k "$dirpath" ]; then
                        continue
                    fi
                    ((ww_dir_count++)) || true
                    local perms=$(stat -c "%a" "$dirpath" 2>/dev/null)
                    local owner=$(stat -c "%U:%G" "$dirpath" 2>/dev/null)

                    ww_dirs="${ww_dirs}${dirpath} (권한: ${perms}, 소유자: ${owner}), "
                fi
            done <<< "$dir_output" || true
        fi
    done || true

    # 결과 판정
    if [ "$ww_count" -eq 0 ] && [ "$ww_dir_count" -eq 0 ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="world-writable 파일 및 디렉터리 없음 (예외: /tmp, /var/tmp 등 제외)"
        command_result="[Command: find world-writable files]${newline}${raw_files_output}${newline}${newline}[Command: find world-writable directories]${newline}${raw_dirs_output}"
        command_executed="find / /home /tmp /var /usr /opt /etc /boot -perm -2 -type f 2>/dev/null; find / /home /tmp /var /usr /opt /etc /boot -perm -2 -type d 2>/dev/null"
    else
        diagnosis_result="VULNERABLE"
        status="취약"
        local details=""

        if [ "$ww_count" -gt 0 ]; then
            details="${details}world-writable 파일 ${ww_count}개: ${ww_files%, }. "
        fi

        if [ "$ww_dir_count" -gt 0 ]; then
            details="${details}world-writable 디렉터리 ${ww_dir_count}개: ${ww_dirs%, }. "
        fi

        inspection_summary="취약: ${details}"
        command_result="[Command: find world-writable files]${newline}${raw_files_output}${newline}${newline}[Command: find world-writable directories]${newline}${raw_dirs_output}"
        command_executed="find / /home /tmp /var /usr /opt /etc /boot -perm -2 -type f 2>/dev/null; find / /home /tmp /var /usr /opt /etc /boot -perm -2 -type d 2>/dev/null"
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
