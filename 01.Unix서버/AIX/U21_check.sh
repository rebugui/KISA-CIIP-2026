#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : U-21
# @Category    : Unix Server
# @Platform    : AIX
# @Severity    : 상
# @Title       : /etc/(r)syslog.conf 파일 소유자 및 권한 설정
# @Description : root:root 644 확인
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


ITEM_ID="U-21"
ITEM_NAME="/etc/(r)syslog.conf 파일 소유자 및 권한 설정"
SEVERITY="상"

# 가이드라인 정보
GUIDELINE_PURPOSE="/etc/(r)syslog.conf 파일의 권한 적절성을 점검하여, 비인가자의 임의적인 /etc/(r)syslog.conf 파일 변조를 방지하기 위함"
GUIDELINE_THREAT="/etc/(r)syslog.conf 파일의 설정 내용을 참조하여 로그의 저장 위치가 노출되며 로그를 기록하지 않도록 설정하거나 대량의 로그를 기록하게하여 시스템과 부하를 유도할 수 있는 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="/etc/(r)syslog.conf 파일의 소유자가 root(또는 bin, sys)이고, 권한이 640 이하인 경우"
GUIDELINE_CRITERIA_BAD="/etc/(r)syslog.conf 파일의 소유자가 root(또는 bin, sys)가 아니거나, 권한이 640 이하가 아닌 경우"
GUIDELINE_REMEDIATION="/etc/(r)syslog.conf 파일 소유자 및 권한 변경 설정"

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
    # /etc/(r)syslog.conf 파일 소유자 및 권한 설정 확인 (644, root:root)

    local target_file=""
    local is_secure=false
    local details=""

    # 대체 파일 확인 (rsyslog.conf 우선, 없으면 syslog.conf)
    if [ -f "/etc/rsyslog.conf" ]; then
        target_file="/etc/rsyslog.conf"
    elif [ -f "/etc/syslog.conf" ]; then
        target_file="/etc/syslog.conf"
    fi

    # 파일 존재 확인
    if [ -z "$target_file" ] || [ ! -f "$target_file" ]; then
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="syslog 설정 파일 없음"
        local ls_output=$(ls -l "$target_file" 2>/dev/null || echo "File not found")
        command_result="[Command: ls -l $target_file]${newline}${ls_output}"
        command_executed="ls -l /etc/rsyslog.conf /etc/syslog.conf 2>&1"
    else
        # 파일 권한 확인 (AIX uses ls -l for stat info)
        local file_perms=$(ls -ld "$target_file" 2>/dev/null | awk '{print $1}' | cut -c2-10 | sed 's/rwx/7/g; s/rw-/6/g; s/r-x/5/g; s/r--/4/g; s/-wx/3/g; s/-w-/2/g; s/--x/1/g; s/---/0/g')
        local file_owner=$(ls -ld "$target_file" 2>/dev/null | awk '{print $3":"$4}')

        # 소유자 확인 (가이드라인 판단기준: 소유자가 root(또는 bin, sys) - 그룹은 기준에 없음)
        # AIX 기본 root:system도 소유자 root이므로 양호
        local file_owner_user="${file_owner%%:*}"
        local is_valid_owner=false
        case "$file_owner_user" in
            root|bin|sys) is_valid_owner=true ;;
        esac

        # 권한 확인 (비트 검사: 640 초과 권한 비트가 없어야 양호 - 622 등 group/other 쓰기 차단)
        if [ "$is_valid_owner" = true ] && [[ "$file_perms" =~ ^[0-7]{3,4}$ ]] && [ "$(( 8#$file_perms & ~8#640 & 07777 ))" -eq 0 ]; then
            is_secure=true
            details="파일: $target_file, 권한: $file_perms, 소유자: $file_owner"
        else
            details="파일: $target_file, 권한: $file_perms, 소유자: $file_owner"
        fi

        # 최종 판정
        if [ "$is_secure" = true ]; then
            diagnosis_result="GOOD"
            status="양호"
            inspection_summary="syslog.conf 보안 설정 적절 ($details)"
            command_result="$details"
            command_executed="ls -ld $target_file"
        else
            diagnosis_result="VULNERABLE"
            status="취약"
            inspection_summary="syslog.conf 보안 설정 부적절 ($details)"
            command_result="$details"
            command_executed="ls -ld $target_file"
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
