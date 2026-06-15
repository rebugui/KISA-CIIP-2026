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
# @Platform    : Debian
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

    # 점검 대상: 존재하는 모든 (x)inetd 설정 파일 — 각 파일이 모두 기준을 충족해야 양호
    local files_to_check=()
    [ -f /etc/inetd.conf ] && files_to_check+=("/etc/inetd.conf")
    [ -f /etc/xinetd.conf ] && files_to_check+=("/etc/xinetd.conf")
    if [ -d /etc/xinetd.d ]; then
        local xf
        for xf in /etc/xinetd.d/*; do
            [ -f "$xf" ] && files_to_check+=("$xf")
        done
    fi

    # Capture command outputs for both files
    local ls_xinetd=$(ls -l /etc/xinetd.conf 2>/dev/null || echo "No /etc/xinetd.conf")
    local ls_inetd=$(ls -l /etc/inetd.conf 2>/dev/null || echo "No /etc/inetd.conf")

    if [ ${#files_to_check[@]} -eq 0 ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="inetd/xinetd 설정 파일 없음 (서비스 미사용)"
        command_result="[Command: ls -l /etc/xinetd.conf]${newline}${ls_xinetd}${newline}${newline}[Command: ls -l /etc/inetd.conf]${newline}${ls_inetd}"
        command_executed="ls -l /etc/inetd.conf /etc/xinetd.conf 2>&1"
    else
        local f file_perms file_owner
        local bad_details=""
        local checked_details=""
        local stat_failed=""

        for f in "${files_to_check[@]}"; do
            file_perms=$(stat -c "%a" "$f" 2>/dev/null || echo "")
            file_owner=$(stat -c "%U:%G" "$f" 2>/dev/null || echo "")
            if [ -z "$file_perms" ] || [ -z "$file_owner" ]; then
                stat_failed="${stat_failed}${f}, "
                continue
            fi
            checked_details="${checked_details}${f} ${file_perms} ${file_owner}; "
            # 소유자 root:root + 600 초과 비트 없음 (400 등 더 강한 권한은 양호)
            if ! { [ "$file_owner" = "root:root" ] && [[ "$file_perms" =~ ^[0-7]{3,4}$ ]] && [ "$(( 8#$file_perms & ~8#600 & 07777 ))" -eq 0 ]; }; then
                bad_details="${bad_details}${f} (권한 ${file_perms}, 소유자 ${file_owner}), "
            fi
        done

        command_result="[Command: ls -l /etc/inetd.conf]${newline}${ls_inetd}${newline}${newline}[Command: ls -l /etc/xinetd.conf]${newline}${ls_xinetd}${newline}${newline}[검사한 파일: 권한/소유자]${newline}${checked_details:-없음}${newline}[stat 실패]${newline}${stat_failed:-없음}"
        command_executed="stat -c '%a %U:%G' /etc/inetd.conf /etc/xinetd.conf /etc/xinetd.d/*"

        if [ -n "$bad_details" ]; then
            diagnosis_result="VULNERABLE"
            status="취약"
            inspection_summary="(x)inetd 설정 파일 보안 설정 부적절 (${bad_details%, })"
        elif [ -n "$stat_failed" ]; then
            diagnosis_result="MANUAL"
            status="수동진단"
            inspection_summary="(x)inetd 설정 파일 권한 확인 실패로 수동 점검 필요 (${stat_failed%, })"
        else
            diagnosis_result="GOOD"
            status="양호"
            inspection_summary="(x)inetd 설정 파일 보안 설정 적절 (${checked_details%; })"
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
