#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-28
# ============================================================================
# [점검 항목 상세]
# @ID          : U-26
# @Category    : UNIX > 2. 파일 및 디렉토리 관리
# @Platform    : RedHat
# @Severity    : 상
# @Title       : /dev에 존재하지 않는 device 파일 점검
# @Description : /dev 디렉터리에 device 파일이 아닌 일반 파일이 존재하는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; LIB_DIR="${SCRIPT_DIR}/../../lib"
source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/metadata_parser.sh"

ITEM_ID="U-26"; ITEM_NAME="/dev에 존재하지 않는 device 파일 점검"; SEVERITY="(상)"
GUIDELINE_PURPOSE="허용한 호스트만 서비스를 사용하게하여 서비스 취약점을 이용한 외부자 공격을 방지하기 위함"
GUIDELINE_THREAT="공격자는 rootkit 설정 파일들을 서버 관리자가 쉽게 발견하지 못하도록 /dev 디렉터리에 device 파일인 것처럼 위장하는 수법을 사용하는 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="/dev 디렉터리에 대한 파일 점검 후 존재하지 않는 device 파일을 제거한 경우"
GUIDELINE_CRITERIA_BAD="/dev 디렉터리에 대한 파일 미점검 또는 존재하지 않는 device 파일을 방치한 경우"
GUIDELINE_REMEDIATION="major, minor number를 가지지 않는 device 파일 제거하도록 설정"

# 전역 변수로 설정하여 main에서 참조 가능하게 함
diagnose() {
    local status="양호"; diagnosis_result="GOOD"
    local inspection_summary="/dev 디렉토리에 device 파일이 아닌 일반 파일이 존재하지 않습니다."
    local command_result=""; local command_executed="find /dev -type f"
    local newline=$'\n'

    # /dev 디렉토리 자체를 신뢰성 있게 열거할 수 있는지 먼저 확인.
    # 권한 부족/탐색 실패로 결과가 비는 경우를 GOOD으로 오판하지 않기 위함.
    if [ ! -d /dev ]; then
        diagnosis_result="MANUAL"; status="수동진단"
        inspection_summary="/dev 디렉터리를 확인할 수 없어 수동 점검이 필요합니다."
        command_result="/dev 디렉터리 없음 또는 접근 불가"
        save_dual_result "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" "${inspection_summary}" "${command_result}" "${command_executed}" "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
        return 0
    fi

    # /dev 디렉토리 내 device 파일이 아닌 일반 파일 탐색.
    # find의 stderr와 종료 코드를 모두 캡처하여 탐색 실패(권한 거부 등)를 식별함.
    local find_err find_rc=0 fake_dev=""
    find_err=$(mktemp 2>/dev/null || echo "/tmp/u26_find_err.$$")
    fake_dev=$(find /dev -type f -not -path '/dev/shm/*' -not -path '/dev/mqueue/*' 2>"$find_err") || find_rc=$?
    local err_content=""
    [ -f "$find_err" ] && err_content=$(cat "$find_err" 2>/dev/null)
    rm -f "$find_err" 2>/dev/null || true

    # 탐색이 실패했거나(권한 거부/오류) 검색 자체가 불완전하면 GOOD으로 단정하지 않고 수동 점검.
    if [ "$find_rc" -ne 0 ] || [ -n "$err_content" ]; then
        diagnosis_result="MANUAL"; status="수동진단"
        inspection_summary="/dev 디렉터리를 신뢰성 있게 열거하지 못해(권한 부족/탐색 오류 가능) 수동 점검이 필요합니다."
        command_result="[find /dev -type f 오류/경고]${newline}${err_content:-탐색 실패(rc=${find_rc})}${newline}부분 결과: [ $(printf '%s' "$fake_dev" | xargs 2>/dev/null) ]"
    elif [ -n "$fake_dev" ]; then
        status="취약"; diagnosis_result="VULNERABLE"
        inspection_summary="/dev 디렉토리에 device 파일이 아닌 일반 파일이 존재합니다."
        command_result="발견된 일반 파일: [ $(printf '%s' "$fake_dev" | xargs 2>/dev/null) ]"
    else
        command_result="/dev 내 특이 파일 없음 (정상 열거 완료)"
    fi

    save_dual_result "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" "${inspection_summary}" "${command_result}" "${command_executed}" "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
}
main() {
    show_diagnosis_start "${ITEM_ID}" "${ITEM_NAME}"
    [ "$EUID" -ne 0 ] && { echo "root 권한이 필요합니다."; exit 1; }
    diagnose
    show_diagnosis_complete "${ITEM_ID}" "${diagnosis_result}"
}
main "$@"
