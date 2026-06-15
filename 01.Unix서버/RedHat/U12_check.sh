#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-04-20
# ============================================================================
# [점검 항목 상세]
# @ID          : U-12
# @Category    : UNIX > 1. 계정 관리
# @Platform    : RedHat
# @Severity    : 하
# @Title       : 세션 종료 시간 설정
# @Description : 사용자 쉘에 대한 환경설정 파일에서 Session Timeout 설정 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/metadata_parser.sh"

ITEM_ID="U-12"
ITEM_NAME="세션 종료 시간 설정"
SEVERITY="하"

# 가이드라인 정보
GUIDELINE_PURPOSE="사용자의 고의 또는 실수로 시스템에 계정이 접속된 상태로 방치됨을 차단하기 위함"
GUIDELINE_THREAT="Sessiontimeout 값이 설정되지 않을 경우, 유휴 시간 내 비인가자가 시스템에 접근하여 불필요한 내부 정보를 노출할 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="Session Timeout이 600초(10분)이하로 설정된 경우"
GUIDELINE_CRITERIA_BAD="Session Timeout이 600초(10분)이하로 설정되지 않은 경우"
GUIDELINE_REMEDIATION="600초(10분)동안 입력이 없는 경우 접속된 Session을 끊도록 설정"

diagnose() {
    local status="양호"
    diagnosis_result="GOOD"
    local inspection_summary="세션 종료 시간이 600초 이하로 적절히 설정되어 있습니다."
    local command_result=""
    local command_executed="grep -iE 'TMOUT' /etc/profile /etc/bashrc /etc/profile.d/*.sh"

    # 1. 실제 데이터 추출: TMOUT 변수 확인 (여러 소스 검사)
    local tmout_val="미설정"
    local all_sources="/etc/profile /etc/bashrc"
    # profile.d 글로브 확장
    for f in /etc/profile.d/*.sh; do
        [ -f "$f" ] && all_sources="$all_sources $f"
    done
    for src in $all_sources; do
        local found=$(grep -iE "^(export\s+)?TMOUT=" "$src" 2>/dev/null | head -1 | sed -E 's/^(export\s+)?TMOUT=//i' | tr -d "[:space:]'\"" | sed -E 's/;.*$//' || true)
        if [ -n "$found" ]; then
            tmout_val="$found"
            break
        fi
    done

    # 2. 판정 로직
    if [ "$tmout_val" = "미설정" ] || ! [[ "$tmout_val" =~ ^[0-9]+$ ]] || [ "$tmout_val" -lt 1 ] || [ "$tmout_val" -gt 600 ]; then
        status="취약"
        diagnosis_result="VULNERABLE"
        inspection_summary="세션 종료 시간이 설정되지 않았거나 값이 숫자가 아니거나 1~600초 범위를 벗어납니다 (0은 자동 종료 비활성화)."
    fi

    # 3. command_result에 실제 TMOUT 설정값 기록
    command_result="설정된 TMOUT 값: [ ${tmout_val} ]"

    save_dual_result \
        "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" \
        "${inspection_summary}" "${command_result}" "${command_executed}" \
        "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" \
        "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
    
    verify_result_saved "${ITEM_ID}"
    return 0
}

main() {
    show_diagnosis_start "${ITEM_ID}" "${ITEM_NAME}"
    [ "$EUID" -ne 0 ] && { echo "root 권한이 필요합니다."; exit 1; }
    diagnose
    show_diagnosis_complete "${ITEM_ID}" "${diagnosis_result}"
    exit 0
}

main "$@"
