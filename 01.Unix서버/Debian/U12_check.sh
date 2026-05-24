#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : U-12
# @Category    : Unix Server
# @Platform    : Debian
# @Severity    : 하
# @Title       : 세션 종료 시간 설정
# @Description : TMOUT 설정 확인 (/etc/profile, /etc/bash.bashrc, /etc/profile.d/)
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


ITEM_ID="U-12"
ITEM_NAME="세션 종료 시간 설정"
SEVERITY="하"

# 가이드라인 정보
GUIDELINE_PURPOSE="사용자의 고의 또는 실수로 시스템에 계정이 접속된 상태로 방치됨을 차단하기 위함"
GUIDELINE_THREAT="Sessiontimeout 값이 설정되지 않을 경우, 유휴 시간 내 비인가자가 시스템에 접근하여 불필요한 내부 정보를 노출할 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="Session Timeout이 600초(10분)이하로 설정된 경우"
GUIDELINE_CRITERIA_BAD="Session Timeout이 600초(10분)이하로 설정되지 않은 경우"
GUIDELINE_REMEDIATION="600초(10분)동안 입력이 없는 경우 접속된 Session을 끊도록 설정"

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
    # 세션 종료시간(TMOUT) 설정 확인
    # GOOD: TMOUT이 600초(10분) 이하로 설정된 경우
    # VULNERABLE: TMOUT이 설정되지 않았거나 600초를 초과하는 경우

    local tmout_value=""
    local raw_output=""

    # 설정 파일에서 TMOUT 값 추출 (/etc/profile, /etc/bash.bashrc, /etc/profile.d/)
    for cfg_file in /etc/profile /etc/bash.bashrc; do
        if [ -f "$cfg_file" ]; then
            local file_tmout=$(grep -E "^\s*(export\s+)?TMOUT=" "$cfg_file" 2>/dev/null | tail -1 | sed -E 's/.*TMOUT=([0-9]+).*/\1/' || echo "")
            if [ -n "$file_tmout" ]; then
                tmout_value="$file_tmout"
                raw_output="${raw_output}[${cfg_file}] TMOUT=${file_tmout}${newline}"
            fi
        fi
    done

    # /etc/profile.d/ 스크립트 확인
    if [ -d /etc/profile.d ]; then
        for pfile in /etc/profile.d/*.sh; do
            [ -f "$pfile" ] || continue
            local file_tmout=$(grep -E "^\s*(export\s+)?TMOUT=" "$pfile" 2>/dev/null | tail -1 | sed -E 's/.*TMOUT=([0-9]+).*/\1/' || echo "")
            if [ -n "$file_tmout" ]; then
                tmout_value="$file_tmout"
                raw_output="${raw_output}[${pfile}] TMOUT=${file_tmout}${newline}"
            fi
        done 2>/dev/null || true
    fi

    # 현재 환경변수 TMOUT도 확인 (우선순위 높음)
    if [ -n "${TMOUT:-}" ]; then
        tmout_value="${TMOUT}"
        raw_output="${raw_output}[환경변수] TMOUT=${TMOUT}${newline}"
    fi

    if [ -z "$raw_output" ]; then
        raw_output="TMOUT 설정 없음${newline}확인경로: /etc/profile, /etc/bash.bashrc, /etc/profile.d/*.sh"
    fi

    command_result="${raw_output}"
    command_executed="grep -rE 'TMOUT=' /etc/profile /etc/bash.bashrc /etc/profile.d/ 2>/dev/null"

    # 최종 판정
    if [ -n "$tmout_value" ]; then
        if [ "$tmout_value" -le 600 ] 2>/dev/null; then
            diagnosis_result="GOOD"
            status="양호"
            inspection_summary="세션 종료시간이 적절히 설정됨 (TMOUT=${tmout_value}초, 600초 이하)"
        else
            diagnosis_result="VULNERABLE"
            status="취약"
            inspection_summary="세션 종료시간이 너무 김 (TMOUT=${tmout_value}초, 600초 이하 권장)"
        fi
    else
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="세션 종료시간이 설정되지 않음 (보안 위험)"
    fi

    # 결과 생성
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
