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
# @Platform    : AIX
# @Severity    : 하
# @Title       : 세션 종료 시간 설정
# @Description : TMOUT 또는 /etc/profile 설정 확인
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
    # TMOUT 또는 /etc/profile 설정 확인
    # GOOD: TMOUT이 600초(10분) 이하로 설정됨
    # VULNERABLE: TMOUT 미설정 또는 600초 초과

    local is_secure=false
    local config_details=""
    local tmout_value=""

    # 1) /etc/profile에서 TMOUT 설정 확인 (AIX grep은 -oE 미지원 → sed 사용)
    if [ -f /etc/profile ]; then
        tmout_value=$(sed -n 's/^[[:space:]]*\(export[[:space:]]*\)*TMOUT=\([0-9]*\).*/\2/p' /etc/profile 2>/dev/null | tail -1 || true)
        if [ -n "$tmout_value" ]; then
            config_details="/etc/profile TMOUT: ${tmout_value}초"
        fi
    fi

    # 2) 현재 쉘 환경에서 TMOUT 확인 (증적용 - 파일 설정이 아니므로 판정에 사용하지 않음)
    local current_tmout="${TMOUT:-}"
    if [ -n "$current_tmout" ]; then
        if [ -n "$config_details" ]; then
            config_details="${config_details}, 현재 세션 TMOUT: ${current_tmout}초 (참고)"
        else
            config_details="현재 세션 TMOUT: ${current_tmout}초 (참고)"
        fi
    fi

    # 3) 사용자별 .profile 파일 확인 (선택적)
    # AIX에서는 사용자별 홈 디렉터리의 .profile 확인
    if [ -n "${HOME:-}" ] && [ -f "$HOME/.profile" ]; then
        local user_tmout=""
        user_tmout=$(sed -n 's/^[[:space:]]*\(export[[:space:]]*\)*TMOUT=\([0-9]*\).*/\2/p' "$HOME/.profile" 2>/dev/null | tail -1 || true)
        if [ -n "$user_tmout" ]; then
            if [ -n "$config_details" ]; then
                config_details="${config_details}, 사용자 .profile TMOUT: ${user_tmout}초"
            else
                config_details="사용자 .profile TMOUT: ${user_tmout}초"
            fi
            # 사용자 설정이 우선 (파일 설정)
            tmout_value="$user_tmout"
        fi
    fi

    # 최종 판정: 설정 파일에 TMOUT이 1~600초로 구성된 경우만 양호 (0은 자동 종료 비활성화)
    if [ -n "$tmout_value" ] && [ "$tmout_value" -ge 1 ] 2>/dev/null && [ "$tmout_value" -le 600 ] 2>/dev/null; then
        is_secure=true
    fi

    # 최종 판정
    if [ "$is_secure" = true ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="세션 종료시간 적절하게 설정됨 (${config_details})"
        command_result="${config_details}"
        command_executed="grep '^TMOUT=' /etc/profile ~/.profile 2>/dev/null"
    else
        diagnosis_result="VULNERABLE"
        status="취약"
        if [ -z "$tmout_value" ]; then
            if [ -n "$config_details" ]; then
                inspection_summary="설정 파일 내 세션 종료시간(TMOUT) 미설정 (${config_details}) - 600초(10분) 이하로 설정 권장"
            else
                inspection_summary="세션 종료시간(TMOUT) 미설정 - 600초(10분) 이하로 설정 권장"
            fi
            local grep_raw=$(grep '^TMOUT=' /etc/profile ~/.profile 2>/dev/null || echo "TMOUT not found")
            command_result="[Command: grep '^TMOUT=' /etc/profile ~/.profile]${newline}${grep_raw}"
        else
            inspection_summary="세션 종료시간 부적절 (${config_details}) - 600초(10분) 이하 권장"
            local grep_raw=$(grep '^TMOUT=' /etc/profile ~/.profile 2>/dev/null || echo "TMOUT not found")
            command_result="[Command: grep '^TMOUT=' /etc/profile ~/.profile]${newline}${grep_raw}"
        fi
        command_executed="grep '^TMOUT=' /etc/profile ~/.profile 2>/dev/null"
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
