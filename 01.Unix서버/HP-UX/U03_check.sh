#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : U-03
# @Category    : Unix Server
# @Platform    : HP-UX
# @Severity    : 상
# @Title       : 계정 잠금 임계값 설정
# @Description : /etc/default/security AUTH_MAXTRIES 및 Trusted Mode u_maxtries 설정 확인
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


ITEM_ID="U-03"
ITEM_NAME="계정 잠금 임계값 설정"
SEVERITY="상"

# 가이드라인 정보
GUIDELINE_PURPOSE="계정 탈취 목적의 무차별 대입 공격 시 해당 계정을 잠금으로써 인증 요청에 응답하는 리소스 낭비를 차단하고 대입 공격으로 인한 비밀번호 노출 공격을 무력화하기 위함"
GUIDELINE_THREAT="계정 잠금 임계값이 설정되어 있지 않을 경우, 비밀번호 탈취 공격(무차별 대입 공격, 사전 대입 공격, 추측 공격 등)의 인증 요청에 대해 설정된 비밀번호가 일치할 때까지 지속적으로 응답하여 해당 계정의 비밀번호가 유출될 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="계정 잠금 임계값이 10회 이하의 값으로 설정된 경우"
GUIDELINE_CRITERIA_BAD="계정 잠금 임계값이 설정되어 있지 않거나, 10회 이하의 값으로 설정되지 않은 경우"
GUIDELINE_REMEDIATION="계정 잠금 임계값을 10회 이하로 설정"

# ============================================================================
# 진단 함수
# ============================================================================

# 진단 수행
diagnose() {
    echo "===================================================================" >&2
    echo "진단 항목: ${ITEM_ID} - ${ITEM_NAME}" >&2
    echo "심각도: ${SEVERITY}" >&2
    echo "===================================================================" >&2
    echo "" >&2

    diagnosis_result="unknown"
    status="미진단"
    inspection_summary=""
    command_result=""
    command_executed=""

    # 진단 로직 구현
    # HP-UX: /etc/default/security의 AUTH_MAXTRIES 확인
    # Trusted Mode(/tcb 존재) 시 /tcb/files/auth/system/default의 u_maxtries 확인

    local newline=$'\n'
    local security_file="/etc/default/security"
    local tcb_default="/tcb/files/auth/system/default"
    local auth_maxtries=""
    local u_maxtries=""
    local raw_security_output=""
    local raw_tcb_output=""
    local trusted_mode=false
    local tcb_readable=false
    local security_file_unreadable=false

    command_executed="grep '^AUTH_MAXTRIES' ${security_file}"

    # 1) 표준 모드: /etc/default/security의 AUTH_MAXTRIES 확인 (주석 제외)
    if [ -r "$security_file" ]; then
        raw_security_output=$(grep -E '^[[:space:]]*AUTH_MAXTRIES[[:space:]]*=' "$security_file" 2>/dev/null | tail -1 || true)
        # POSIX sed 추출 (HP-UX 기본 grep은 -o 미지원)
        auth_maxtries=$(echo "$raw_security_output" | sed -n 's/.*=[[:space:]]*\([0-9][0-9]*\).*/\1/p' | head -1 || true)
        command_result="[FILE: ${security_file}]${newline}${raw_security_output:-AUTH_MAXTRIES 설정 없음}${newline}"
    else
        security_file_unreadable=true
        command_result="[FILE: ${security_file}] 파일 없음 또는 읽기 불가${newline}"
    fi

    # 2) Trusted Mode 확인 (/tcb 존재 시 u_maxtries가 잠금 임계값을 결정)
    if [ -d "/tcb" ]; then
        trusted_mode=true
        command_executed="${command_executed}; grep 'u_maxtries' ${tcb_default}"
        if [ -r "$tcb_default" ]; then
            tcb_readable=true
            raw_tcb_output=$(grep 'u_maxtries#' "$tcb_default" 2>/dev/null | head -1 || true)
            # POSIX sed 추출 (HP-UX 기본 grep은 -o 미지원)
            u_maxtries=$(echo "$raw_tcb_output" | sed -n 's/.*u_maxtries#\([0-9][0-9]*\).*/\1/p' | head -1 || true)
            command_result="${command_result}[FILE: ${tcb_default}]${newline}${raw_tcb_output:-u_maxtries 설정 없음}${newline}"
        else
            command_result="${command_result}[FILE: ${tcb_default}] 읽기 불가 (Trusted Mode)${newline}"
        fi
    fi

    # 최종 판정
    # - Trusted Mode인데 /tcb 기본 DB를 읽지 못하면 수동진단
    # - u_maxtries 또는 AUTH_MAXTRIES가 1~10이면 양호, 0/미설정/10 초과는 취약
    if [ "$trusted_mode" = true ] && [ "$tcb_readable" = false ]; then
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="Trusted Mode 시스템이나 ${tcb_default} 파일을 읽을 수 없어 u_maxtries 값을 확인하지 못함. 수동 점검 필요 (AUTH_MAXTRIES=${auth_maxtries:-미설정})"
    elif [ "$trusted_mode" = true ] && [ -n "$u_maxtries" ]; then
        if [ "$u_maxtries" -ge 1 ] && [ "$u_maxtries" -le 10 ]; then
            diagnosis_result="GOOD"
            status="양호"
            inspection_summary="계정 잠금 임계값 적절히 설정됨 (Trusted Mode u_maxtries#${u_maxtries})"
        else
            diagnosis_result="VULNERABLE"
            status="취약"
            inspection_summary="계정 잠금 임계값 부적절 (Trusted Mode u_maxtries#${u_maxtries}, 0은 잠금 미적용)"
        fi
    elif [ -n "$auth_maxtries" ] && [ "$auth_maxtries" -ge 1 ] && [ "$auth_maxtries" -le 10 ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="계정 잠금 임계값 적절히 설정됨 (AUTH_MAXTRIES=${auth_maxtries})"
    elif [ "$trusted_mode" = false ] && [ "$security_file_unreadable" = true ] && [ -z "$auth_maxtries" ]; then
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="AUTH_MAXTRIES 점검 파일(${security_file})을 읽을 수 없어 확인 불가 - 수동 점검 필요"
    else
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="계정 잠금 임계값 미설정 또는 부적절 (AUTH_MAXTRIES=${auth_maxtries:-미설정}, 0/미설정은 잠금 미적용)"
    fi

    echo "" >&2
  #  echo "진단 결과: ${status}" >&2
  # echo "판정: ${diagnosis_result}" >&2
  # echo "설명: ${inspection_summary}" >&2
    echo "" >&2

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
