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
# @Platform    : AIX
# @Severity    : 상
# @Title       : 계정 잠금 임계값 설정
# @Description : AIX /etc/security/user loginretries 설정 확인
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
    # AIX: /etc/security/user의 loginretries 설정 확인

    local is_secure=false
    local config_details=""
    local newline=$'\n'
    local user_file="/etc/security/user"
    local raw_output=""
    local lsuser_output=""

    # 1) /etc/security/user 파일 확인 및 원본 출력 캡처
    if [ -f "$user_file" ]; then
        # loginretries 설정 추출 (default 및 사용자별 설정)
        # AIX에서 loginretries는 기본값과 사용자별 설정으로 구분됨

        # 원본 grep 출력 캡처
        raw_output=$(grep -E "^default:|^loginretries" "$user_file" 2>/dev/null || echo "")

        # 기본(default) 설정 확인
        # AIX /etc/security/user 표준 형식은 "loginretries = N" (= 양쪽 공백)이므로
        # '=' 구분자로 값 필드를 추출한다 (awk '{print $2}' 는 '=' 를 반환하는 버그가 있음).
        # default: 스탠자 경계를 벗어나면 추출을 중단하여(U02 u02_get_default_attr 동일 패턴)
        # 뒤따르는 사용자/시스템 스탠자의 loginretries 값을 default 값으로 오인하지 않도록 한다.
        # default: 스탠자에 loginretries 가 없으면 빈 값 -> 미설정 -> 취약 판정.
        local default_loginretries=$(awk '
            /^\*/ { next }
            /^default:/ { in_def=1; next }
            /^[^ \t]/ { in_def=0 }
            in_def && /loginretries/ {
                v=$0
                gsub(/[^0-9]/,"",v)
                if (v != "") val=v
            }
            END { if (val != "") print val }
        ' "$user_file" 2>/dev/null | head -1)

        # 설정이 없는 경우 AIX 기본값은 보통 3 또는 5
        if [ -z "$default_loginretries" ]; then
            # AIX 시스템 기본값 확인 (lsuser 명령)
            # lsuser 출력이 비어 있으면 "미설정"으로 간주 — 통과 기본값(3 등)을 주입하지 않는다.
            lsuser_output=$(lsuser -a loginretries root 2>/dev/null || echo "")
            if [[ "$lsuser_output" == *"loginretries="* ]]; then
                default_loginretries=$(echo "$lsuser_output" | awk -F'loginretries=' '{print $2}' | awk '{print $1}')
            else
                default_loginretries=""
            fi
        fi

        if [ -n "$default_loginretries" ]; then
            # loginretries 값이 숫자인지 확인
            if [[ "$default_loginretries" =~ ^[0-9]+$ ]]; then
                if [ "$default_loginretries" -ge 1 ] && [ "$default_loginretries" -le 10 ]; then
                    is_secure=true
                    config_details="loginretries=${default_loginretries}"
                else
                    config_details="loginretries=${default_loginretries} (기준 1~10회 범위 벗어남; 0은 계정 잠금 비활성화)"
                fi
            else
                config_details="loginretries 설정값이 숫자가 아님: ${default_loginretries}"
            fi
        else
            config_details="loginretries 설정 없음"
        fi

        # 사용자별 설정 확인 (예외 사항 체크)
        local user_sections=$(grep -n "^[a-z_]*:" "$user_file" 2>/dev/null | grep -v "^default:" || echo "")

        if [ -n "$user_sections" ]; then
            config_details="${config_details}, 사용자별 설정 확인됨"
        fi

        # 원본 출력 구성
        command_result="[FILE: /etc/security/user]${newline}${raw_output}${newline}"
        if [ -n "$lsuser_output" ]; then
            command_result="${command_result}[COMMAND: lsuser -a loginretries root]${newline}${lsuser_output}${newline}"
        fi
        command_executed="grep -E '^default:|^loginretries' /etc/security/user"
        if [ -n "$lsuser_output" ]; then
            command_executed="${command_executed}; lsuser -a loginretries root"
        fi
    else
        config_details="/etc/security/user 파일 없음"
        command_result="[FILE NOT FOUND: /etc/security/user]${newline}"
        command_executed="ls -l /etc/security/user"
    fi

    # 최종 판정
    if [ "$is_secure" = true ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="계정 잠금 임계값 적절 (${config_details})"
    else
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="계정 잠금 임계값 미설치 또는 부적절 (${config_details})"
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
