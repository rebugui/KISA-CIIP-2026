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
# @Platform    : Solaris
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
    # 세션 타임아웃 설정 확인 (Solaris)
    # - sh/ksh/bash: /etc/profile의 TMOUT (초 단위, 1~600초 양호)
    # - csh: /etc/.login, /etc/csh.cshrc, /etc/csh.login의 set autologout (분 단위, 1~10분 양호)
    # GOOD: 시스템 설정 파일에 TMOUT 1~600초 또는 autologout 1~10분 설정
    # VULNERABLE: 미설정 또는 범위 벗어남(0, 600초/10분 초과)
    # MANUAL: 설정 파일을 읽을 수 없어 확인 불가

    local is_secure=false
    local config_details=""
    local tmout_value=""
    local tmout_source=""
    local tmout_found=false
    local autologout_value=""
    local autologout_source=""
    local autologout_found=false
    local unreadable_files=""
    local cmd_tmout="grep -E '^[[:space:]]*(export[[:space:]]+)?TMOUT=' /etc/profile"
    local cmd_autologout="grep -E '^[[:space:]]*set[[:space:]]+autologout[[:space:]]*=' /etc/.login /etc/csh.cshrc /etc/csh.login"

    # 1) sh/ksh/bash 계열: /etc/profile에서 TMOUT 확인 (시스템 설정 파일만 인정, 환경변수 상속은 미인정)
    local sh_file=""
    for sh_file in /etc/profile; do
        if [ -f "${sh_file}" ]; then
            if [ ! -r "${sh_file}" ]; then
                unreadable_files="${unreadable_files}${sh_file} "
                continue
            fi
            local tmout_line=""
            tmout_line=$(grep -E '^[[:space:]]*(export[[:space:]]+)?TMOUT=' "${sh_file}" 2>/dev/null | tail -n 1 || true)
            if [ -n "${tmout_line}" ]; then
                tmout_found=true
                tmout_value=$(echo "${tmout_line}" | sed -e 's/^.*TMOUT=//' -e 's/[^0-9].*$//')
                tmout_source="${sh_file}"
            fi
        fi
    done

    # 2) csh 계열: /etc/.login, /etc/csh.cshrc, /etc/csh.login에서 autologout 확인 (분 단위)
    local csh_file=""
    for csh_file in /etc/.login /etc/csh.cshrc /etc/csh.login; do
        if [ -f "${csh_file}" ]; then
            if [ ! -r "${csh_file}" ]; then
                unreadable_files="${unreadable_files}${csh_file} "
                continue
            fi
            local autologout_line=""
            autologout_line=$(grep -E '^[[:space:]]*set[[:space:]]+autologout[[:space:]]*=' "${csh_file}" 2>/dev/null | tail -n 1 || true)
            if [ -n "${autologout_line}" ] && [ "${autologout_found}" = false ]; then
                autologout_found=true
                autologout_value=$(echo "${autologout_line}" | sed -e 's/^.*autologout[[:space:]]*=[[:space:]]*//' -e 's/[^0-9].*$//')
                autologout_source="${csh_file}"
            fi
        fi
    done

    # 3) TMOUT 값 판정 (1~600초 양호, 0 또는 600 초과 취약)
    local tmout_in_range=false
    if [ "${tmout_found}" = true ]; then
        if [ -n "${tmout_value}" ] && [[ "${tmout_value}" =~ ^[0-9]+$ ]] && [ "${tmout_value}" -ge 1 ] && [ "${tmout_value}" -le 600 ]; then
            tmout_in_range=true
            config_details="TMOUT=${tmout_value}초 (${tmout_source}) - 1~600초(10분) 이내 [양호]"
        else
            config_details="TMOUT=${tmout_value:-비정상값} (${tmout_source}) - 1~600초(10분) 범위 벗어남 [취약] (0은 자동 종료 비활성화)"
        fi
    else
        config_details="/etc/profile: TMOUT 설정 없음"
    fi

    # 4) autologout 값 판정 (분 단위: 1~10분 = 60~600초 양호)
    local autologout_in_range=false
    if [ "${autologout_found}" = true ]; then
        if [ -n "${autologout_value}" ] && [[ "${autologout_value}" =~ ^[0-9]+$ ]] && [ "${autologout_value}" -ge 1 ] && [ "${autologout_value}" -le 10 ]; then
            autologout_in_range=true
            config_details="${config_details}${newline}autologout=${autologout_value}분 (${autologout_source}) - 1~10분(600초) 이내 [양호]"
        else
            config_details="${config_details}${newline}autologout=${autologout_value:-비정상값} (${autologout_source}) - 1~10분(600초) 범위 벗어남 [취약]"
        fi
    else
        config_details="${config_details}${newline}/etc/.login, /etc/csh.cshrc, /etc/csh.login: autologout 설정 없음"
    fi

    if [ -n "${unreadable_files}" ]; then
        config_details="${config_details}${newline}읽기 불가 파일: ${unreadable_files}"
    fi

    # 5) 최종 판정
    if [ "${tmout_in_range}" = true ] || [ "${autologout_in_range}" = true ]; then
        is_secure=true
    fi

    if [ "${is_secure}" = true ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="세션 타임아웃 적절히 설정됨 (600초/10분 이하)${newline}${config_details}"
        command_result="${config_details}"
        command_executed="${cmd_tmout}; ${cmd_autologout}"
    elif [ "${tmout_found}" = false ] && [ "${autologout_found}" = false ] && [ -n "${unreadable_files}" ]; then
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="세션 타임아웃 설정 파일을 읽을 수 없어 수동 확인 필요 (${unreadable_files})${newline}${config_details}"
        command_result="${config_details}"
        command_executed="${cmd_tmout}; ${cmd_autologout}"
    else
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="세션 타임아웃 설정 미흡 (TMOUT 1~600초 또는 autologout 1~10분 설정 필요)${newline}${config_details}"
        command_result="${config_details}"
        command_executed="${cmd_tmout}; ${cmd_autologout}"
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
