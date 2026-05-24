#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : U-36
# @Category    : Unix Server
# @Platform    : HP-UX
# @Severity    : 상
# @Title       : r 계열 서비스 비활성화
# @Description : TMOUT <= 600 seconds 확인
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


ITEM_ID="U-36"
ITEM_NAME="r 계열 서비스 비활성화"
SEVERITY="상"

# 가이드라인 정보
GUIDELINE_PURPOSE="r-command 사용을 통한 원격 접속은 NET Backup 또는 클러스터 링 등 용도로 사용되기도하나, 인증 없이 관리자 원격 접속이 가능하여 이에 대한 보안 위협을 방지하기 위함"
GUIDELINE_THREAT="rlogin, rsh, rexec 등의 r-command를 이용하여 원격에서 인증 절차 없이 터미널 접속, 쉘 명령어를 실행이 가능한 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="불필요한 r 계열 서비스가 비활성화된 경우"
GUIDELINE_CRITERIA_BAD="불필요한 r 계열 서비스가 활성화된 경우"
GUIDELINE_REMEDIATION="불필요한 r 계열 서비스 중지 및 비활성화 설정 ※ NET Backup 등 특별한 용도로 사용하지 않는다면 shell(514), login(513), exec(512)서비스 중 지 ※ rlogin, rsh, rexec 서비스는 backup, 클러스터 링 등의 용도로 종종 사용되고 있으므로 해당 서 비 스 사용 유무를 확인하여 미사용 시 서비스 중지 ※ /etc/hosts.equiv 또는 \$HOME/.rhosts 파일을 통해 해당 서비스 사용 여부 확인 (파일이 존재하지 않거나 해당 파일 내에 설정이 없다면 사용하지 않는 것으로 간주)"

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
    # /etc/profile, /etc/bash.bashrc에서 TMOUT 또는 TIMEOUT 확인

    local is_secure=false
    local config_details=""
    local tmout_value=""
    local timeout_value=""

    # 1) /etc/profile 확인
    if [ -f /etc/profile ]; then
        local profile_tmout=$(grep -E "^TMOUT=" /etc/profile | awk -F= '{print $2}' | tr -d ' ')
        if [ -n "$profile_tmout" ]; then
            tmout_value=$profile_tmout
        fi
        local profile_timeout=$(grep -E "^TIMEOUT=" /etc/profile | awk -F= '{print $2}' | tr -d ' ')
        if [ -n "$profile_timeout" ]; then
            timeout_value=$profile_timeout
        fi
    fi

    # 2) /etc/bash.bashrc 확인
    if [ -z "$tmout_value" ] && [ -f /etc/bash.bashrc ]; then
        local bashrc_tmout=$(grep -E "^TMOUT=" /etc/bash.bashrc | awk -F= '{print $2}' | tr -d ' ')
        if [ -n "$bashrc_tmout" ]; then
            tmout_value=$bashrc_tmout
        fi
        local bashrc_timeout=$(grep -E "^TIMEOUT=" /etc/bash.bashrc | awk -F= '{print $2}' | tr -d ' ')
        if [ -n "$bashrc_timeout" ]; then
            timeout_value=$bashrc_timeout
        fi
    fi

    # 3) /etc/profile.d/*.sh 확인
    if [ -z "$tmout_value" ] && [ -d /etc/profile.d ]; then
        local profile_d_tmout=$(grep -h -E "^TMOUT=" /etc/profile.d/*.sh 2>/dev/null | awk -F= '{print $2}' | tr -d ' ' | head -1)
        if [ -n "$profile_d_tmout" ]; then
            tmout_value=$profile_d_tmout
        fi
    fi

    # 값 검증 (TMOUT 또는 TIMEOUT)
    local final_value=""
    if [ -n "$tmout_value" ]; then
        final_value=$tmout_value
        config_details="TMOUT=${tmout_value} seconds"
    elif [ -n "$timeout_value" ]; then
        final_value=$timeout_value
        config_details="TIMEOUT=${timeout_value} seconds"
    fi

    # 최종 판정 (600초 = 10분 이하이면 양호)
    if [ -n "$final_value" ]; then
        if [ "$final_value" -le 600 ]; then
            is_secure=true
        fi
    fi

    if [ "$is_secure" = true ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="자동 로그아웃 설정 적절함 (${config_details} <= 600초)"
        command_result="${config_details}"
        command_executed="grep -E '^TMOUT=|^TIMEOUT=' /etc/profile /etc/bash.bashrc"
    elif [ -n "$final_value" ]; then
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="자동 로그아웃 설정됨但 시간 초과 (${config_details} > 600초)"
        command_result="${config_details}"
        command_executed="grep -E '^TMOUT=|^TIMEOUT=' /etc/profile /etc/bash.bashrc"
    else
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="자동 로그아웃 미설정 (TMOUT 또는 TIMEOUT 변수 미설정)"
        local tmout_check=$(grep -E '^TMOUT=|^TIMEOUT=' /etc/profile /etc/bash.bashrc 2>/dev/null || echo "No TMOUT/TIMEOUT settings found")
        command_result="${tmout_check}"
        command_executed="grep -E '^TMOUT=|^TIMEOUT=' /etc/profile /etc/bash.bashrc"
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
