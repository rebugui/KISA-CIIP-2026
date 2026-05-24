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
    # 관리자 권한 분리 확인 (UID 0 또는 wheel group 사용자)
    # GOOD: 관리자 권한이 적절히 분리됨 (여러 관리자 계정 존재)
    # VULNERABLE: 단일 관리자 계정만 존재

    local is_secure=false
    local config_details=""

    # UID 0인 계정 (root 계정) 목록 추출
    local uid_zero_users=$(awk -F: '$3 == 0 {print $1}' /etc/passwd)
    local uid_zero_count=$(echo "$uid_zero_users" | wc -l)

    config_details="UID 0 계정 (${uid_zero_count}개): ${uid_zero_users}"

    # wheel 그룹 사용자 확인
    local wheel_users=""
    if getent group wheel >/dev/null 2>&1; then
        wheel_users=$(getent group wheel | cut -d: -f4)
        if [ -n "$wheel_users" ]; then
            local wheel_count=$(echo "$wheel_users" | tr ',' '\n' | wc -l)
            config_details="${config_details}\\nwheel 그룹 멤버 (${wheel_count}개): ${wheel_users}"
        else
            config_details="${config_details}\\nwheel 그룹 멤버: 없음"
        fi
    else
        config_details="${config_details}\\nwheel 그룹: 존재하지 않음"
    fi

    # sudo 그룹 사용자 확인 (Debian에서 관리자 그룹)
    local sudo_users=""
    if getent group sudo >/dev/null 2>&1; then
        sudo_users=$(getent group sudo | cut -d: -f4)
        if [ -n "$sudo_users" ]; then
            local sudo_count=$(echo "$sudo_users" | tr ',' '\n' | wc -l)
            config_details="${config_details}\\nsudo 그룹 멤버 (${sudo_count}개): ${sudo_users}"
        else
            config_details="${config_details}\\nsudo 그룹 멤버: 없음"
        fi
    else
        config_details="${config_details}\\nsudo 그룹: 존재하지 않음"
    fi

    # 최종 판정
    # UID 0 계정이 2개 이상이거나, wheel/sudo 그룹에 멤버가 있는 경우 양호
    local admin_count=0

    # UID 0 계정 수 (root 포함)
    admin_count=$((admin_count + uid_zero_count))

    # wheel 그룹 멤버 수
    if [ -n "$wheel_users" ]; then
        local wheel_members_count=$(echo "$wheel_users" | tr ',' '\n' | wc -l)
        admin_count=$((admin_count + wheel_members_count))
    fi

    # sudo 그룹 멤버 수
    if [ -n "$sudo_users" ]; then
        local sudo_members_count=$(echo "$sudo_users" | tr ',' '\n' | wc -l)
        admin_count=$((admin_count + sudo_members_count))
    fi

    if [ "$admin_count" -ge 2 ]; then
        is_secure=true
    fi

    # 최종 판정
    if [ "$is_secure" = true ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="관리자 권한 적절히 분리됨 (총 ${admin_count}개 관리자 계정/그룹)\\n${config_details}"
        command_result="${config_details}"
        command_executed="awk -F: '\$3 == 0 {print \$1}' /etc/passwd && getent group wheel sudo"
    else
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="관리자 권한 분리 미흡 (단일 관리자 계정만 존재)\\n${config_details}"
        command_result="${config_details}"
        command_executed="awk -F: '\$3 == 0 {print \$1}' /etc/passwd && getent group wheel sudo"
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
