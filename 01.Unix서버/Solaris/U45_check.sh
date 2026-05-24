#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : U-45
# @Category    : Unix Server
# @Platform    : Solaris
# @Severity    : 상
# @Title       : 메일 서비스 버전 점검
# @Description : Sendmail/Postfix 버전 확인
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


ITEM_ID="U-45"
ITEM_NAME="메일 서비스 버전 점검"
SEVERITY="상"

# 가이드라인 정보
GUIDELINE_PURPOSE="메일 서비스 사용 목적 검토 및 취약점이 없는 버전의 사용 유무 점검으로 최적화된 메일 서비스의 운영하기 위함"
GUIDELINE_THREAT="취약점이 발견된 메일 버전의 경우 버퍼 오버 플로우(Buffer Overflow) 공격에 의한 시스템 권한 획득 및 주요 정보 노출의 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="메일 서비스 버전이 최신 버전인 경우"
GUIDELINE_CRITERIA_BAD="메일 서비스 버전이 최신 버전이 아닌 경우"
GUIDELINE_REMEDIATION="메일 서비스를 사용하지 않는 경우 서비스 중지 및 비활성화 설정 메일 서비스 사용 시 패치 관리 정책을 수립하여 주기적으로 패치 적용 설정"

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

    # 메일 서비스 버전 확인
    local mail_installed=false
    local mail_info=""
    local mail_version=""

    # Raw command outputs
    local sendmail_cmd_output=""
    local postconf_cmd_output=""
    local exim_cmd_output=""
    local sendmail_svc_output=""
    local postfix_svc_output=""
    local exim_svc_output=""

    # 1) Sendmail 확인
    if command -v sendmail &>/dev/null; then
        mail_installed=true
        sendmail_cmd_output=$(sendmail -d0.4 -bv < /dev/null 2>&1 || echo "Command failed")
        mail_version=$(echo "$sendmail_cmd_output" | grep "Version" | head -1 || echo "Unknown")
        mail_info="${mail_info}Sendmail: ${mail_version}${newline}"
    else
        sendmail_cmd_output="sendmail 명령어 없음"
    fi

    # 2) Postfix 확인
    if command -v postconf &>/dev/null; then
        mail_installed=true
        postconf_cmd_output=$(postconf mail_version 2>/dev/null || echo "Command failed")
        mail_version=$(echo "$postconf_cmd_output" | grep "mail_version" | awk '{print $3}' || echo "Unknown")
        mail_info="${mail_info}Postfix: ${mail_version}${newline}"
    else
        postconf_cmd_output="postconf 명령어 없음"
    fi

    # 3) Exim 확인
    if command -v exim &>/dev/null; then
        mail_installed=true
        exim_cmd_output=$(exim --version 2>&1 || echo "Command failed")
        mail_version=$(echo "$exim_cmd_output" | head -1 || echo "Unknown")
        mail_info="${mail_info}Exim: ${mail_version}${newline}"
    else
        exim_cmd_output="exim 명령어 없음"
    fi

    # 4) 서비스 실행 확인 (Solaris SMF)
    if svcs sendmail 2>/dev/null | grep -q "online"; then
        mail_installed=true
        sendmail_svc_output="online"
        mail_info="${mail_info}Sendmail 서비스 실행 중${newline}"
    else
        sendmail_svc_output="offline 또는 미설치"
    fi

    if svcs postfix 2>/dev/null | grep -q "online"; then
        mail_installed=true
        postfix_svc_output="online"
        mail_info="${mail_info}Postfix 서비스 실행 중${newline}"
    else
        postfix_svc_output="offline 또는 미설치"
    fi

    if svcs exim 2>/dev/null | grep -q "online"; then
        mail_installed=true
        exim_svc_output="online"
        mail_info="${mail_info}Exim 서비스 실행 중${newline}"
    else
        exim_svc_output="offline 또는 미설치"
    fi

    # 최종 판정
    if [ "$mail_installed" = false ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="메일 서비스 미설치됨"
        local mail_check=$(command -v sendmail postconf exim 2>/dev/null || echo "No mail commands found")
        local mail_svc=$(svcs sendmail postfix exim 2>/dev/null || echo "No mail services found")
        command_result="[Command: command -v sendmail postconf exim]${newline}${mail_check}${newline}${newline}[Command: svcs sendmail postfix exim]${newline}${mail_svc}"
        command_executed="command -v sendmail postconf exim; svcs sendmail postfix exim"
    else
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="메일 서비스 설치됨 - 버전 확인 필요: 최신 보안 패치 적용 여부 수동 확인 권장"
        command_result="${mail_info}${newline}${newline}[Sendmail Command Output]${newline}${sendmail_cmd_output}${newline}${newline}[Postfix Command Output]${newline}${postconf_cmd_output}${newline}${newline}[Exim Command Output]${newline}${exim_cmd_output}${newline}${newline}[Service Status]${newline}Sendmail: ${sendmail_svc_output}${newline}Postfix: ${postfix_svc_output}${newline}Exim: ${exim_svc_output}"
        command_executed="sendmail -d0.4 -bv < /dev/null; postconf mail_version; exim --version; svcs sendmail postfix exim"
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
