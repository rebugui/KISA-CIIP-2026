#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : U-52
# @Category    : Unix Server
# @Platform    : AIX
# @Severity    : 중
# @Title       : Telnet 서비스 비활성화
# @Description : Telnet 서비스 중지 확인
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


ITEM_ID="U-52"
ITEM_NAME="Telnet 서비스 비활성화"
SEVERITY="중"

# 가이드라인 정보
GUIDELINE_PURPOSE="취약한 Telnet 프로토콜을 비활성화함으로써 계정 및 중요 정보 유출 방지하기 위함"
GUIDELINE_THREAT="원격 접속 시 Telnet 프로토콜을 사용할 경우, 데이터가 평문으로 전송되어 비인가자가 스니핑을 통해 계정 및 중요 정보를 외부로 유출할 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="원격 접속 시 Telnet 프로토콜을 비활성화하고 있는 경우"
GUIDELINE_CRITERIA_BAD="원격 접속 시 Telnet 프로토콜을 사용하는 경우"
GUIDELINE_REMEDIATION="Telnet,FTP 등 안전하지 않은 서비스 사용을 중지하고 SSH 설치 및 사용하도록 설정"

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
    # Telnet 서비스 비활성화 확인

    local telnet_running=false
    local telnet_details=""
    local service_status=""

    # 1) Telnet 서비스 실행 여부 확인 (AIX: lssrc)
    local telnetd_lssrc=$(lssrc -s telnetd 2>/dev/null || echo "")
    local telnetd_status="inoperative"
    if echo "$telnetd_lssrc" | grep -q "active"; then
        telnetd_status="active"
    fi
    if [ "$telnetd_status" = "active" ]; then
        telnet_running=true
        telnet_details="telnetd 서비스 상태: ${telnetd_status}"
        service_status="${telnetd_status}"
    fi

    # 2) Telnet 서비스 실행 여부 확인 (inetd)
    if [ -f /etc/inetd.conf ]; then
        if grep -q "^telnet" /etc/inetd.conf 2>/dev/null; then
            telnet_running=true
            telnet_details="${telnet_details}, inetd.conf에 telnet 항목 존재"
        fi
    fi

    # 3) Telnet 포트 Listening 확인 (AIX netstat 점 표기 *.23 및 콜론 표기 모두 매칭)
    local port_probe_cmd="netstat -an | grep -E '[.:]23[[:space:]].*LISTEN'"
    local port_probe_out=""
    local port_evidence=""
    local port_cmd_note=""
    if command -v netstat >/dev/null 2>&1; then
        port_probe_out=$(netstat -an 2>/dev/null | grep -E '[.:]23[[:space:]].*LISTEN' || true)
        port_cmd_note="${port_probe_cmd}"
        if [ -n "$port_probe_out" ]; then
            telnet_running=true
            telnet_details="${telnet_details}, 포트 23 listening"
            port_evidence="[Command: ${port_probe_cmd}]${newline}${port_probe_out}"
        else
            port_evidence="[Command: ${port_probe_cmd}]${newline}출력 없음 (포트 23 LISTEN 미검출)"
        fi
    else
        port_cmd_note="netstat 사용 불가 (포트 23 확인 생략)"
        port_evidence="netstat 명령을 사용할 수 없어 포트 23 상태 확인 불가"
    fi

    # 4) Telnet 패키지 설치 여부 확인 (AIX: lslpp -L)
    local telnet_installed=""
    if lslpp -L 2>/dev/null | grep -qi "telnet"; then
        telnet_installed="telnet 패키지 설치됨"
    fi

    if [ "$telnet_running" = true ]; then
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="Telnet 서비스가 실행 중임: ${telnet_details#, }${telnet_installed:+ ($telnet_installed)}"
        command_result="${telnet_details#, }${telnet_installed:+, $telnet_installed}"
        command_executed="lssrc -s telnetd 2>/dev/null; grep '^telnet' /etc/inetd.conf; ${port_cmd_note}"
    else
        diagnosis_result="GOOD"
        status="양호"
        if [ -n "$telnet_installed" ]; then
            inspection_summary="Telnet 서비스는 비활성화되어 있으나 패키지는 설치됨 (${telnet_installed})"
            local lssrc_out=$(lssrc -s telnet 2>/dev/null || echo "Telnet service not found")
            local cmd_check=$(command -v telnetd 2>/dev/null || echo "telnetd command not found")
            command_result="[Command: lssrc -s telnet]${newline}${lssrc_out}${newline}${newline}[Command: command -v telnetd]${newline}${cmd_check}"
        else
            inspection_summary="Telnet 서비스가 설치되어 있지 않거나 비활성화됨"
            local lssrc_out=$(lssrc -s telnet 2>/dev/null || echo "Telnet service not found")
            command_result="[Command: lssrc -s telnet]${newline}${lssrc_out}${newline}${newline}${port_evidence}"
        fi
        command_executed="lssrc -s telnetd 2>/dev/null; grep '^telnet' /etc/inetd.conf; ${port_cmd_note}"
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
