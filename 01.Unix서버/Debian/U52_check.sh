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
# @Platform    : Debian
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

    # 1) Telnet 서비스 실행 여부 확인 (systemd)
    if command -v systemctl >/dev/null 2>&1; then
        service_status=$(systemctl is-active telnetd 2>/dev/null || systemctl is-active telnet 2>/dev/null || echo "inactive")

        if [ "$service_status" = "active" ] || [ "$service_status" = "running" ]; then
            telnet_running=true
            telnet_details="systemd 서비스 상태: ${service_status}"
        fi
    fi

    # 2) Telnet 서비스 실행 여부 확인 (xinetd/inetd)
    if [ -f /etc/xinetd.d/telnet ]; then
        local xinetd_status=$(grep -E "^[\s]*disable" /etc/xinetd.d/telnet 2>/dev/null | awk '{print $2}')
        if [ "$xinetd_status" = "no" ]; then
            telnet_running=true
            telnet_details="${telnet_details}, xinetd에서 활성화됨"
        fi
    elif [ -f /etc/inetd.conf ]; then
        if grep -q "^telnet" /etc/inetd.conf 2>/dev/null; then
            telnet_running=true
            telnet_details="${telnet_details}, inetd.conf에 telnet 항목 존재"
        fi
    fi

    # 3) Telnet 포트Listening 확인
    if command -v ss >/dev/null 2>&1; then
        if ss -tuln 2>/dev/null | grep -q ":23 "; then
            telnet_running=true
            telnet_details="${telnet_details}, 포트 23 listening"
        fi
    elif command -v netstat >/dev/null 2>&1; then
        if netstat -tuln 2>/dev/null | grep -q ":23 "; then
            telnet_running=true
            telnet_details="${telnet_details}, 포트 23 listening"
        fi
    fi

    # 4) Telnet 패키지 설치 여부 확인
    local telnet_installed=""
    if command -v dpkg >/dev/null 2>&1; then
        if dpkg -l 2>/dev/null | grep -q "telnetd"; then
            telnet_installed="telnetd 패키지 설치됨"
        fi
    elif command -v rpm >/dev/null 2>&1; then
        if rpm -qa 2>/dev/null | grep -q "telnet-server"; then
            telnet_installed="telnet-server 패키지 설치됨"
        fi
    fi

    if [ "$telnet_running" = true ]; then
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="Telnet 서비스가 실행 중임: ${telnet_details#, }${telnet_installed:+ ($telnet_installed)}"
        command_result="${telnet_details#, }${telnet_installed:+, $telnet_installed}"
        command_executed="systemctl status telnetd 2>/dev/null; ss -tuln | grep ':23 '; grep -E '^disable' /etc/xinetd.d/telnet 2>/dev/null"
    else
        diagnosis_result="GOOD"
        status="양호"
        if [ -n "$telnet_installed" ]; then
            inspection_summary="Telnet 서비스는 비활성화되어 있으나 패키지는 설치됨 (${telnet_installed})"
            command_result="Telnet Service: [inactive], Package: [installed]"
        else
            inspection_summary="Telnet 서비스가 설치되어 있지 않거나 비활성화됨"
            command_result="Telnet Service: [inactive or not installed]"
        fi
        command_executed="systemctl is-active telnetd 2>/dev/null; ss -tuln | grep ':23 '"
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
