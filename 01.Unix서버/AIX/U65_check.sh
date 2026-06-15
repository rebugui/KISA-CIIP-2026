#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : U-65
# @Category    : Unix Server
# @Platform    : AIX
# @Severity    : 중
# @Title       : NTP 및 시각 동기화 설정
# @Description : NTP 서비스 설정 확인
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


ITEM_ID="U-65"
ITEM_NAME="NTP 및 시각 동기화 설정"
SEVERITY="중"

# 가이드라인 정보
GUIDELINE_PURPOSE="인증 및 감사 목적을 위한 시간 동기화는 필수적이며, 안전하고 승인된 NTP 서비스와 동기화하기 위함"
GUIDELINE_THREAT="시스템 간 시간 동기화 미흡으로 보안 사고 및 장애 발생 시 로그에 대한 신뢰도 확보 미흡 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="NTP 및 시각 동기화 설정이 기준에 따라 적용된 경우"
GUIDELINE_CRITERIA_BAD="NTP 및 시각 동기화 설정이 기준에 따라 적용되어 있지 않은 경우"
GUIDELINE_REMEDIATION="NTP 설정 및 동기화 주기 설정"

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
    # NTP 및 시각 동기화 설정 확인

    local ntp_installed=false
    local ntp_running=false
    local ntp_configured=false
    local ntp_details=""
    local config_files=""

    # 1) NTP 서비스 설치 여부 확인
    if command -v ntpd >/dev/null 2>&1 || [ -f /etc/ntp.conf ] || command -v chronyd >/dev/null 2>&1 || [ -f /etc/chrony.conf ]; then
        ntp_installed=true
    fi

    if [ "$ntp_installed" = false ]; then
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="NTP 서비스가 설치되지 않음 (시간 동기화 불가)"
        local cmd_check=$(command -v ntpd 2>/dev/null || echo "ntpd command not found")
        local pkg_check=$(lslpp -L | grep -i ntp 2>/dev/null || echo "NTP packages not found")
        command_result="[Command: command -v ntpd]${newline}${cmd_check}${newline}${newline}[Command: lslpp -L | grep ntp]${newline}${pkg_check}"
        command_executed="which ntpd chronyd; ls /etc/{ntp.conf,chrony.conf} 2>/dev/null"
    else
        # 2) NTP 설정 파일 확인
        if [ -f /etc/ntp.conf ]; then
            config_files="${config_files}/etc/ntp.conf"

            # NTP 서버 설정 확인 (server 또는 pool 지시자)
            local ntp_servers=$(grep -E "^[[:space:]]*(server|pool)[[:space:]]" /etc/ntp.conf 2>/dev/null | grep -v "^[[:space:]]*#" | head -5)
            if [ -n "$ntp_servers" ]; then
                ntp_configured=true
                ntp_details="NTP 서버 설정됨: $(echo "$ntp_servers" | head -3 | tr '\n' ' ')"
            else
                ntp_details="NTP 서버 설정 없음"
            fi
        fi

        if [ -f /etc/chrony.conf ]; then
            config_files="${config_files} /etc/chrony.conf"

            # Chrony 서버 설정 확인
            local chrony_servers=$(grep -E "^[[:space:]]*(server|pool)[[:space:]]" /etc/chrony.conf 2>/dev/null | grep -v "^[[:space:]]*#" | head -5)
            if [ -n "$chrony_servers" ]; then
                ntp_configured=true
                ntp_details="${ntp_details}, Chrony 서버 설정됨"
            fi
        fi

        # systemd-timesyncd 확인 (최신 리눅스 배포판)
        if [ -f /etc/systemd/timesyncd.conf ]; then
            config_files="${config_files} /etc/systemd/timesyncd.conf"

            local timesyncd_servers=$(grep -E "^[[:space:]]*NTP=" /etc/systemd/timesyncd.conf 2>/dev/null | grep -v "^[[:space:]]*#" | grep -v "^NTP=$")
            if [ -n "$timesyncd_servers" ]; then
                ntp_configured=true
                ntp_details="${ntp_details}, systemd-timesyncd: ${timesyncd_servers}"
            fi
        fi

        # 3) NTP 서비스 실행 여부 확인 (AIX: lssrc, xntpd daemon)
        local ntp_service_running=false
        local probe_available=false
        if command -v lssrc >/dev/null 2>&1; then
            probe_available=true
            local xntpd_lssrc=$(lssrc -s xntpd 2>/dev/null || echo "")
            local xntpd_status="inoperative"
            if echo "$xntpd_lssrc" | grep -q "active"; then
                xntpd_status="active"
            fi
            if [ "$xntpd_status" = "active" ]; then
                ntp_running=true
                ntp_service_running=true
            fi
        fi
        if [ "$ntp_running" = false ] && command -v ps >/dev/null 2>&1; then
            probe_available=true
            if ps -ef 2>/dev/null | grep -v grep | grep -qE 'xntpd|ntpd|chronyd'; then
                ntp_running=true
                ntp_service_running=true
            fi
        fi

        # 4) NTP 패키지 설치 확인 (AIX: lslpp -L)
        local ntp_packages=""
        if lslpp -L 2>/dev/null | grep -qi "bos.net.tcp.client"; then
            ntp_packages="${ntp_packages}bos.net.tcp.client(xntpd) "
        fi

        # 최종 판정
        if [ "$ntp_running" = true ] && [ "$ntp_configured" = true ]; then
            diagnosis_result="GOOD"
            status="양호"
            inspection_summary="NTP 서비스 실행 중且 시간 동기화 설정됨: ${ntp_details}"
            local lssrc_out=$(lssrc -s xntpd 2>/dev/null || echo "NTP service not found")
            local ntpq_out=$(ntpq -p 2>/dev/null | head -10 || echo "ntpq failed")
            command_result="[Command: lssrc -s xntpd]${newline}${lssrc_out}${newline}${newline}[Command: ntpq -p]${newline}${ntpq_out}"
            command_executed="lssrc -a ntp chrony systemd-timesyncd 2>/dev/null; cat ${config_files}"
        elif [ "$ntp_configured" = true ] && [ "$probe_available" = false ]; then
            diagnosis_result="MANUAL"
            status="수동진단"
            inspection_summary="NTP 서버 설정은 확인되었으나 데몬 동작 상태를 확인할 수 없음 (lssrc/ps 사용 불가): ${ntp_details}"
            local cat_ntp=$(cat /etc/ntp.conf 2>/dev/null | head -30 || echo "NTP config not readable")
            command_result="[Command: cat /etc/ntp.conf]${newline}${cat_ntp}${newline}${newline}[Probe] lssrc/ps unavailable - daemon state unknown"
            command_executed="command -v lssrc; command -v ps; cat /etc/ntp.conf"
        elif [ "$ntp_configured" = true ]; then
            diagnosis_result="VULNERABLE"
            status="취약"
            inspection_summary="NTP 서버 설정은 있으나 NTP 데몬이 중지되어 시간 동기화가 동작하지 않음: ${ntp_details}"
            local lssrc_out=$(lssrc -s xntpd 2>/dev/null || echo "NTP service not found")
            local cat_ntp=$(cat /etc/ntp.conf 2>/dev/null | head -30 || echo "NTP config not readable")
            command_result="[Command: lssrc -s xntpd]${newline}${lssrc_out}${newline}${newline}[Command: cat /etc/ntp.conf]${newline}${cat_ntp}"
            command_executed="lssrc -s xntpd 2>/dev/null; cat /etc/ntp.conf"
        else
            diagnosis_result="VULNERABLE"
            status="취약"
            if [ -z "$ntp_details" ]; then
                inspection_summary="NTP가 설치되어 있으나 서버 설정 안됨"
                local find_ntp=$(find /etc -name 'ntp*' 2>/dev/null | head -10 || echo "No NTP configs found")
                command_result="[Command: find /etc -name 'ntp*']${newline}${find_ntp}"
            else
                inspection_summary="NTP 설정 또는 서비스 실행 문제: ${ntp_details}"
                local lssrc_out=$(lssrc -s xntpd 2>/dev/null || echo "NTP service not found")
                local cat_ntp=$(cat /etc/ntp.conf 2>/dev/null | head -20 || echo "Config not readable")
                command_result="[Command: lssrc -s xntpd]${newline}${lssrc_out}${newline}${newline}[Command: cat /etc/ntp.conf]${newline}${cat_ntp}"
            fi
            command_executed="lssrc -s xntpd; grep -E '^[[:space:]]*(server|pool)[[:space:]]' /etc/ntp.conf /etc/chrony.conf 2>/dev/null"
        fi
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
