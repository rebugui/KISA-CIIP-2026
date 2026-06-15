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
# @Platform    : HP-UX
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
        local ntp_not_installed=$(which ntpd chronyd 2>/dev/null || ls /etc/ntp.conf /etc/chrony.conf 2>/dev/null || echo "NTP not installed")
        command_result="${ntp_not_installed}"
        command_executed="which ntpd chronyd; ls /etc/{ntp.conf,chrony.conf} 2>/dev/null"
    else
        # 2) NTP 설정 파일 확인
        if [ -f /etc/ntp.conf ]; then
            config_files="${config_files}/etc/ntp.conf"

            # NTP 서버 설정 확인 (server 또는 pool 지시자)
            local ntp_servers=$(grep -E "^[\s]*server|^[\s]*pool" /etc/ntp.conf 2>/dev/null | grep -v "^#" | head -5)
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
            local chrony_servers=$(grep -E "^[\s]*server|^[\s]*pool" /etc/chrony.conf 2>/dev/null | grep -v "^#" | head -5)
            if [ -n "$chrony_servers" ]; then
                ntp_configured=true
                ntp_details="${ntp_details}, Chrony 서버 설정됨"
            fi
        fi

        # systemd-timesyncd 확인 (최신 리눅스 배포판)
        if [ -f /etc/systemd/timesyncd.conf ]; then
            config_files="${config_files} /etc/systemd/timesyncd.conf"

            local timesyncd_servers=$(grep "^[\s]*NTP=" /etc/systemd/timesyncd.conf 2>/dev/null | grep -v "^#" | grep -v "^NTP=$")
            if [ -n "$timesyncd_servers" ]; then
                ntp_configured=true
                ntp_details="${ntp_details}, systemd-timesyncd: ${timesyncd_servers}"
            fi
        fi

        # 3) NTP 서비스 실행 여부 확인
        local ntp_service_running=false
        local probe_available=false
        if [ -f /sbin/init.d/ntp ] || [ -f /sbin/init.d/xntpd ]; then
            probe_available=true
            if /sbin/init.d/ntp status 2>/dev/null | grep -q "running" >/dev/null 2>&1 || /sbin/init.d/xntpd status 2>/dev/null | grep -q "running" >/dev/null 2>&1; then
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

        # 4) NTP 패키지 설치 확인
        local ntp_packages=""
        if swlist 2>/dev/null | grep -q "ntp "; then
            ntp_packages="${ntp_packages}ntp "
        fi

        # 최종 판정
        if [ "$ntp_running" = true ] && [ "$ntp_configured" = true ]; then
            # 실제 동기화 상태 확인 (ntpq -p '*' 동기화 피어 / chronyc tracking) - 미동기화는 취약
            local sync_state="unknown"
            local sync_evidence=""
            if command -v ntpq >/dev/null 2>&1; then
                sync_evidence=$(ntpq -pn 2>/dev/null | head -10 || true)
                if echo "$sync_evidence" | grep -q '^\*'; then
                    sync_state="synced"
                elif [ -n "$sync_evidence" ]; then
                    sync_state="unsynced"
                fi
            fi
            if [ "$sync_state" = "unknown" ] && command -v chronyc >/dev/null 2>&1; then
                sync_evidence=$(chronyc tracking 2>/dev/null || true)
                if echo "$sync_evidence" | grep -qiE 'Leap status[[:space:]]*:[[:space:]]*Normal'; then
                    sync_state="synced"
                elif [ -n "$sync_evidence" ]; then
                    sync_state="unsynced"
                fi
            fi

            if [ "$sync_state" = "unsynced" ]; then
                diagnosis_result="VULNERABLE"
                status="취약"
                inspection_summary="NTP 데몬은 실행 중이나 동기화된 피어가 없어 시간 동기화가 이루어지지 않음: ${ntp_details}"
                command_result="${ntp_details}, service: running, sync: none${newline}${sync_evidence}"
                command_executed="ntpq -pn; chronyc tracking; cat ${config_files}"
            elif [ "$sync_state" = "unknown" ]; then
                diagnosis_result="MANUAL"
                status="수동진단"
                inspection_summary="NTP 데몬 실행 및 서버 설정은 확인되었으나 동기화 상태(ntpq/chronyc)를 확인할 수 없음 - 수동 확인 필요: ${ntp_details}"
                command_result="${ntp_details}, service: running, sync: unknown(probe unavailable)"
                command_executed="ntpq -pn; chronyc tracking; cat ${config_files}"
            else
                diagnosis_result="GOOD"
                status="양호"
                inspection_summary="NTP 서비스 실행 중이며 시간 동기화 동작 확인됨: ${ntp_details}"
                command_result="${ntp_details}, service: running, sync: active${newline}${sync_evidence}"
                command_executed="ntpq -pn; chronyc tracking; cat ${config_files}"
            fi
        elif [ "$ntp_configured" = true ] && [ "$probe_available" = false ]; then
            diagnosis_result="MANUAL"
            status="수동진단"
            inspection_summary="NTP 서버 설정은 확인되었으나 데몬 동작 상태를 확인할 수 없음 (init 스크립트/ps 사용 불가): ${ntp_details}"
            command_result="${ntp_details}, probe: unavailable (daemon state unknown)"
            command_executed="ls /sbin/init.d/ntp /sbin/init.d/xntpd 2>/dev/null; command -v ps"
        elif [ "$ntp_configured" = true ]; then
            diagnosis_result="VULNERABLE"
            status="취약"
            inspection_summary="NTP 서버 설정은 있으나 NTP 데몬이 중지되어 시간 동기화가 동작하지 않음: ${ntp_details}"
            command_result="${ntp_details}, service: stopped"
            command_executed="/sbin/init.d/xntpd status 2>/dev/null; ps -ef | grep ntpd; grep -E '^server|^pool' /etc/ntp.conf 2>/dev/null"
        else
            diagnosis_result="VULNERABLE"
            status="취약"
            if [ -z "$ntp_details" ]; then
                inspection_summary="NTP가 설치되어 있으나 서버 설정 안됨"
                local ntp_no_config=$(ls /etc/ntp.conf /etc/chrony.conf 2>/dev/null || cat /etc/ntp.conf 2>/dev/null | grep '^server' | head -3 || echo "NTP installed but not configured")
                command_result="${ntp_no_config}"
            else
                inspection_summary="NTP 설정 또는 서비스 실행 문제: ${ntp_details}"
                command_result="${ntp_details}, service: ${ntp_service_running:-[inactive]}"
            fi
            command_executed="/sbin/init.d/ntp status 2>/dev/null; ps -ef | grep -E 'xntpd|ntpd|chronyd'; grep -E '^server|^pool' /etc/ntp.conf /etc/chrony.conf 2>/dev/null"
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
