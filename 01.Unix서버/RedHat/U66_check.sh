#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-04-20
# ============================================================================
# [점검 항목 상세]
# @ID          : U-66
# @Category    : UNIX > 3. 서비스 관리
# @Platform    : RedHat
# @Severity    : 중
# @Title       : 정책에 따른 시스템로깅 설정
# @Description : rsyslog/syslog 서비스 설정 및 로그 기록 확인
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/metadata_parser.sh"

ITEM_ID="U-66"
ITEM_NAME="정책에 따른 시스템로깅 설정"
SEVERITY="중"

GUIDELINE_PURPOSE="보안 사고 발생 시 원인 파악 및 각종 침해 사실 확인을 하기 위함"
GUIDELINE_THREAT="로깅 설정이 되어 있지 않을 경우, 원인 규명이 어려우며 법적 대응을 위한 충분한 증거로 사용할 수 없는 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="로그 기록 정책이 보안 정책에 따라 설정되어 수립되어 있으며, 로그를 남기고 있는 경우"
GUIDELINE_CRITERIA_BAD="로그 기록 정책 미수립 또는 정책에 따라 설정되어 있지 않거나, 로그를 남기고 있지 않은 경우"
GUIDELINE_REMEDIATION="로그 기록 정책을 수립하고, 정책에 따라(r)syslog.conf 파일을 설정"

diagnose() {
    local status="양호"
    diagnosis_result="GOOD"
    local inspection_summary=""
    local command_result=""
    local command_executed="systemctl is-active rsyslog; grep -v '^#' /etc/rsyslog.conf | grep -v '^$' | head -20"

    local newline=$'\n'

    # ==========================================================================
    # 1. syslog 서비스 확인
    # ==========================================================================
    local syslog_service=""
    local config_file=""
    local service_active=false

    if systemctl is-active --quiet rsyslog 2>/dev/null; then
        syslog_service="rsyslog"
        service_active=true
        config_file="/etc/rsyslog.conf"
    elif systemctl is-active --quiet syslog 2>/dev/null; then
        syslog_service="syslog"
        service_active=true
        config_file="/etc/syslog.conf"
    elif [ -f /etc/rsyslog.conf ]; then
        syslog_service="rsyslog"
        config_file="/etc/rsyslog.conf"
        service_active=false
    elif [ -f /etc/syslog.conf ]; then
        syslog_service="syslog"
        config_file="/etc/syslog.conf"
        service_active=false
    else
        # syslog 서비스를 찾을 수 없음
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="syslog 서비스(rsyslog)를 찾을 수 없습니다."
        command_result="rsyslog/syslog 서비스 미발견"
        command_executed="systemctl status rsyslog; ls /etc/rsyslog.conf /etc/syslog.conf 2>/dev/null"

        save_dual_result \
            "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" \
            "${inspection_summary}" "${command_result}" "${command_executed}" \
            "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" \
            "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"

        verify_result_saved "${ITEM_ID}"
        return 0
    fi

    # ==========================================================================
    # 2. 설정 파일 확인
    # ==========================================================================
    if [ ! -f "$config_file" ]; then
        status="취약"
        diagnosis_result="VULNERABLE"
        inspection_summary="${syslog_service} 설정 파일(${config_file})이 존재하지 않습니다."
        command_result="설정 파일 없음: ${config_file}"
        command_executed="ls -l ${config_file}"

        save_dual_result \
            "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" \
            "${inspection_summary}" "${command_result}" "${command_executed}" \
            "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" \
            "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"

        verify_result_saved "${ITEM_ID}"
        return 0
    fi

    # 설정 파일 내용 분석 (주석 제외)
    local config_lines=$(grep -v "^#" "$config_file" 2>/dev/null | grep -v "^[[:space:]]*$" | wc -l)
    local raw_output=$(grep -v "^#" "$config_file" 2>/dev/null | grep -v "^[[:space:]]*$" | head -20 || echo "Empty config")

    # ==========================================================================
    # 3. 주요 로그 파일 기록 확인
    # ==========================================================================
    local log_files_check=0
    local total_log_files=0
    local critical_logs=("/var/log/messages" "/var/log/secure" "/var/log/syslog" "/var/log/auth.log" "/var/log/kern.log")

    # 설정 파일에 정의된 로그 파일 경로 추가 수집 (rsyslog '-' 접두 제거)
    local configured_logs
    configured_logs=$(grep -v "^#" "$config_file" 2>/dev/null | awk '{t=$NF; sub(/^-/,"",t); print t}' | grep "^/" | grep -v "^/dev/" | sort -u || true)
    local configured_log
    for configured_log in $configured_logs; do
        case " ${critical_logs[*]} " in
            *" ${configured_log} "*) ;;
            *) critical_logs+=("$configured_log") ;;
        esac
    done

    for log_file in "${critical_logs[@]}"; do
        ((total_log_files++)) || true
        if [ -f "$log_file" ]; then
            local last_mod=$(stat -c "%Y" "$log_file" 2>/dev/null || echo "0")
            local current_time=$(date +%s)
            local days_since_mod=$(( (current_time - last_mod) / 86400 ))
            if [ "$days_since_mod" -le 7 ]; then
                ((log_files_check++)) || true
            fi
        fi
    done || true

    command_executed="systemctl is-active ${syslog_service}; grep -v '^#' ${config_file} | grep -v '^$'; ls -l /var/log/messages /var/log/secure 2>/dev/null"

    # ==========================================================================
    # 4. 판정
    # ==========================================================================
    # 양호: 데몬 활성 + 설정 존재 + 실제 로그를 남기고 있는 경우 모두 충족
    if [ "$service_active" = true ] && [ "$config_lines" -gt 0 ] && [ "$log_files_check" -ge 1 ]; then
        status="양호"
        diagnosis_result="GOOD"
        inspection_summary="${syslog_service} 서비스가 활성화되어 있고, 로그 기록 정책이 설정되어 있으며, 로그를 남기고 있습니다. (설정 파일: ${config_file}, 최근 기록 로그 파일: ${log_files_check}/${total_log_files}개)"
        command_result="${raw_output}"
    else
        status="취약"
        diagnosis_result="VULNERABLE"
        local reason=""
        if [ "$service_active" = false ]; then
            reason="${syslog_service} 서비스 비활성화"
        fi
        if [ "$config_lines" -eq 0 ]; then
            reason="${reason}${reason:+, }설정 파일 내용 없음"
        fi
        if [ "$log_files_check" -lt 1 ]; then
            reason="${reason}${reason:+, }최근 기록된 로그 파일 없음 - 로그를 남기고 있지 않은 경우 (${log_files_check}/${total_log_files}개)"
        fi
        inspection_summary="시스템 로깅 설정이 부적절합니다: ${reason}. ${syslog_service} 서비스를 활성화하고 로그 기록 정책을 설정하세요."
        command_result="${raw_output}"
    fi

    command_result=$(echo "$command_result" | tr -d '\n\r')

    save_dual_result \
        "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" \
        "${inspection_summary}" "${command_result}" "${command_executed}" \
        "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" \
        "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"

    verify_result_saved "${ITEM_ID}"
    return 0
}

main() {
    show_diagnosis_start "${ITEM_ID}" "${ITEM_NAME}"
    [ "$EUID" -ne 0 ] && { echo "root 권한이 필요합니다."; exit 1; }
    diagnose
    show_diagnosis_complete "${ITEM_ID}" "${diagnosis_result}"
    exit 0
}

main "$@"
