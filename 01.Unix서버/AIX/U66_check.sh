#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : U-66
# @Category    : Unix Server
# @Platform    : AIX
# @Severity    : 중
# @Title       : 정책에 따른 시스템로깅 설정
# @Description : rsyslog/syslog-ng 설정 및 로그 기록 확인
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


ITEM_ID="U-66"
ITEM_NAME="정책에 따른 시스템로깅 설정"
SEVERITY="중"

# 가이드라인 정보
GUIDELINE_PURPOSE="보안 사고 발생 시 원인 파악 및 각종 침해 사실 확인을 하기 위함"
GUIDELINE_THREAT="로깅 설정이 되어 있지 않을 경우, 원인 규명이 어려우며 법적 대응을 위한 충분한 증거로 사용할 수 없는 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="로그 기록 정책이 보안 정책에 따라 설정되어 수립되어 있으며, 로그를 남기고 있는 경우"
GUIDELINE_CRITERIA_BAD="로그 기록 정책 미수립 또는 정책에 따라 설정되어 있지 않거나, 로그를 남기고 있지 않은 경우"
GUIDELINE_REMEDIATION="로그 기록 정책을 수립하고, 정책에 따라(r)syslog.conf 파일을 설정"

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
    # 1) syslog 데몬 활성화 확인 (rsyslog, syslog-ng, syslog)
    # 2) 로그 설정 파일 존재 및 설정 확인
    # 3) 실제 로그 파일 기록 확인

    local syslog_service=""
    local config_file=""
    local service_active=false
    local log_files_check=0
    local total_log_files=0

    # 1) syslog 서비스 확인
    if lssrc -s rsyslog 2>/dev/null | grep -q "active" >/dev/null 2>&1; then
        syslog_service="rsyslog"
        service_active=true
        config_file="/etc/rsyslog.conf"
    elif lssrc -s syslog-ng 2>/dev/null | grep -q "active" >/dev/null 2>&1; then
        syslog_service="syslog-ng"
        service_active=true
        config_file="/etc/syslog-ng/syslog-ng.conf"
    elif lssrc -s sysklogd 2>/dev/null | grep -q "active" >/dev/null 2>&1; then
        syslog_service="sysklogd"
        service_active=true
        config_file="/etc/syslog.conf"
    elif lssrc -s syslogd 2>/dev/null | grep -q "active" >/dev/null 2>&1; then
        # AIX 기본 syslogd (SRC 관리)
        syslog_service="syslogd"
        service_active=true
        config_file="/etc/syslog.conf"
    elif ps -ef 2>/dev/null | grep syslogd | grep -v grep >/dev/null 2>&1; then
        # SRC 미등록 syslogd 프로세스 확인 (fallback)
        syslog_service="syslogd"
        service_active=true
        config_file="/etc/syslog.conf"
    elif [ -f "/etc/rsyslog.conf" ]; then
        syslog_service="rsyslog"
        config_file="/etc/rsyslog.conf"
        # rsyslog 설치되어 있지만 비활성화된 경우
        service_active=false
    elif [ -f "/etc/syslog.conf" ]; then
        # AIX 기본 syslogd가 설치(설정 파일 존재)되어 있으나 데몬이 중지된 경우 → 취약 판정 경로로 진행
        syslog_service="syslogd"
        config_file="/etc/syslog.conf"
        service_active=false
    else
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="syslog 서비스(rsyslog, syslog-ng)를 찾을 수 없습니다"
        local lssrc_out=$(lssrc -s syslogd 2>/dev/null || echo "syslog service not found")
        local ss_out=$(ss -tuln | grep ":514 " 2>/dev/null || echo "Port 514 not listening")
        command_result="[Command: lssrc -s syslogd]${newline}${lssrc_out}${newline}${newline}[Command: ss -tuln | grep :514]${newline}${ss_out}"
        command_executed="lssrc -a rsyslog; lssrc -a syslog-ng"

        echo ""
      #  echo "진단 결과: ${status}"
      # echo "판정: ${diagnosis_result}"
      # echo "설명: ${inspection_summary}"
        echo ""

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
    fi

    # 2) 설정 파일 확인
    if [ ! -f "$config_file" ]; then
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="${syslog_service} 설정 파일(${config_file})이 존재하지 않습니다"
        local find_syslog=$(find /etc -name 'syslog.conf' 2>/dev/null | head -5 || echo "syslog.conf not found")
        command_result="[Command: find /etc -name 'syslog.conf']${newline}${find_syslog}"
        command_executed="ls -l ${config_file}"
    else
        # 설정 파일 내용 확인 (주석 제외한 라인 수)
        local config_lines=$(grep -v "^#" "$config_file" | grep -v "^[[:space:]]*$" | wc -l)

        # 3) 주요 로그 파일 기록 확인 (표준 경로 + 설정 파일에 정의된 로그 경로)
        local critical_logs=("/var/log/syslog" "/var/log/messages" "/var/log/auth.log" "/var/log/secure" "/var/log/kern.log")

        local configured_logs
        # AIX 'rotate size ... files N' 접미사가 있어도 로그 경로를 추출하도록 selector 이후 첫 '/' 토큰 사용
        configured_logs=$(grep -v "^#" "$config_file" 2>/dev/null | awk '{for(i=2;i<=NF;i++){t=$i; sub(/^-/,"",t); if(t ~ /^\//){print t; break}}}' | grep -v "^/dev/" | sort -u || true)
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
                # 로그 파일이 존재하고 최근 기록이 있는지 확인 (AIX: stat -c 미지원, perl 사용)
                local last_mod=$(perl -e 'print((stat(shift))[9])' "$log_file" 2>/dev/null || echo "0")
                [ -n "$last_mod" ] || last_mod=0
                local current_time=$(perl -e 'print time' 2>/dev/null || date +%s 2>/dev/null || echo "0")
                [ -n "$current_time" ] || current_time=0
                local days_since_mod=$(( (current_time - last_mod) / 86400 ))

                if [ "$last_mod" -gt 0 ] && [ "$current_time" -gt 0 ] && [ "$days_since_mod" -le 7 ]; then
                    ((log_files_check++)) || true
                fi
            fi
        done || true

        command_executed="lssrc -a ${syslog_service}; ls -l /var/log/*.log | head -10"

        # 최종 판정 (양호: 데몬 활성 + 설정 존재 + 실제 로그를 남기고 있는 경우 모두 충족)
        if [ "$service_active" = true ] && [ "$config_lines" -gt 0 ] && [ "$log_files_check" -ge 1 ]; then
            diagnosis_result="GOOD"
            status="양호"
            inspection_summary="${syslog_service} 서비스가 활성화되어 있고, 로그 기록 정책이 설정되어 있으며, 로그를 남기고 있습니다. (설정 파일: ${config_file}, 최근 기록 로그 파일: ${log_files_check}/${total_log_files}개)"
            local cat_conf=$(cat "$config_file" 2>/dev/null | head -30 || echo "config not readable")
            local ls_log=$(ls -la /var/log/*.log 2>/dev/null | head -20 || echo "No log files")
            command_result="[Command: cat ${config_file}]${newline}${cat_conf}${newline}${newline}[Command: ls -la /var/log/*.log]${newline}${ls_log}"
        else
            diagnosis_result="VULNERABLE"
            status="취약"
            local reason=""
            if [ "$service_active" = false ]; then
                reason="${syslog_service} 서비스 비활성화"
            fi
            if [ "$config_lines" -eq 0 ]; then
                if [ -n "$reason" ]; then
                    reason="${reason}, "
                fi
                reason="${reason}설정 파일 내용 없음"
            fi
            if [ "$log_files_check" -lt 1 ]; then
                if [ -n "$reason" ]; then
                    reason="${reason}, "
                fi
                reason="${reason}최근 기록된 로그 파일 없음 - 로그를 남기고 있지 않은 경우 (${log_files_check}/${total_log_files}개)"
            fi
            inspection_summary="시스템 로깅 설정이 부적절합니다: ${reason}. ${syslog_service} 서비스를 활성화하고 로그 기록 정책을 설정하세요"
            command_result="${reason}"
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
