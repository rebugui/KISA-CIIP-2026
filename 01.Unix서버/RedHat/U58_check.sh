#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-04-20
# ============================================================================
# [점검 항목 상세]
# @ID          : U-58
# @Category    : UNIX > 3. 서비스 관리
# @Platform    : RedHat
# @Severity    : 중
# @Title       : 불필요한 SNMP 서비스 구동 점검
# @Description : SNMP 서비스 활성화 여부 확인
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/metadata_parser.sh"

ITEM_ID="U-58"
ITEM_NAME="불필요한 SNMP 서비스 구동 점검"
SEVERITY="중"

GUIDELINE_PURPOSE="불필요한 SNMP 서비스를 비활성화하여 필요 이상의 정보가 노출되는 것을 방지하기 위함"
GUIDELINE_THREAT="SNMP 서비스가 활성화되어 있을 경우, 비인가자가 시스템의 중요 정보를 유출하거나 불법적으로 수정할 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="SNMP 서비스를 사용하지 않는 경우"
GUIDELINE_CRITERIA_BAD="SNMP 서비스를 사용하는 경우"
GUIDELINE_REMEDIATION="SNMP 서비스를 사용하지 않는 경우 서비스 중지 및 비활성화 설정"

diagnose() {
    local status="양호"
    diagnosis_result="GOOD"
    local inspection_summary="SNMP 서비스가 비활성화되어 있습니다."
    local command_result=""
    local command_executed="systemctl is-active snmpd; ss -tuln | grep ':161 '; rpm -qa | grep net-snmp"

    local snmp_running=false
    local details=""

    # ==========================================================================
    # 1. systemd 서비스 확인
    # ==========================================================================
    if command -v systemctl >/dev/null 2>&1; then
        if systemctl is-active --quiet snmpd 2>/dev/null; then
            snmp_running=true
            local is_enabled=$(systemctl is-enabled snmpd 2>/dev/null || echo "unknown")
            details="${details}snmpd: active (enabled: ${is_enabled}). "
        fi
    fi

    # ==========================================================================
    # 2. 프로세스 확인 (백업)
    # ==========================================================================
    if [ "$snmp_running" = false ]; then
        local snmp_ps=$(ps aux 2>/dev/null | grep -E "snmpd" | grep -v grep || true)
        if [ -n "$snmp_ps" ]; then
            snmp_running=true
            details="${details}snmpd 프로세스 실행 중. "
        fi
    fi

    # ==========================================================================
    # 3. 포트 161 listening 확인
    # ==========================================================================
    if [ "$snmp_running" = false ]; then
        if command -v ss >/dev/null 2>&1; then
            if ss -tuln 2>/dev/null | grep -q ":161 "; then
                snmp_running=true
                details="${details}포트 161 listening. "
            fi
        elif command -v netstat >/dev/null 2>&1; then
            if netstat -tuln 2>/dev/null | grep -q ":161 "; then
                snmp_running=true
                details="${details}포트 161 listening. "
            fi
        fi
    fi

    # ==========================================================================
    # 4. net-snmp 패키지 설치 확인 (보조 정보)
    # ==========================================================================
    local snmp_installed=""
    if command -v rpm >/dev/null 2>&1; then
        if rpm -qa 2>/dev/null | grep -q "net-snmp"; then
            snmp_installed="net-snmp 패키지 설치됨"
        fi
    fi

    # ==========================================================================
    # 5. 판정
    # ==========================================================================
    if [ "$snmp_running" = true ]; then
        status="취약"
        diagnosis_result="VULNERABLE"
        inspection_summary="SNMP 서비스가 활성화되어 있습니다. ${details}${snmp_installed:+(${snmp_installed})}"
        command_result="${details}${snmp_installed:+, ${snmp_installed}}"
    else
        status="양호"
        diagnosis_result="GOOD"
        if [ -n "$snmp_installed" ]; then
            inspection_summary="SNMP 서비스는 비활성화되어 있으나 패키지는 설치됨 (${snmp_installed})"
            command_result="SNMP Service: [inactive], Package: [installed]"
        else
            inspection_summary="SNMP 서비스가 설치되어 있지 않거나 비활성화됨"
            command_result="SNMP Service: [inactive or not installed]"
        fi
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
