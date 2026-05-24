#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : U-59
# @Category    : Unix Server
# @Platform    : Debian
# @Severity    : 상
# @Title       : 안전한 SNMP 버전 사용
# @Description : SNMP v3 사용 확인
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


ITEM_ID="U-59"
ITEM_NAME="안전한 SNMP 버전 사용"
SEVERITY="상"

# 가이드라인 정보
GUIDELINE_PURPOSE="안전한 SNMP 버전 사용으로 전송되는 데이터를 보호하기 위함"
GUIDELINE_THREAT="SNMP 버전이 기준보다 낮을 경우, 응답 패킷이 평문으로 전송되어 스니 핑 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="SNMP 서비스를 v3 이상으로 사용하는 경우"
GUIDELINE_CRITERIA_BAD="SNMP 서비스를 v2 이하로 사용하는 경우"
GUIDELINE_REMEDIATION="SNMP 서비스를 사용하지 않는 경우 서비스 중지 및 비활성화 설정 SNMP 서비스 사용 시 SNMP 버전을 v3 이상으로 적용하도록 설정"

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
    # SNMP v3 사용 확인

    local snmpd_installed=false
    local snmp_running=false
    local snmp_version=""
    local config_details=""
    local raw_output=""

    # 1) SNMP 서비스 설치 여부 확인
    if command -v snmpd >/dev/null 2>&1 || [ -f /etc/snmp/snmpd.conf ]; then
        snmpd_installed=true
    fi

    # 2) SNMP 서비스 실행 여부 확인
    if [ "$snmpd_installed" = true ]; then
        if command -v systemctl >/dev/null 2>&1; then
            local service_status=$(systemctl is-active snmpd 2>/dev/null || echo "inactive")
            if [ "$service_status" = "active" ] || [ "$service_status" = "running" ]; then
                snmp_running=true
            fi
        fi
    fi

    if [ "$snmpd_installed" = false ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="SNMP 서비스가 설치되지 않음"
        command_result="SNMP: [not installed]"
        command_executed="which snmpd; ls /etc/snmp/snmpd.conf 2>/dev/null"
    elif [ "$snmp_running" = false ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="SNMP 서비스가 설치되어 있으나 비활성화됨"
        command_result="SNMP: [installed], Service: [inactive]"
        command_executed="systemctl is-active snmpd 2>/dev/null"
    else
        # 3) SNMP 버전 설정 확인 (snmpd.conf)
        local snmp_conf="/etc/snmp/snmpd.conf"
        if [ -f "$snmp_conf" ]; then
            # Capture raw SNMP config
            raw_output=$(cat "$snmp_conf" 2>/dev/null | grep -v "^#" | grep -v "^$" | head -20 || echo "Empty or unreadable")

            # SNMP v1/v2c 사용 여부 확인
            if grep -qi "com2sec" "$snmp_conf" 2>/dev/null; then
                snmp_version="v1/v2c"
                config_details="com2sec 설정 발견 (SNMP v1/v2c 사용)"
            fi

            # SNMP v3 사용 여부 확인
            if grep -qi "createUser\|rouser\|rwuser" "$snmp_conf" 2>/dev/null; then
                # v3 사용자 설정이 있으면 v3 사용 중
                if grep -qi "com2sec" "$snmp_conf" 2>/dev/null; then
                    # v1/v2c와 v3가 모두 설정된 경우
                    diagnosis_result="VULNERABLE"
                    status="취약"
                    inspection_summary="SNMP v1/v2c가 활성화됨 (v3와 공존): ${config_details}"
                    command_result="${raw_output}"
                    command_executed="grep -E 'com2sec|createUser|rouser' ${snmp_conf}"
                else
                    # v3만 사용하는 경우
                    diagnosis_result="GOOD"
                    status="양호"
                    inspection_summary="SNMP v3만 사용 중 (보안 설정 적절)"
                    command_result="${raw_output}"
                    command_executed="grep -E 'createUser|rouser|rwuser' ${snmp_conf}"
                fi
            elif [ -n "$config_details" ]; then
                # v1/v2c만 사용하는 경우
                diagnosis_result="VULNERABLE"
                status="취약"
                inspection_summary="SNMP v1/v2c 사용 중 (v3 권장): ${config_details}"
                command_result="${raw_output}"
                command_executed="grep com2sec ${snmp_conf}"
            else
                # 설정을 찾을 수 없는 경우 (기본 설정일 수 있음)
                diagnosis_result="MANUAL"
                status="수동진단"
                inspection_summary="SNMP 버전 설정을 자동으로 확인할 수 없음 (수동 확인 필요)"
                command_result="${raw_output}"
                command_executed="cat ${snmp_conf}"
            fi
        else
            diagnosis_result="MANUAL"
            status="수동진단"
            inspection_summary="SNMP 설정 파일을 찾을 수 없음 (수동 확인 필요)"
            raw_output=$(ls /etc/snmp/*.conf 2>/dev/null || echo "No SNMP config files found")
            command_result="${raw_output}"
            command_executed="ls /etc/snmp/*.conf 2>/dev/null"
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
