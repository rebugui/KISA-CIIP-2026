#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : U-61
# @Category    : Unix Server
# @Platform    : Solaris
# @Severity    : 상
# @Title       : SNMP Access Control 설정
# @Description : SNMP 접근 제어 설정 확인
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


ITEM_ID="U-61"
ITEM_NAME="SNMP Access Control 설정"
SEVERITY="상"

# 가이드라인 정보
GUIDELINE_PURPOSE="SNMP 접근 제어 설정을 통해 비인가자의 접근을 차단하기 위함"
GUIDELINE_THREAT="SNMP 서비스에 접근 제어가 설정되어 있지 않을 경우, 비인가자의 접근, 네트워크 정보 유출, 시스템 및 네트워크 설정 변경,DoS 공격 등의 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="SNMP 서비스에 접근 제어 설정이 되어 있는 경우"
GUIDELINE_CRITERIA_BAD="SNMP 서비스에 접근 제어 설정이 되어 있지 않은 경우"
GUIDELINE_REMEDIATION="SNMP 서비스를 사용하지 않는 경우 서비스 중지 및 비활성화 설정 SNMP 서비스 사용 시 SNMP 접근 제어 설정하도록 설정"

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
    # SNMP 접근 제어 설정 확인

    local snmpd_installed=false
    local has_acl=false
    local acl_details=""
    local snmp_conf="/etc/snmp/snmpd.conf"

    # 1) SNMP 설치 여부 확인
    if [ -f "$snmp_conf" ] || command -v snmpd >/dev/null 2>&1; then
        snmpd_installed=true
    fi

    if [ "$snmpd_installed" = false ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="SNMP 서비스가 설치되지 않음"
        local snmp_check=$(ls "${snmp_conf}" 2>/dev/null || echo "SNMP not installed")
        command_result="[Command: ls ${snmp_conf}]\${newline}${snmp_check}"
        command_executed="ls ${snmp_conf} 2>/dev/null"
    elif [ ! -f "$snmp_conf" ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="SNMP 설정 파일이 존재하지 않음"
        local snmp_check=$(ls /etc/snmp/*.conf 2>/dev/null || echo "No SNMP config found")
        command_result="[Command: ls /etc/snmp/*.conf]\${newline}${snmp_check}"
        command_executed="ls /etc/snmp/*.conf 2>/dev/null"
    else
        # 2) SNMP 접근 제어 설정 확인

        # 2-1) VACM (View-based Access Control Model) 설정 확인
        if grep -qiE "view|access.*ronContext|access.*rwuserContext" "$snmp_conf" 2>/dev/null; then
            has_acl=true
            acl_details="${acl_details}VACM 설정 있음, "
        fi

        # 2-2) Community String별 접근 제어 확인
        if grep -qiE "com2sec.*[^0-9.]+|rocommunity|rwcommunity" "$snmp_conf" 2>/dev/null | grep -qE "source"; then
            has_acl=true
            acl_details="${acl_details}Community별 IP 제한 있음, "
        fi

        # 2-3) SNMP 접근 허용 IP/네트워크 확인
        # snmpd.conf에서 소스 IP 제한이 있는지 확인
        local com2sec_lines=$(grep -i "^com2sec" "$snmp_conf" 2>/dev/null | grep -v "^#")
        if [ -n "$com2sec_lines" ]; then
            # "default" (모든 IP)인지 특정 IP/네트워크인지 확인
            if echo "$com2sec_lines" | grep -q "default"; then
                acl_details="${acl_details}com2sec에 'default' 사용 (모든 IP 허용), "
            else
                has_acl=true
                acl_details="${acl_details}com2sec에 IP 제한 설정됨, "
            fi
        fi

        # 2-4) whiltelist/blacklist 설정 확인
        if [ -f /etc/snmp/snmpd.d/custom.conf ]; then
            if grep -qiE "whitelist|blacklist|allow|deny" /etc/snmp/snmpd.d/custom.conf 2>/dev/null; then
                has_acl=true
                acl_details="${acl_details}IP 필터링 설정 있음, "
            fi
        fi

        # 3) Listen 주소 확인
        local listen_lines=$(grep -iE "^agentAddress|listen" "$snmp_conf" 2>/dev/null | grep -v "^#")
        if [ -n "$listen_lines" ]; then
            if echo "$listen_lines" | grep -qE "127.0.0.1|localhost"; then
                has_acl=true
                acl_details="${acl_details}localhost만 listen, "
            elif echo "$listen_lines" | grep -q "0.0.0.0"; then
                acl_details="${acl_details}모든 인터페이스 listen (0.0.0.0), "
            fi
        fi

        # 4) SNMP v3 사용자별 접근 제어 확인
        if grep -qiE "rouser|rwuser" "$snmp_conf" 2>/dev/null; then
            # v3 사용자에 대한 접근 권한 설정 확인
            local rouser_lines=$(grep -iE "^rouser|^rwuser" "$snmp_conf" 2>/dev/null | grep -v "^#")
            if [ -n "$rouser_lines" ]; then
                has_acl=true
                acl_details="${acl_details}v3 사용자 접근 제어 설정됨, "
            fi
        fi

        # 최종 판정
        if [ "$has_acl" = true ]; then
            diagnosis_result="GOOD"
            status="양호"
            inspection_summary="SNMP 접근 제어가 적절하게 설정됨: ${acl_details%, }"
            command_result="${acl_details%, }"
            command_executed="grep -E 'com2sec|rouser|rwuser|agentAddress' ${snmp_conf}"
        else
            diagnosis_result="VULNERABLE"
            status="취약"
            inspection_summary="SNMP 접근 제어가 설정되지 않음 (모든 접근 허용 가능): ${acl_details:-접근 제어 없음}"
            command_result="${acl_details:-[no access control]}"
            command_executed="grep -v '^#' ${snmp_conf} | grep -E 'com2sec|rouuser|rwuser|agentAddress'"
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
