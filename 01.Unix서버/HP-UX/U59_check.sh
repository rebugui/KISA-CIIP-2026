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
# @Platform    : HP-UX
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

    # 1) SNMP 서비스 설치 여부 확인 (net-snmp + HP-UX 기본 에이전트 snmpdm/설정 파일)
    if command -v snmpd >/dev/null 2>&1 || command -v snmpdm >/dev/null 2>&1 || [ -f /etc/snmp/snmpd.conf ] || [ -f /etc/snmpd.conf ] || [ -f /etc/SnmpAgent.d/snmpd.conf ]; then
        snmpd_installed=true
    fi

    # 2) SNMP 서비스 실행 여부 확인
    #    HP-UX 네이티브 에이전트는 /sbin/init.d/snmpd가 아닌 SnmpMaster(snmpdm)로 동작하므로 ps 폴백 필수
    if [ "$snmpd_installed" = true ]; then
        if [ -f /sbin/init.d/snmpd ]; then
            local service_status=$(/sbin/init.d/snmpd status 2>/dev/null | grep -q "running" 2>/dev/null && echo "active" || echo "inactive")
            if [ "$service_status" = "active" ] || [ "$service_status" = "running" ]; then
                snmp_running=true
            fi
        fi
        if [ "$snmp_running" = false ]; then
            if ps -ef 2>/dev/null | grep -E '[s]nmpdm|[s]nmpd([[:space:]]|$)' >/dev/null 2>&1; then
                snmp_running=true
            fi
        fi
    fi

    if [ "$snmpd_installed" = false ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="SNMP 서비스가 설치되지 않음"
        local snmp_not_installed=$(which snmpd 2>/dev/null; ls /etc/snmp/snmpd.conf 2>/dev/null || echo "SNMP not installed")
        command_result="${snmp_not_installed}"
        command_executed="which snmpd; ls /etc/snmp/snmpd.conf 2>/dev/null"
    elif [ "$snmp_running" = false ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="SNMP 서비스가 설치되어 있으나 비활성화됨"
        local snmp_inactive=$(/sbin/init.d/snmpd status 2>/dev/null | head -2 || echo "SNMP installed but inactive")
        command_result="${snmp_inactive}"
        command_executed="/sbin/init.d/snmpd status 2>/dev/null; ps -ef | grep -E 'snmpdm|snmpd'"
    else
        # 3) SNMP 버전 설정 확인 (net-snmp snmpd.conf + HP-UX 기본 에이전트 설정)
        local snmp_confs="/etc/snmp/snmpd.conf /etc/snmpd.conf /etc/SnmpAgent.d/snmpd.conf"
        local found_confs=""
        local v1v2c_evidence=""
        local v3_evidence=""
        local conf=""
        local v1_hit=""
        local v3_hit=""
        for conf in $snmp_confs; do
            if [ -f "$conf" ]; then
                found_confs="${found_confs}${conf} "
                v1_hit=""
                v3_hit=""
                if [ "$conf" = "/etc/snmp/snmpd.conf" ]; then
                    # net-snmp: com2sec/rocommunity/rwcommunity/community = v1/v2c
                    v1_hit=$(grep -Ei '^[[:space:]]*(com2sec|rocommunity6?|rwcommunity6?|community)[[:space:]]' "$conf" 2>/dev/null | head -10 || true)
                    v3_hit=$(grep -Ei '^[[:space:]]*(createUser|rouser|rwuser)[[:space:]]' "$conf" 2>/dev/null | head -10 || true)
                else
                    # HP-UX 기본 에이전트: get-community-name/set-community-name = v1/v2c 커뮤니티
                    v1_hit=$(grep -Ei '^[[:space:]]*(get-community-name|set-community-name)[[:space:]]*:' "$conf" 2>/dev/null | head -10 || true)
                fi
                if [ -n "$v1_hit" ]; then
                    v1v2c_evidence="${v1v2c_evidence}[${conf}]${newline}${v1_hit}${newline}"
                    config_details="${config_details}${conf}: v1/v2c 커뮤니티 설정 발견; "
                fi
                if [ -n "$v3_hit" ]; then
                    v3_evidence="${v3_evidence}[${conf}]${newline}${v3_hit}${newline}"
                fi
            fi
        done

        if [ -z "$found_confs" ]; then
            diagnosis_result="MANUAL"
            status="수동진단"
            inspection_summary="SNMP 설정 파일을 찾을 수 없음 (수동 확인 필요)"
            local no_conf=$(ls /etc/snmp/snmpd.conf /etc/snmpd.conf /etc/SnmpAgent.d/snmpd.conf 2>/dev/null || echo "No SNMP config files")
            command_result="${no_conf}"
            command_executed="ls /etc/snmp/snmpd.conf /etc/snmpd.conf /etc/SnmpAgent.d/snmpd.conf 2>/dev/null"
        elif [ -n "$v1v2c_evidence" ]; then
            diagnosis_result="VULNERABLE"
            status="취약"
            if [ -n "$v3_evidence" ]; then
                inspection_summary="SNMP v1/v2c가 활성화됨 (v3와 공존): ${config_details}"
            else
                inspection_summary="SNMP v1/v2c 사용 중 (v3 권장): ${config_details}"
            fi
            command_result="[v1/v2c community 설정]${newline}${v1v2c_evidence}"
            command_executed="grep -E 'com2sec|rocommunity|rwcommunity|community|get-community-name|set-community-name' ${found_confs}"
        elif [ -n "$v3_evidence" ]; then
            diagnosis_result="GOOD"
            status="양호"
            inspection_summary="SNMP v3만 사용 중 (보안 설정 적절)"
            command_result="[v3 설정]${newline}${v3_evidence}"
            command_executed="grep -E 'createUser|rouser|rwuser' ${found_confs}"
        else
            diagnosis_result="MANUAL"
            status="수동진단"
            inspection_summary="SNMP 버전 설정을 자동으로 확인할 수 없음 (수동 확인 필요): ${found_confs}"
            local snmp_unknown=$(head -10 ${found_confs} 2>/dev/null || echo "Config not readable")
            command_result="SNMP version: unknown${newline}${snmp_unknown}"
            command_executed="head -10 ${found_confs}"
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
