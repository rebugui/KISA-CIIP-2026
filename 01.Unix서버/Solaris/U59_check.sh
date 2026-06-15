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
# @Platform    : Solaris
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

    # 1) SNMP 서비스 설치 여부 확인 (net-snmp + Solaris SMA/Solstice 설정 파일)
    if command -v snmpd >/dev/null 2>&1 || [ -f /etc/snmp/snmpd.conf ] || [ -f /etc/sma/snmp/snmpd.conf ] || [ -f /etc/snmp/conf/snmpd.conf ] || [ -f /etc/net-snmp/snmp/snmpd.conf ]; then
        snmpd_installed=true
    fi

    # 2) SNMP 서비스 실행 여부 확인 (Solaris SMF)
    if [ "$snmpd_installed" = true ]; then
        if svcs -a | grep -i "snmp" | grep -q "online" 2>/dev/null; then
            snmp_running=true
        fi
    fi

    # 1b) 레거시 Solaris SNMP 마스터 에이전트(snmpdx/Solstice) 탐지
    # snmpdx는 v1/v2c 전용(v3 미지원)이므로 동작 중이면 항상 취약.
    # net-snmp(snmpd)가 없어도 snmpdx가 살아 있으면 위 설치 검사에서 누락될 수 있음.
    local snmpdx_active=false
    local snmpdx_evidence=""
    if command -v snmpdx >/dev/null 2>&1 || [ -f /etc/snmp/conf/snmpdx.acl ] || [ -f /etc/snmp/conf/snmpdx.rsrc ]; then
        # SMF 서비스 상태 또는 프로세스 확인
        if svcs -Ho state svc:/application/management/snmpdx:default 2>/dev/null | grep -q online; then
            snmpdx_active=true
            snmpdx_evidence="svc:/application/management/snmpdx: online"
        elif ps -ef 2>/dev/null | grep -q "[s]nmpdx"; then
            snmpdx_active=true
            snmpdx_evidence="snmpdx 프로세스 실행 중"
        fi
    fi

    if [ "$snmpdx_active" = true ]; then
        # snmpdx는 v3를 지원하지 않는 레거시 v1/v2c 전용 에이전트 → 취약
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="레거시 SNMP 마스터 에이전트(snmpdx, v1/v2c 전용) 동작 중 - 안전한 SNMP v3 미사용"
        command_result="[Legacy SNMP]${newline}${snmpdx_evidence}"
        command_executed="svcs -Ho state svc:/application/management/snmpdx:default; ps -ef | grep [s]nmpdx"
    elif [ "$snmpd_installed" = false ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="SNMP 서비스가 설치되지 않음"
        command_result="SNMP: [not installed]"
        command_executed="which snmpd; ls /etc/snmp/snmpd.conf 2>/dev/null"
    elif [ "$snmp_running" = false ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="SNMP 서비스가 설치되어 있으나 비활성화됨"
        command_result="SNMP: installed, [inactive]"
        command_executed="svcs -a | grep -i snmp"
    else
        # 3) SNMP 버전 설정 확인 (net-snmp + Solaris SMA /etc/sma/snmp + Solstice /etc/snmp/conf)
        local snmp_confs="/etc/snmp/snmpd.conf /etc/sma/snmp/snmpd.conf /etc/snmp/conf/snmpd.conf /etc/net-snmp/snmp/snmpd.conf"
        local found_confs=""
        local v1v2c_evidence=""
        local v3_evidence=""
        local conf=""
        local v1_hit=""
        local v3_hit=""
        for conf in $snmp_confs; do
            if [ -f "$conf" ]; then
                found_confs="${found_confs}${conf} "
                # net-snmp/SMA: com2sec/rocommunity/rwcommunity/community,
                # Solstice: read-community/system-group-read-community 등 = v1/v2c
                v1_hit=$(grep -Ei '^[[:space:]]*(com2sec|[a-z-]*community6?)[[:space:]]' "$conf" 2>/dev/null | head -10 || true)
                v3_hit=$(grep -Ei '^[[:space:]]*(createUser|rouser|rwuser)[[:space:]]' "$conf" 2>/dev/null | head -10 || true)
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
            local snmp_check=$(ls /etc/snmp/snmpd.conf /etc/sma/snmp/snmpd.conf /etc/snmp/conf/snmpd.conf /etc/net-snmp/snmp/snmpd.conf 2>/dev/null || echo "No SNMP config found")
            command_result="[Command: ls /etc/snmp/snmpd.conf /etc/sma/snmp/snmpd.conf /etc/snmp/conf/snmpd.conf /etc/net-snmp/snmp/snmpd.conf]${newline}${snmp_check}"
            command_executed="ls /etc/snmp/snmpd.conf /etc/sma/snmp/snmpd.conf /etc/snmp/conf/snmpd.conf /etc/net-snmp/snmp/snmpd.conf 2>/dev/null"
        elif [ -n "$v1v2c_evidence" ]; then
            diagnosis_result="VULNERABLE"
            status="취약"
            if [ -n "$v3_evidence" ]; then
                inspection_summary="SNMP v1/v2c가 활성화됨 (v3와 공존): ${config_details}"
            else
                inspection_summary="SNMP v1/v2c 사용 중 (v3 권장): ${config_details}"
            fi
            command_result="[v1/v2c community 설정]${newline}${v1v2c_evidence}"
            command_executed="grep -E 'com2sec|rocommunity|rwcommunity|community' ${found_confs}"
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
            local snmp_conf_content=$(head -20 ${found_confs} 2>/dev/null || echo "File not found")
            command_result="[Command: head -20 ${found_confs}]${newline}${snmp_conf_content}"
            command_executed="head -20 ${found_confs}"
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
