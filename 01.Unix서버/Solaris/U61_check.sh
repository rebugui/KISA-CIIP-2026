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
    # SNMP 접근 제어 설정 확인 (community 라인의 소스 IP 제한 기반 판정)
    # Solaris: net-snmp(/etc/net-snmp/snmp/snmpd.conf), SMA(/etc/sma/snmp/snmpd.conf) 경로 포함

    local snmpd_installed=false
    local snmp_running=false
    local conf_candidates="/etc/net-snmp/snmp/snmpd.conf /etc/sma/snmp/snmpd.conf /etc/snmp/snmpd.conf"
    local readable_confs=""
    local unreadable_confs=""
    local unrestricted_entries=""
    local restricted_entries=""
    local v3_entries=""
    local raw_output=""
    local active_lines=""
    local conf=""
    local line=""
    local keyword=""
    local src=""

    # 1) SNMP 설치/구동 여부 확인
    if command -v snmpd >/dev/null 2>&1; then
        snmpd_installed=true
    fi
    if ps -ef 2>/dev/null | grep -i "snmpd" | grep -v "grep" >/dev/null 2>&1; then
        snmp_running=true
        snmpd_installed=true
    fi
    for conf in ${conf_candidates}; do
        if [ -f "$conf" ]; then
            snmpd_installed=true
            if [ -r "$conf" ]; then
                readable_confs="${readable_confs}${conf} "
            else
                unreadable_confs="${unreadable_confs}${conf} "
            fi
        fi
    done

    if [ "$snmpd_installed" = false ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="SNMP 서비스가 설치되지 않음"
        command_result="SNMP: [not installed]"
        command_executed="command -v snmpd; ls ${conf_candidates} 2>/dev/null"
    elif [ -z "$readable_confs" ]; then
        if [ "$snmp_running" = true ]; then
            diagnosis_result="MANUAL"
            status="수동진단"
            inspection_summary="snmpd 프로세스가 구동 중이나 SNMP 설정 파일을 읽을 수 없어 접근 통제 설정의 수동 확인이 필요함"
            raw_output=$(ps -ef 2>/dev/null | grep -i "snmpd" | grep -v "grep" | head -5 || echo "snmpd process detected")
            command_result="[Unreadable conf: ${unreadable_confs:-not found}]${newline}${raw_output}"
            command_executed="ps -ef | grep snmpd; ls -l ${conf_candidates}"
        else
            diagnosis_result="GOOD"
            status="양호"
            inspection_summary="snmpd가 구동 중이지 않고 읽을 수 있는 SNMP 설정 파일이 없음 (SNMP 서비스 미사용)"
            command_result="SNMP conf: [not found or unreadable], snmpd process: [not running]"
            command_executed="ps -ef | grep snmpd; ls ${conf_candidates} 2>/dev/null"
        fi
    else
        # 2) community/com2sec 라인의 소스 IP 제한 여부 확인 (net-snmp)
        #    - rocommunity/rwcommunity: 3번째 필드(소스)가 없거나 default/0.0.0.0 → 무제한
        #    - com2sec: 3번째 필드(소스)가 default/0.0.0.0 → 무제한
        for conf in ${readable_confs}; do
            active_lines=$(grep -vE '^[[:space:]]*#' "$conf" 2>/dev/null | grep -vE '^[[:space:]]*$' || true)
            [ -z "$active_lines" ] && continue
            raw_output="${raw_output}[${conf}]${newline}$(echo "$active_lines" | head -20)${newline}"
            while IFS= read -r line; do
                [ -z "$line" ] && continue
                keyword=$(echo "$line" | awk '{print tolower($1)}')
                src=$(echo "$line" | awk '{print $3}')
                case "$keyword" in
                    rocommunity|rwcommunity|rocommunity6|rwcommunity6)
                        case "$src" in
                            ""|default|0.0.0.0|0.0.0.0/0|::|::/0|-V|-s)
                                unrestricted_entries="${unrestricted_entries}${conf}: ${line}${newline}"
                                ;;
                            *)
                                restricted_entries="${restricted_entries}${conf}: ${line}${newline}"
                                ;;
                        esac
                        ;;
                    com2sec|com2sec6)
                        case "$src" in
                            ""|default|0.0.0.0|0.0.0.0/0|::|::/0)
                                unrestricted_entries="${unrestricted_entries}${conf}: ${line}${newline}"
                                ;;
                            *)
                                restricted_entries="${restricted_entries}${conf}: ${line}${newline}"
                                ;;
                        esac
                        ;;
                    rouser|rwuser)
                        v3_entries="${v3_entries}${conf}: ${line}${newline}"
                        ;;
                esac
            done <<< "$active_lines"
        done

        # 최종 판정: 소스 제한 없는 community = 무제한 접근 → 취약
        if [ -n "$unrestricted_entries" ]; then
            diagnosis_result="VULNERABLE"
            status="취약"
            inspection_summary="소스 IP 제한 없이 모든 호스트의 접근을 허용하는 SNMP community 설정이 존재함"
            command_result="[무제한 허용 설정]${newline}${unrestricted_entries%${newline}}"
            command_executed="grep -vE '^[[:space:]]*#' ${conf_candidates} | grep -Ei 'rocommunity|rwcommunity|com2sec'"
        elif [ -n "$restricted_entries" ]; then
            diagnosis_result="GOOD"
            status="양호"
            inspection_summary="SNMP community가 특정 호스트/네트워크에서만 접근하도록 소스 IP 제한이 설정됨"
            command_result="[소스 제한 설정]${newline}${restricted_entries%${newline}}"
            command_executed="grep -vE '^[[:space:]]*#' ${conf_candidates} | grep -Ei 'rocommunity|rwcommunity|com2sec'"
        elif [ -n "$v3_entries" ]; then
            diagnosis_result="GOOD"
            status="양호"
            inspection_summary="SNMPv1/v2c community 미설정, SNMPv3 사용자 기반 접근 제어 사용"
            command_result="[SNMPv3 사용자 설정]${newline}${v3_entries%${newline}}"
            command_executed="grep -vE '^[[:space:]]*#' ${conf_candidates} | grep -Ei 'rouser|rwuser'"
        else
            diagnosis_result="GOOD"
            status="양호"
            inspection_summary="SNMP community 설정이 없어 SNMPv1/v2c 무제한 접근이 허용되지 않음"
            command_result="${raw_output:-[no active SNMP configuration]}"
            command_executed="grep -vE '^[[:space:]]*#' ${conf_candidates}"
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
