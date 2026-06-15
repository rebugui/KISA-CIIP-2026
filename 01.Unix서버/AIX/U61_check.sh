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
# @Platform    : AIX
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
    # SNMP 접근 제어 설정 확인 (AIX)
    # - /etc/snmpdv3.conf : COMMUNITY <name> <secName> <secLevel> <netAddr> <netMask> ... (netAddr 0.0.0.0 = 무제한)
    #                       VACM_GROUP/VACM_VIEW/VACM_ACCESS = 뷰 기반 접근 제어
    # - /etc/snmpd.conf   : community <name> [<requestAddr> [<netmask> ...]] (주소 없음/0.0.0.0 = 무제한)

    local snmpd_installed=false
    local snmp_running=false
    local snmpdv3_conf="/etc/snmpdv3.conf"
    local legacy_conf="/etc/snmpd.conf"
    local readable_confs=""
    local unreadable_confs=""
    local unrestricted_entries=""
    local restricted_entries=""
    local vacm_entries=""
    local raw_output=""
    local active_lines=""
    local conf=""
    local line=""
    local keyword=""
    local net=""

    # 1) SNMP 설치/구동 여부 확인
    if command -v snmpd >/dev/null 2>&1 || command -v snmpdv3ne >/dev/null 2>&1; then
        snmpd_installed=true
    fi
    if ps -ef 2>/dev/null | grep -i "snmpd" | grep -v "grep" >/dev/null 2>&1; then
        snmp_running=true
        snmpd_installed=true
    fi
    for conf in "${snmpdv3_conf}" "${legacy_conf}"; do
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
        command_result="SNMP: [not installed] (${snmpdv3_conf}, ${legacy_conf} 없음, snmpd 미구동)"
        command_executed="ls ${snmpdv3_conf} ${legacy_conf} 2>/dev/null; ps -ef | grep snmpd"
    elif [ -z "$readable_confs" ]; then
        if [ "$snmp_running" = true ]; then
            diagnosis_result="MANUAL"
            status="수동진단"
            inspection_summary="snmpd 프로세스가 구동 중이나 SNMP 설정 파일(${snmpdv3_conf}, ${legacy_conf})을 읽을 수 없어 접근 통제 설정의 수동 확인이 필요함"
            raw_output=$(ps -ef 2>/dev/null | grep -i "snmpd" | grep -v "grep" | head -5 || echo "snmpd process detected")
            command_result="[Unreadable conf: ${unreadable_confs:-not found}]${newline}${raw_output}"
            command_executed="ps -ef | grep snmpd; ls -l ${snmpdv3_conf} ${legacy_conf}"
        else
            diagnosis_result="GOOD"
            status="양호"
            inspection_summary="snmpd가 구동 중이지 않고 읽을 수 있는 SNMP 설정 파일이 없음 (SNMP 서비스 미사용)"
            command_result="SNMP conf: [not found or unreadable], snmpd process: [not running]"
            command_executed="ps -ef | grep snmpd; ls ${snmpdv3_conf} ${legacy_conf} 2>/dev/null"
        fi
    else
        # 2) /etc/snmpdv3.conf: COMMUNITY 네트워크 필드(5번째) 및 VACM 엔트리 확인
        if [ -f "$snmpdv3_conf" ] && [ -r "$snmpdv3_conf" ]; then
            active_lines=$(grep -vE '^[[:space:]]*#' "$snmpdv3_conf" 2>/dev/null | grep -vE '^[[:space:]]*$' || true)
            if [ -n "$active_lines" ]; then
                raw_output="${raw_output}[${snmpdv3_conf}]${newline}$(echo "$active_lines" | head -20)${newline}"
                while IFS= read -r line; do
                    [ -z "$line" ] && continue
                    keyword=$(echo "$line" | awk '{print tolower($1)}')
                    case "$keyword" in
                        community)
                            net=$(echo "$line" | awk '{print $5}')
                            case "$net" in
                                ""|0.0.0.0)
                                    unrestricted_entries="${unrestricted_entries}${snmpdv3_conf}: ${line}${newline}"
                                    ;;
                                *)
                                    restricted_entries="${restricted_entries}${snmpdv3_conf}: ${line}${newline}"
                                    ;;
                            esac
                            ;;
                        vacm_group|vacm_view|vacm_access)
                            vacm_entries="${vacm_entries}${snmpdv3_conf}: ${line}${newline}"
                            ;;
                    esac
                done <<< "$active_lines"
            fi
        fi

        # 3) /etc/snmpd.conf(레거시): community 라인의 요청 주소 필드(3번째) 확인
        if [ -f "$legacy_conf" ] && [ -r "$legacy_conf" ]; then
            active_lines=$(grep -vE '^[[:space:]]*#' "$legacy_conf" 2>/dev/null | grep -vE '^[[:space:]]*$' || true)
            if [ -n "$active_lines" ]; then
                raw_output="${raw_output}[${legacy_conf}]${newline}$(echo "$active_lines" | head -20)${newline}"
                while IFS= read -r line; do
                    [ -z "$line" ] && continue
                    keyword=$(echo "$line" | awk '{print tolower($1)}')
                    if [ "$keyword" = "community" ]; then
                        net=$(echo "$line" | awk '{print $3}')
                        case "$net" in
                            ""|0.0.0.0)
                                unrestricted_entries="${unrestricted_entries}${legacy_conf}: ${line}${newline}"
                                ;;
                            *)
                                restricted_entries="${restricted_entries}${legacy_conf}: ${line}${newline}"
                                ;;
                        esac
                    fi
                done <<< "$active_lines"
            fi
        fi

        # 최종 판정: 네트워크 제한 없는 COMMUNITY/community = 무제한 접근 → 취약
        if [ -n "$unrestricted_entries" ]; then
            diagnosis_result="VULNERABLE"
            status="취약"
            inspection_summary="소스 IP 제한 없이 모든 호스트의 접근을 허용하는 SNMP community 설정이 존재함"
            command_result="[무제한 허용 설정]${newline}${unrestricted_entries%${newline}}"
            command_executed="grep -vE '^[[:space:]]*#' ${snmpdv3_conf} ${legacy_conf} | grep -iE 'community'"
        elif [ -n "$restricted_entries" ]; then
            diagnosis_result="GOOD"
            status="양호"
            inspection_summary="SNMP community가 특정 호스트/네트워크에서만 접근하도록 소스 IP 제한이 설정됨"
            command_result="[소스 제한 설정]${newline}${restricted_entries%${newline}}"
            command_executed="grep -vE '^[[:space:]]*#' ${snmpdv3_conf} ${legacy_conf} | grep -iE 'community'"
        elif [ -n "$vacm_entries" ]; then
            diagnosis_result="GOOD"
            status="양호"
            inspection_summary="community 무제한 허용 없이 VACM(뷰 기반) 접근 제어가 설정됨"
            command_result="[VACM 설정]${newline}${vacm_entries%${newline}}"
            command_executed="grep -vE '^[[:space:]]*#' ${snmpdv3_conf} | grep -iE 'VACM_GROUP|VACM_VIEW|VACM_ACCESS'"
        else
            diagnosis_result="GOOD"
            status="양호"
            inspection_summary="SNMP community 설정이 없어 무제한 접근이 허용되지 않음"
            command_result="${raw_output:-[no active SNMP configuration]}"
            command_executed="grep -vE '^[[:space:]]*#' ${snmpdv3_conf} ${legacy_conf}"
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
