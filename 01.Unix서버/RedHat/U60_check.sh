#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-04-20
# ============================================================================
# [점검 항목 상세]
# @ID          : U-60
# @Category    : UNIX > 5. 서비스 관리
# @Platform    : RedHat
# @Severity    : 중
# @Title       : SNMP Community String 복잡성 설정
# @Description : 기본 Community String(public, private) 사용 및 복잡성 검증
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/metadata_parser.sh"

ITEM_ID="U-60"
ITEM_NAME="SNMP Community String 복잡성 설정"
SEVERITY="중"

GUIDELINE_PURPOSE="SNMP 서비스의 Community String의 복잡성 설정을 통해 비인가자의 비밀번호 추측 공격에 대비하기 위함"
GUIDELINE_THREAT="Community String에 복잡성 설정이 되어 있지 않을 경우, 비인가자가 비밀번호 추측 공격을 통해 계정 탈취 시 환경 설정 파일 열람 및 수정, 각종 정보 수집, 관리자 권한 획득 등 다양한 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="SNMP Community String 기본값인 'public', 'private'이 아닌 영문자, 숫자 포함 10 자리 이상 또는 영문자, 숫자, 특수 문자 포함 8 자리 이상인 경우 ※ SNMPv3의 경우 별도 인증 기능을 사용하고, 해당 비밀번호가 복잡 도를 만족하는 경우 양호"
GUIDELINE_CRITERIA_BAD="아래의 내용 중 하나라도 해당되는 경우 1. SNMP Community String 기본값인'public', 'private'일 경우 2. 영문자, 숫자 포함 10 자리 미만인 경우 3. 영문자, 숫자, 특수 문자 포함 8 자리 미만인 경우"
GUIDELINE_REMEDIATION="SNMP 서비스를 사용하지 않는 경우 서비스 중지 및 비활성화 설정 SNMP 서비스 사용 시 SNMP Community String 기본값인 'public', 'private'이 아닌 영문자, 숫자 포함 10 자리 이상 또는 영문자, 숫자, 특수 문자 포함 8 자리 이상으로 설정"

diagnose() {
    local status="양호"
    diagnosis_result="GOOD"
    local inspection_summary="SNMP Community String 복잡성 설정이 적절합니다."
    local command_result=""
    local command_executed="grep -v '^#' /etc/snmp/snmpd.conf /etc/snmp/snmpd.local.conf /etc/snmp/snmpd.conf.d/* | grep -iE 'rocommunity|rwcommunity|com2sec'"

    # ==========================================================================
    # 1. SNMP 서비스 실행 여부 확인
    # ==========================================================================
    local snmp_running=false
    if systemctl is-active --quiet snmpd 2>/dev/null; then
        snmp_running=true
    elif ps aux 2>/dev/null | grep -E "snmpd" | grep -v grep >/dev/null 2>&1; then
        snmp_running=true
    fi

    if [ "$snmp_running" = false ]; then
        status="양호"
        diagnosis_result="GOOD"
        inspection_summary="SNMP 서비스가 비활성화되어 있습니다."
        command_result="SNMP Service: [inactive]"

        save_dual_result \
            "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" \
            "${inspection_summary}" "${command_result}" "${command_executed}" \
            "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" \
            "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"

        verify_result_saved "${ITEM_ID}"
        return 0
    fi

    # ==========================================================================
    # 2. snmpd 설정 파일 확인 (snmpd.conf + snmpd.local.conf + conf.d 포함)
    # ==========================================================================
    local conf_files=""
    local cf
    for cf in /etc/snmp/snmpd.conf /etc/snmp/snmpd.local.conf /etc/snmp/snmpd.conf.d/*; do
        [ -f "$cf" ] && conf_files="${conf_files} ${cf}"
    done

    if [ -z "${conf_files// /}" ]; then
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="SNMP 서비스가 실행 중이나 설정 파일을 찾을 수 없습니다."
        command_result="snmpd.conf 파일 없음"

        save_dual_result \
            "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" \
            "${inspection_summary}" "${command_result}" "${command_executed}" \
            "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" \
            "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"

        verify_result_saved "${ITEM_ID}"
        return 0
    fi

    # ==========================================================================
    # 3. Community String 복잡성 검증
    # ==========================================================================
    local issues=""
    local community_lines=$(cat ${conf_files} 2>/dev/null | grep -v "^#" | grep -iE "^[[:space:]]*(rocommunity|rcommunity|rwcommunity|community|com2sec)" || true)

    if [ -z "$community_lines" ]; then
        # SNMPv3만 사용하거나 community 설정 없음
        local v3_lines=$(cat ${conf_files} 2>/dev/null | grep -v "^#" | grep -iE "createUser|rouser|rwuser" || true)
        if [ -n "$v3_lines" ]; then
            # v3 인증 비밀번호 복잡도는 정적 점검 불가 → 수동진단
            status="수동진단"
            diagnosis_result="MANUAL"
            inspection_summary="SNMPv3 인증 모드 사용 중 (Community String 미사용). 인증 비밀번호의 복잡도 충족 여부는 정적 점검이 불가하므로 수동 확인이 필요합니다."
            command_result="SNMPv3 설정 감지됨 (createUser/rouser/rwuser), 점검 파일:${conf_files}"
        else
            inspection_summary="Community String 설정이 없습니다."
            command_result="Community String: [none], 점검 파일:${conf_files}"
        fi
    else
        while IFS= read -r line; do
            # community string 값 추출 (com2sec: 네 번째 필드, 그 외: 두 번째 필드)
            local comm_string
            if echo "$line" | grep -qiE "^[[:space:]]*com2sec"; then
                comm_string=$(echo "$line" | awk '{print $4}' | head -1)
            else
                comm_string=$(echo "$line" | awk '{print $2}' | head -1)
            fi

            if [ -z "$comm_string" ]; then
                continue
            fi

            # 기본값 검사
            if [ "$comm_string" = "public" ] || [ "$comm_string" = "private" ]; then
                issues="${issues}[${comm_string}] 기본 Community String 사용. "
                continue
            fi

            # 복잡성 검증
            local has_alpha=$(echo "$comm_string" | grep -cE '[a-zA-Z]' || true)
            local has_digit=$(echo "$comm_string" | grep -cE '[0-9]' || true)
            local has_special=$(echo "$comm_string" | grep -cE '[^a-zA-Z0-9]' || true)
            local length=${#comm_string}

            # 영문+숫자 10자리 이상 또는 영문+숫자+특수 8자리 이상
            local complex_enough=false
            if [ "$has_alpha" -gt 0 ] && [ "$has_digit" -gt 0 ] && [ "$length" -ge 10 ] && [ "$has_special" -eq 0 ]; then
                complex_enough=true
            fi
            if [ "$has_alpha" -gt 0 ] && [ "$has_digit" -gt 0 ] && [ "$has_special" -gt 0 ] && [ "$length" -ge 8 ]; then
                complex_enough=true
            fi

            if [ "$complex_enough" = false ]; then
                issues="${issues}[${comm_string}] 복잡성 부족 (길이:${length}, 영문:${has_alpha}, 숫자:${has_digit}, 특수:${has_special}). "
            fi
        done <<< "$community_lines"

        if [ -n "$issues" ]; then
            status="취약"
            diagnosis_result="VULNERABLE"
            inspection_summary="Community String 복잡성 기준 미달: ${issues}"
            command_result="${issues}"
        else
            inspection_summary="모든 Community String이 복잡성 기준을 만족합니다."
            command_result="Community Strings: [복잡성 검증 통과]"
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
