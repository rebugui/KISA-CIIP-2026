#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : U-58
# @Category    : Unix Server
# @Platform    : Solaris
# @Severity    : 중
# @Title       : 불필요한 SNMP 서비스 구동 점검
# @Description : SNMP 서비스 활성화 여부 확인
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


ITEM_ID="U-58"
ITEM_NAME="불필요한 SNMP 서비스 구동 점검"
SEVERITY="중"

# 가이드라인 정보
GUIDELINE_PURPOSE="불필요한 SNMP 서비스를 비활성화하여 필요 이상의 정보가 노출되는 것을 방지하기 위함"
GUIDELINE_THREAT="SNMP 서비스가 활성화되어 있을 경우, 비인가자가 시스템의 중요 정보를 유출하거나 불법적으로 수정할 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="SNMP 서비스를 사용하지 않는 경우"
GUIDELINE_CRITERIA_BAD="SNMP 서비스를 사용하는 경우"
GUIDELINE_REMEDIATION="SNMP 서비스를 사용하지 않는 경우 서비스 중지 및 비활성화 설정"

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
    # SNMP 서비스 활성화 여부 확인

    local snmp_running=false
    local service_details=""
    local probe_available=false
    local probe_evidence=""

    # Solaris SMF(svcs)로 SNMP/SMA 관련 서비스 상태 확인
    if command -v svcs >/dev/null 2>&1; then
        probe_available=true
        local svcs_out
        svcs_out="$(svcs -H -o state,fmri 2>/dev/null | grep -E 'sma|snmp' || true)"
        if echo "$svcs_out" | grep -q '^online'; then
            snmp_running=true
            service_details="SMF online: $(echo "$svcs_out" | grep '^online' | awk '{print $2}' | tr '\n' ' ')"
        fi
        command_executed="svcs -H -o state,fmri | grep -E 'sma|snmp'"
        probe_evidence="[svcs -H -o state,fmri | grep -E 'sma|snmp']${newline}${svcs_out:-SNMP/SMA 관련 SMF 서비스 없음}"
    fi

    # 프로세스 확인 (백업 방법): snmpd, snmpdx, sma
    if ! $snmp_running && command -v ps >/dev/null 2>&1; then
        probe_available=true
        local ps_out
        ps_out="$(ps -ef 2>/dev/null | grep -E 'snmpd|snmpdx|sma' | grep -v grep || true)"
        if [ -n "$ps_out" ]; then
            snmp_running=true
            service_details="${service_details}SNMP 프로세스(snmpd/snmpdx/sma) 실행 중"
        fi
        command_executed="${command_executed:+${command_executed}; }ps -ef | grep -E 'snmpd|snmpdx|sma' | grep -v grep"
        probe_evidence="${probe_evidence}${probe_evidence:+${newline}}[ps -ef | grep -E 'snmpd|snmpdx|sma' | grep -v grep]${newline}${ps_out:-SNMP 프로세스 없음}"
    fi

    # 레거시 init 스크립트 확인 (보조 증거, Solaris 5.9 이하)
    local legacy_script
    for legacy_script in /etc/init.d/init.sma /etc/init.d/init.snmpdx; do
        if [ -f "$legacy_script" ]; then
            probe_evidence="${probe_evidence}${probe_evidence:+${newline}}[레거시 init 스크립트 존재함] ${legacy_script}"
            command_executed="${command_executed:+${command_executed}; }ls ${legacy_script}"
        fi
    done

    # 최종 판정
    if [ "$snmp_running" = true ]; then
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="SNMP 서비스가 활성화되어 있습니다 (${service_details%, }). 불필요한 경우 서비스를 중지하고 비활성화해야 합니다: svcadm disable <해당 SNMP/SMA FMRI> (예: svcadm disable svc:/application/management/sma:default)"
        command_result="${probe_evidence}"
    elif [ "$probe_available" = true ]; then
        # 점검 명령이 실제로 수행되었고 SNMP 구동 흔적이 없는 경우에만 양호
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="SNMP 서비스가 비활성화되어 있습니다."
        command_result="${probe_evidence:-SNMP service not running}"
    else
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="SNMP 서비스 상태를 확인할 수 없어 수동 점검이 필요합니다 (svcs, ps 명령 사용 불가)"
        command_result="[Cannot determine]${newline}svcs 및 ps 명령을 사용할 수 없어 SNMP 서비스(snmpd/snmpdx/sma) 구동 여부를 확인하지 못했습니다."
        command_executed="${command_executed:-command -v svcs; command -v ps}"
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
