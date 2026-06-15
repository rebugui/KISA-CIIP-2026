#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-28
# ============================================================================
# [점검 항목 상세]
# @ID          : U-42
# @Category    : UNIX > 3. 서비스 관리
# @Platform    : RedHat
# @Severity    : 상
# @Title       : 불필요한 RPC 서비스 비활성화
# @Description : 취약점이 있는 불필요한 RPC 서비스의 활성화 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/metadata_parser.sh"

ITEM_ID="U-42"
ITEM_NAME="불필요한 RPC 서비스 비활성화"
SEVERITY="상"

# 가이드라인 정보 (PDF 내용 반영)
GUIDELINE_PURPOSE="많은 취약점(버퍼 오버 플로우, DoS, 원격 실행 등)이 존재하는 RPC 서비스를 비활성화하여 시스템의 보안성을 높이기 위함"
GUIDELINE_THREAT="RPC 서비스의 취약점을 통해 비인가자가 root 권한 획득 및 각종 공격을 시도할 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="불필요한 RPC 서비스가 비활성화된 경우"
GUIDELINE_CRITERIA_BAD="불필요한 RPC 서비스가 활성화된 경우"
GUIDELINE_REMEDIATION="불필요한 RPC 서비스 중지 및 비활성화 설정"

diagnose() {
    local status="양호"
    diagnosis_result="GOOD"
    local inspection_summary="불필요한 RPC 서비스가 비활성화되어 있습니다."
    local command_result=""
    local command_executed=""
    local newline=$'\n'

    # 가이드라인(U-42) 명시 불필요 RPC 서비스 목록 (15종)
    local rpc_service_list=("rpc.cmsd" "rpc.ttdbserverd" "sadmind" "rusersd" "walld" "sprayd" "rstatd" "rpc.nisd" "rexd" "rpc.pcnfsd" "rpc.statd" "rpc.ypupdated" "rpc.rquotad" "kcms_server" "cachefsd")
    # 데몬명(rpc.*)/inetd 서비스명/systemd 유닛명 표기를 모두 매칭
    local rpc_pattern='cmsd|ttdbserver|sadmind|rusersd|walld|sprayd|rstatd|statd|nisd|rexd|pcnfsd|ypupdated|rquotad|kcms_server|cachefsd'

    local is_vulnerable=false
    local probe_available=false
    local findings=""

    # 1. 불필요 RPC 프로세스 확인
    if command -v ps >/dev/null 2>&1; then
        probe_available=true
        local rpc_procs=$(ps -ef 2>/dev/null | grep -Ei "$rpc_pattern" | grep -v grep || echo "")
        if [ -n "$rpc_procs" ]; then
            is_vulnerable=true
            findings="${findings}[프로세스] $(echo "$rpc_procs" | awk '{print $8}' | sort -u | xargs)${newline}"
        fi
    fi

    # 2. /etc/inetd.conf 확인 (비주석 항목)
    if [ -f /etc/inetd.conf ]; then
        probe_available=true
        local inetd_entries=$(grep -Ei "$rpc_pattern" /etc/inetd.conf 2>/dev/null | grep -Ev '^[[:space:]]*#' || echo "")
        if [ -n "$inetd_entries" ]; then
            is_vulnerable=true
            findings="${findings}[inetd.conf] $(echo "$inetd_entries" | awk '{print $1}' | sort -u | xargs)${newline}"
        fi
    fi

    # 3. xinetd 확인 (disable = no 인 불필요 RPC 서비스)
    if [ -d /etc/xinetd.d ]; then
        probe_available=true
        local xfile
        for xfile in /etc/xinetd.d/*; do
            [ -f "$xfile" ] || continue
            basename "$xfile" | grep -Eqi "$rpc_pattern" || continue
            if grep -Eqi '^[[:space:]]*disable[[:space:]]*=[[:space:]]*no' "$xfile" 2>/dev/null; then
                is_vulnerable=true
                findings="${findings}[xinetd] $(basename "$xfile") (disable = no)${newline}"
            fi
        done
    fi

    # 4. systemd 실행 중 서비스 확인 (rpcbind 자체는 점검 대상 아님)
    if command -v systemctl >/dev/null 2>&1; then
        probe_available=true
        local systemd_units=$(systemctl list-units --type=service --state=running 2>/dev/null | grep -Ei "$rpc_pattern" || echo "")
        if [ -n "$systemd_units" ]; then
            is_vulnerable=true
            findings="${findings}[systemd] $(echo "$systemd_units" | awk '{print $1}' | xargs)${newline}"
        fi
    fi

    command_executed="ps -ef | grep -Ei '${rpc_pattern}'; grep -Ei '${rpc_pattern}' /etc/inetd.conf; grep -ri 'disable' /etc/xinetd.d; systemctl list-units --type=service --state=running | grep -Ei '${rpc_pattern}'"

    # 판정 로직
    if [ "$probe_available" = false ]; then
        status="수동진단"
        diagnosis_result="MANUAL"
        inspection_summary="ps/inetd/xinetd/systemctl을 사용할 수 없어 불필요한 RPC 서비스 상태를 수동으로 점검해야 합니다."
        command_result="점검 대상: ${rpc_service_list[*]}${newline}점검 수단(ps, inetd.conf, xinetd.d, systemctl)을 사용할 수 없습니다."
    elif [ "$is_vulnerable" = true ]; then
        status="취약"
        diagnosis_result="VULNERABLE"
        inspection_summary="보안에 취약한 RPC 서비스가 활성화되어 있습니다."
        command_result="점검 대상: ${rpc_service_list[*]}${newline}${findings}"
    else
        command_result="점검 대상: ${rpc_service_list[*]}${newline}불필요한 RPC 서비스가 탐지되지 않았습니다."
    fi

    save_dual_result \
        "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" \
        "${inspection_summary}" "${command_result}" "${command_executed}" \
        "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" \
        "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
    
    return 0
}

main() { [ "$EUID" -ne 0 ] && exit 1; diagnose; }
main "$@"
