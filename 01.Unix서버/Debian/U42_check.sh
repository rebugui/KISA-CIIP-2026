#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : U-42
# @Category    : Unix Server
# @Platform    : Debian
# @Severity    : 상
# @Title       : 불필요한 RPC 서비스 비활성화
# @Description : 취약점이 있는 불필요한 RPC 서비스(rpc.cmsd, rusersd, rexd 등) 비활성화 확인
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


ITEM_ID="U-42"
ITEM_NAME="불필요한 RPC 서비스 비활성화"
SEVERITY="상"

# 가이드라인 정보
GUIDELINE_PURPOSE="많은 취약점(버퍼 오버 플로우, DoS, 원격 실행 등)이 존재하는 RPC 서비스를 비활성화하여 시스템의 보안성을 높이기 위함"
GUIDELINE_THREAT="RPC 서비스의 취약점을 통해 비인가자가 root 권한 획득 및 각종 공격을 시도할 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="불필요한 RPC 서비스가 비활성화된 경우"
GUIDELINE_CRITERIA_BAD="불필요한 RPC 서비스가 활성화된 경우"
GUIDELINE_REMEDIATION="불필요한 RPC 서비스 중지 및 비활성화 설정"

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
    # 가이드라인 명시 불필요 RPC 서비스의 활성화 여부 확인 (rpcbind 자체는 점검 대상 아님)

    local is_secure=true
    local probe_available=false
    local service_status=""
    local active_services=()

    # 가이드라인(U-42) 명시 불필요 RPC 서비스 목록 (15종)
    local rpc_service_list=("rpc.cmsd" "rpc.ttdbserverd" "sadmind" "rusersd" "walld" "sprayd" "rstatd" "rpc.nisd" "rexd" "rpc.pcnfsd" "rpc.statd" "rpc.ypupdated" "rpc.rquotad" "kcms_server" "cachefsd")
    # 데몬명(rpc.*)/inetd 서비스명/systemd 유닛명 표기를 모두 매칭
    local rpc_pattern='cmsd|ttdbserver|sadmind|rusersd|walld|sprayd|rstatd|statd|nisd|rexd|pcnfsd|ypupdated|rquotad|kcms_server|cachefsd'

    # 1) 불필요 RPC 프로세스 확인
    if command -v ps >/dev/null 2>&1; then
        probe_available=true
        local rpc_procs=$(ps -ef 2>/dev/null | grep -Ei "$rpc_pattern" | grep -v grep || echo "")
        if [ -n "$rpc_procs" ]; then
            is_secure=false
            active_services+=("프로세스: $(echo "$rpc_procs" | awk '{print $8}' | sort -u | xargs)")
            service_status="${service_status}불필요 RPC 프로세스 실행 중${newline}"
        else
            service_status="${service_status}불필요 RPC 프로세스 없음${newline}"
        fi
    fi

    # 2) /etc/inetd.conf 확인 (비주석 항목)
    if [ -f /etc/inetd.conf ]; then
        probe_available=true
        local inetd_entries=$(grep -Ei "$rpc_pattern" /etc/inetd.conf 2>/dev/null | grep -Ev '^[[:space:]]*#' || echo "")
        if [ -n "$inetd_entries" ]; then
            is_secure=false
            active_services+=("inetd.conf: $(echo "$inetd_entries" | awk '{print $1}' | sort -u | xargs)")
            service_status="${service_status}inetd.conf에서 불필요 RPC 서비스 활성화됨${newline}"
        else
            service_status="${service_status}inetd.conf: 불필요 RPC 서비스 항목 없음${newline}"
        fi
    fi

    # 2b) /etc/xinetd.d 확인 (disable = yes 명시가 없으면 활성으로 간주)
    if [ -d /etc/xinetd.d ]; then
        probe_available=true
        local xinetd_active=""
        local xf
        for xf in /etc/xinetd.d/*; do
            [ -f "$xf" ] || continue
            # 파일명 또는 server= 지시자가 불필요 RPC 서비스에 해당하는지 확인
            if ! basename "$xf" | grep -qEi "$rpc_pattern" \
                && ! grep -qEi "^[[:space:]]*server[[:space:]]*=.*(${rpc_pattern})" "$xf" 2>/dev/null; then
                continue
            fi
            if ! grep -qEi '^[[:space:]]*disable[[:space:]]*=[[:space:]]*yes' "$xf" 2>/dev/null; then
                xinetd_active="${xinetd_active}$(basename "$xf") "
            fi
        done
        if [ -n "$xinetd_active" ]; then
            is_secure=false
            active_services+=("xinetd.d: ${xinetd_active% }")
            service_status="${service_status}xinetd.d에서 불필요 RPC 서비스 활성화됨 (${xinetd_active% })${newline}"
        else
            service_status="${service_status}xinetd.d: 불필요 RPC 서비스 항목 없음${newline}"
        fi
    fi

    # 3) systemd 실행 중 서비스 확인
    if command -v systemctl >/dev/null 2>&1; then
        probe_available=true
        local systemd_units=$(systemctl list-units --type=service --state=running 2>/dev/null | grep -Ei "$rpc_pattern" || echo "")
        if [ -n "$systemd_units" ]; then
            is_secure=false
            active_services+=("systemd: $(echo "$systemd_units" | awk '{print $1}' | xargs)")
            service_status="${service_status}systemd에서 불필요 RPC 서비스 실행 중${newline}"
        fi
        # 참고: rpcbind 상태는 판정에서 제외 (증적용)
        local rpcbind_state=$(systemctl is-active rpcbind 2>/dev/null || echo "unknown")
        service_status="${service_status}[참고] rpcbind: ${rpcbind_state} (판정 제외)${newline}"
    fi

    # 4) rpcinfo 등록 확인 (목록 내 프로그램만, rexd→rex, rpc.statd→status 등록명 포함)
    if command -v rpcinfo >/dev/null 2>&1; then
        probe_available=true
        local rpc_info=$(rpcinfo -p 2>/dev/null | grep -Ei "${rpc_pattern}|rex|status" || echo "")
        if [ -n "$rpc_info" ]; then
            is_secure=false
            active_services+=("rpcinfo에 불필요 RPC 서비스 등록됨")
            service_status="${service_status}rpcinfo: 불필요 RPC 서비스 등록됨${newline}"
        fi
    fi

    # 최종 판정
    command_result="점검 대상: ${rpc_service_list[*]}${newline}${service_status}"
    command_executed="ps -ef | grep -Ei '${rpc_pattern}'; grep -Ei '${rpc_pattern}' /etc/inetd.conf; systemctl list-units --type=service --state=running | grep -Ei '${rpc_pattern}'; rpcinfo -p"

    if [ "$probe_available" = false ]; then
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="ps/inetd.conf/systemctl/rpcinfo를 사용할 수 없어 불필요한 RPC 서비스 상태를 수동으로 점검해야 합니다."
        command_result="점검 대상: ${rpc_service_list[*]}${newline}점검 수단을 사용할 수 없습니다."
    elif [ "$is_secure" = true ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="불필요한 RPC 서비스가 비활성화되어 있습니다."
    else
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="보안에 취약한 RPC 서비스가 활성화되어 있습니다: ${active_services[*]}"
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
