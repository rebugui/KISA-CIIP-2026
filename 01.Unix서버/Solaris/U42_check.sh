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
# @Platform    : Solaris
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
    # 가이드라인 명시 불필요 RPC 서비스의 활성화 여부 확인 (rpc/bind 자체는 점검 대상 아님)

    local is_secure=true
    local probe_available=false
    local service_status=""
    local active_services=()

    # 가이드라인(U-42) 명시 불필요 RPC 서비스 목록 (15종)
    local rpc_service_list=("rpc.cmsd" "rpc.ttdbserverd" "sadmind" "rusersd" "walld" "sprayd" "rstatd" "rpc.nisd" "rexd" "rpc.pcnfsd" "rpc.statd" "rpc.ypupdated" "rpc.rquotad" "kcms_server" "cachefsd")
    # 데몬명(rpc.*)과 inetd 서비스명 표기를 모두 매칭
    local rpc_pattern='cmsd|ttdbserver|sadmind|rusersd|walld|sprayd|rstatd|statd|nisd|rexd|pcnfsd|ypupdated|rquotad|kcms_server|cachefsd'
    # SMF FMRI 표기 매칭 패턴 (firewall 오탐 방지를 위해 wall/rex는 rpc/ 경로로 한정, rpc/bind 미포함)
    local fmri_pattern='rusers|spray|rpc/wall|walld|rstat|rpc/rex|rexd|ttdbserver|cmsd|sadmind|nisplus|pcnfs|nfs/status|statd|nis/update|ypupdated|rquota|kcms|cachefs'

    # 1) inetadm 등록 불필요 RPC 서비스 확인 (enabled 상태)
    if command -v inetadm >/dev/null 2>&1; then
        probe_available=true
        local inetadm_rpc=$(inetadm 2>/dev/null | grep -i enabled | grep -Ei "$fmri_pattern" || echo "")
        if [ -n "$inetadm_rpc" ]; then
            is_secure=false
            active_services+=("inetadm: $(echo "$inetadm_rpc" | awk '{print $NF}' | xargs)")
            service_status="${service_status}inetadm에서 불필요 RPC 서비스 enabled\\n"
        else
            service_status="${service_status}inetadm: 불필요 RPC 서비스 없음\\n"
        fi
    fi

    # 2) SMF 서비스 상태 확인 (online 인 불필요 RPC 서비스)
    if command -v svcs >/dev/null 2>&1; then
        probe_available=true
        local online_rpc=$(svcs -H -o state,fmri 2>/dev/null | awk '$1 == "online"' | grep -Ei "$fmri_pattern" || echo "")
        if [ -n "$online_rpc" ]; then
            is_secure=false
            active_services+=("SMF: $(echo "$online_rpc" | awk '{print $2}' | xargs)")
            service_status="${service_status}SMF에서 불필요 RPC 서비스 online\\n"
        else
            service_status="${service_status}SMF: 불필요 RPC 서비스 online 없음\\n"
        fi
        # 참고: rpc/bind(rpcbind) 상태는 판정에서 제외 (증적용)
        local bind_state=$(svcs -H -o state svc:/network/rpc/bind 2>/dev/null || echo "미설치")
        service_status="${service_status}[참고] network/rpc/bind: ${bind_state} (판정 제외)\\n"
    fi

    # 3) 불필요 RPC 프로세스 확인
    if command -v ps >/dev/null 2>&1; then
        probe_available=true
        local rpc_procs=$(ps -ef 2>/dev/null | grep -Ei "$rpc_pattern" | grep -v grep || echo "")
        if [ -n "$rpc_procs" ]; then
            is_secure=false
            local proc_names=$(echo "$rpc_procs" | awk '{print $8}' | sort -u | xargs)
            active_services+=("프로세스: ${proc_names}")
            service_status="${service_status}불필요 RPC 프로세스 실행 중\\n"
        else
            service_status="${service_status}불필요 RPC 프로세스 없음\\n"
        fi
    fi

    # 최종 판정
    command_result="점검 대상: ${rpc_service_list[*]}\\n${service_status}"
    command_executed="inetadm | grep -Ei '${fmri_pattern}'; svcs -H -o state,fmri | grep -Ei '${fmri_pattern}'; ps -ef | grep -Ei '${rpc_pattern}'"

    if [ "$probe_available" = false ]; then
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="inetadm/svcs/ps를 사용할 수 없어 불필요한 RPC 서비스 상태를 수동으로 점검해야 합니다."
        command_result="점검 대상: ${rpc_service_list[*]}\\n점검 수단(inetadm, svcs, ps)을 사용할 수 없습니다."
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
