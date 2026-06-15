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
# @Platform    : HP-UX
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
    # 가이드라인 명시 불필요 RPC 서비스의 활성화 여부 확인 (inetd.conf + 프로세스)

    local is_secure=true
    local probe_available=false
    local service_status=""
    local active_services=()

    # 가이드라인(U-42) 명시 불필요 RPC 서비스 목록 (15종)
    local rpc_service_list=("rpc.cmsd" "rpc.ttdbserverd" "sadmind" "rusersd" "walld" "sprayd" "rstatd" "rpc.nisd" "rexd" "rpc.pcnfsd" "rpc.statd" "rpc.ypupdated" "rpc.rquotad" "kcms_server" "cachefsd")
    # 데몬명(rpc.*)과 inetd 서비스명 표기를 모두 매칭 (rwalld→walld, ttdbserverd→ttdbserver 포함)
    local rpc_pattern='cmsd|ttdbserver|sadmind|rusersd|walld|sprayd|rstatd|statd|nisd|rexd|pcnfsd|ypupdated|rquotad|kcms_server|cachefsd'

    # 1) /etc/inetd.conf 내 불필요 RPC 서비스 확인 (비주석 항목)
    if [ -f /etc/inetd.conf ]; then
        probe_available=true
        local inetd_entries=$(grep -Ei "$rpc_pattern" /etc/inetd.conf 2>/dev/null | grep -Ev '^[[:space:]]*#' || echo "")
        if [ -n "$inetd_entries" ]; then
            is_secure=false
            local inetd_names=$(echo "$inetd_entries" | awk '{print $1}' | sort -u | xargs)
            active_services+=("inetd.conf: ${inetd_names}")
            service_status="${service_status}inetd.conf에서 불필요 RPC 서비스 활성화됨\\n"
        else
            service_status="${service_status}inetd.conf: 불필요 RPC 서비스 항목 없음\\n"
        fi
    else
        service_status="${service_status}/etc/inetd.conf 파일 없음\\n"
    fi

    # 2) 불필요 RPC 프로세스 확인
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
    command_executed="grep -Ei '${rpc_pattern}' /etc/inetd.conf; ps -ef | grep -Ei '${rpc_pattern}'"

    if [ "$probe_available" = false ]; then
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="inetd.conf와 ps를 확인할 수 없어 불필요한 RPC 서비스 상태를 수동으로 점검해야 합니다."
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
