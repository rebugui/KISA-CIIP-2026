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
# @Severity    : 중
# @Title       : NFS 서비스 비활성화
# @Description : nfs-server, rpcbind 서비스 비활성화 확인
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
ITEM_NAME="NFS 서비스 비활성화"
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
    # nfs-server, rpcbind 서비스 상태 확인

    local is_secure=true
    local service_status=""
    local active_services=()

    # 확인할 서비스 목록
    local services=("nfs-server" "rpcbind" "nfs-client.target")

    for service in "${services[@]}"; do
        # HP-UX init.d로 서비스 상태 확인
        if [ -f /sbin/init.d/"$service" ]; then
            local state=$(/sbin/init.d/"$service" status 2>/dev/null | grep -q "running" 2>/dev/null && echo "active" || echo "inactive")

            if [ "$state" = "active" ]; then
                is_secure=false
                active_services+=("${service} (active)")
            fi

            service_status="${service_status}${service}: ${state}\\n"
        fi
    done || true

    # 포트 확인 (NFS: 2049, rpcbind: 111)
    if command -v ss &>/dev/null; then
        local nfs_port=$(ss -tuln | grep ":2049 " || echo "")
        local rpcbind_port=$(ss -tuln | grep ":111 " || echo "")

        if [ -n "$nfs_port" ]; then
            is_secure=false
            service_status="${service_status}NFS 포트 2049 활성화\\n"
        fi
        if [ -n "$rpcbind_port" ]; then
            is_secure=false
            service_status="${service_status}rpcbind 포트 111 활성화\\n"
        fi
    fi

    # 최종 판정
    if [ "$is_secure" = true ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="NFS 관련 서비스 비활성화됨"
        command_result="${service_status}"
        command_executed="/sbin/init.d/nfs-server status 2>/dev/null | grep -q "running" rpcbind; ss -tuln | grep -E ':2049|:111'"
    else
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="NFS 관련 서비스 활성화됨: ${active_services[*]}"
        command_result="${service_status}"
        command_executed="/sbin/init.d/nfs-server status 2>/dev/null | grep -q "running" rpcbind; ss -tuln | grep -E ':2049|:111'"
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
