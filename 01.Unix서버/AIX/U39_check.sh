#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.2
# @Last Updated: 2026-04-23
# ============================================================================
# [점검 항목 상세]
# @ID          : U-39
# @Category    : Unix Server
# @Platform    : AIX
# @Severity    : 상
# @Title       : 불필요한 NFS 서비스 비활성화
# @Description : NFS 관련 데몬(nfsd, rpc.mountd, rpcbind) 비활성화 확인
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


ITEM_ID="U-39"
ITEM_NAME="불필요한 NFS 서비스 비활성화"
SEVERITY="상"

# 가이드라인 정보
GUIDELINE_PURPOSE="NFS(Network File System) 서비스는 한 서버의 파일을 많은 서비스 서버들이 공유하여 사용할 때 이용하는 서비스지만 이를 이용한 침해 사고 위험성이 높으므로 사용하지 않는 경우 중지하기 위함"
GUIDELINE_THREAT="NFS 서비스는 서버의 디스크를 클라이언트와 공유하는 서비스로 적정한 보안 설정이 적용되어 있지 않다면 불필요한 파일 공유로 인한 유출 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="불필요한 NFS 서비스 관련 데몬 이 비활성화된 경우"
GUIDELINE_CRITERIA_BAD="불필요한 NFS 서비스 관련 데몬이 활성화된 경우"
GUIDELINE_REMEDIATION="NFS 서비스를 사용하지 않는 경우 서비스 중지 및 비활성화 설정 ※ 로컬 서버에 마운트되어 있는 디렉터리 제거 및 공유 디렉터리 제거 후 서비스 중지 가능"

# ============================================================================
# 진단 함수
# ============================================================================

diagnose() {

    diagnosis_result="unknown"
    local status="미진단"
    local inspection_summary=""
    local command_result=""
    local command_executed=""
    local newline=$'\n'

    local is_secure=true
    local active_services=()
    local service_status=""

    # 1) AIX lssrc로 NFS 서비스 상태 확인
    local nfs_subsystems=("nfs" "nfsd" "rpc.mountd" "rpcbind" "portmap")
    for svc in "${nfs_subsystems[@]}"; do
        local state=$(lssrc -s "$svc" 2>/dev/null | grep -E "$svc" | awk '{print $NF}' || echo "inoperative")
        if [ "$state" = "active" ]; then
            is_secure=false
            active_services+=("${svc} (active)")
        fi
        service_status="${service_status}${svc}: ${state}\\n"
    done || true

    # 2) NFS 프로세스 확인
    local nfs_procs=$(ps -ef 2>/dev/null | grep -Ei "nfsd|mountd|rpcbind|portmap" | grep -v grep || echo "")
    if [ -n "$nfs_procs" ]; then
        is_secure=false
        local proc_names=$(echo "$nfs_procs" | awk '{print $8}' | sort -u | xargs)
        active_services+=("NFS 프로세스: ${proc_names}")
    fi

    # 3) NFS 포트 확인 (2049)
    local nfs_port=$(netstat -an 2>/dev/null | grep "\.2049 " | grep LISTEN || echo "")
    if [ -n "$nfs_port" ]; then
        is_secure=false
        active_services+=("NFS 포트 2049 활성화")
    fi

    # 4) 공유 디렉토리 확인
    local exports=""
    if [ -f /etc/exports ]; then
        exports=$(grep -v "^#" /etc/exports 2>/dev/null | grep -v "^$" || echo "")
        if [ -n "$exports" ]; then
            is_secure=false
            active_services+=("/etc/exports에 공유 설정 존재")
        fi
    fi

    # 명령어 결과 수집
    local lssrc_raw=""
    for svc in nfs nfsd rpcbind; do
        lssrc_raw="${lssrc_raw}$(lssrc -s "$svc" 2>/dev/null || echo "${svc}: service not found")${newline}"
    done

    # 최종 판정
    if [ "$is_secure" = true ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="NFS 관련 서비스가 비활성화되어 있습니다."
        command_result="[Command: lssrc]${newline}${lssrc_raw}${newline}[Command: cat /etc/exports]${newline}${exports:-no exports configured}"
        command_executed="lssrc -s nfs; lssrc -s nfsd; lssrc -s rpcbind; cat /etc/exports"
    else
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="NFS 관련 서비스가 활성화되어 있습니다: ${active_services[*]}"
        command_result="[Command: lssrc]${newline}${lssrc_raw}${newline}[Command: cat /etc/exports]${newline}${exports:-no exports configured}"
        command_executed="lssrc -s nfs; lssrc -s nfsd; lssrc -s rpcbind; cat /etc/exports"
    fi

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

    verify_result_saved "${ITEM_ID}"

    return 0
}

# ============================================================================
# 메인 실행
# ============================================================================

main() {
    show_diagnosis_start "${ITEM_ID}" "${ITEM_NAME}"

    check_disk_space

    diagnose

    show_diagnosis_complete "${ITEM_ID}" "${diagnosis_result:-UNKNOWN}"

    return 0
}

# 스크립트 직접 실행 시에만 진단 수행
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi
