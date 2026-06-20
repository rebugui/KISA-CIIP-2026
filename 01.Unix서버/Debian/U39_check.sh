#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : U-39
# @Category    : Unix Server
# @Platform    : Debian
# @Severity    : 상
# @Title       : 불필요한 NFS 서비스 비활성화
# @Description : NFS 서비스 비활성화 여부 확인
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

# 진단 수행
diagnose() {


    diagnosis_result="unknown"
    local status="미진단"
    local inspection_summary=""
    local command_result=""
    local command_executed=""
    local newline=$'\n'

    # 진단 로직 구현
    # NFS 서비스 비활성화 여부 점검
    # 가이드라인: 불필요한 NFS 서비스 관련 데몬이 비활성화된 경우 양호

    local nfs_active=false
    local active_services=""
    local raw_output=""

    # NFS 관련 서비스 목록
    # 참고: rpcbind/portmapper는 NIS/ypbind/quota 등에도 사용되는 범용 RPC 포트매퍼이므로
    # NFS 전용 데몬에서 제외 (가이드라인은 "NFS 관련" 데몬 비활성화를 요구)
    local nfs_services=("nfs-server" "nfs-server.service" "nfs-kernel-server" "nfs" "nfsserver" "rpc-statd" "rpc-mountd")
    local nfs_daemons=("nfsd" "rpc.nfsd" "rpc.mountd" "rpc.statd")

    # 1) systemctl 확인
    if command -v systemctl >/dev/null 2>&1 && systemctl --version >/dev/null 2>&1; then
        for svc in nfs-server nfs-kernel-server nfs; do
            if systemctl is-active --quiet "$svc" 2>/dev/null; then
                nfs_active=true
                active_services="${active_services}${svc} "
                raw_output="${raw_output}[systemctl] ${svc} 실행 중${newline}"
            fi
        done
    fi

    # 2) service 명령어 확인
    if [ "$nfs_active" = false ] && command -v service >/dev/null 2>&1; then
        for svc in nfs nfs-kernel-server nfs-server; do
            local svc_output=$(service "$svc" status 2>&1 || echo "")
            if echo "$svc_output" | grep -qE "running|active|is running"; then
                nfs_active=true
                active_services="${active_services}${svc} "
                raw_output="${raw_output}[service] ${svc}: ${svc_output}${newline}"
            fi
        done
    fi

    # 3) 프로세스 확인
    if [ "$nfs_active" = false ]; then
        for daemon in "${nfs_daemons[@]}"; do
            local daemon_ps=$(ps aux 2>/dev/null | grep -E "$daemon" | grep -v grep || echo "")
            if [ -n "$daemon_ps" ]; then
                nfs_active=true
                active_services="${active_services}${daemon} "
                raw_output="${raw_output}[Process] ${daemon}:${newline}${daemon_ps}${newline}"
            fi
        done
    fi

    # 4) NFS 마운트 및 export 확인 (정보성)
    local exports=""
    if [ -f /etc/exports ]; then
        exports=$(grep -v "^#" /etc/exports 2>/dev/null | grep -v "^$" || echo "")
    fi
    local mount_output=$(mount 2>/dev/null | grep -E "type nfs" || echo "")

    # NFS 패키지 설치 확인
    local nfs_pkg=""
    if command -v dpkg >/dev/null 2>&1; then
        nfs_pkg=$(dpkg -l 2>/dev/null | grep -E "nfs-kernel-server|nfs-common" | grep "^ii" || echo "")
    fi

    # 최종 판정
    if [ "$nfs_active" = true ]; then
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="NFS 서비스가 활성화됨: ${active_services}"
        command_result="${raw_output}[Exports]${exports:-없음}${newline}[Mounts]${mount_output:-없음}${newline}[Package]${nfs_pkg:-미설치}"
        command_executed="systemctl status nfs-server nfs-kernel-server 2>/dev/null; ps aux | grep nfsd; cat /etc/exports 2>/dev/null"
    else
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="NFS 서비스가 비활성화됨"
        command_result="${raw_output}[Exports]${exports:-없음}${newline}[Mounts]${mount_output:-없음}${newline}[Package]${nfs_pkg:-미설치}"
        command_executed="systemctl status nfs-server nfs-kernel-server 2>/dev/null; ps aux | grep nfsd"
    fi

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
