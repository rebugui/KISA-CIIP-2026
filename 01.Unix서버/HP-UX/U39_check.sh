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
# @Platform    : HP-UX
# @Severity    : 상
# @Title       : 불필요한 NFS 서비스 비활성화
# @Description : NFS 서버 데몬(nfsd, rpc.mountd) 및 dfstab/nfsconf 설정 확인
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
    # HP-UX NFS 서버 데몬(nfsd, rpc.mountd) 및 설정 파일 점검
    # 가이드라인: 불필요한 NFS 서비스 관련 데몬이 비활성화된 경우 양호
    # ※ rpcbind/portmap은 NFS 전용 데몬이 아니므로 참고 증적으로만 수집

    local nfs_active=false
    local probe_available=false
    local active_evidence=()
    local raw_output=""

    # 1) NFS 서버 데몬 프로세스 확인 (nfsd, rpc.mountd)
    local ps_output=""
    if command -v ps >/dev/null 2>&1; then
        probe_available=true
        ps_output=$(ps -ef 2>/dev/null | grep -E 'nfsd|rpc\.mountd' | grep -v grep || echo "")
        if [ -n "$ps_output" ]; then
            nfs_active=true
            active_evidence+=("NFS 서버 데몬(nfsd/rpc.mountd) 실행 중")
        fi
        raw_output="${raw_output}[Command: ps -ef | grep -E 'nfsd|rpc.mountd']${newline}${ps_output:-실행 중인 NFS 서버 데몬 없음}${newline}"

        # 2) rpcbind/portmap 상태 (참고 증적 - 단독으로는 취약 판정 근거 아님)
        local rpc_output=$(ps -ef 2>/dev/null | grep -E 'rpcbind|portmap' | grep -v grep || echo "")
        raw_output="${raw_output}[Command: ps -ef | grep -E 'rpcbind|portmap'] (참고용)${newline}${rpc_output:-실행 중인 rpcbind/portmap 없음}${newline}"
    else
        raw_output="${raw_output}[Command: ps] 명령을 사용할 수 없음${newline}"
    fi

    # 3) /etc/dfs/dfstab 공유(share) 설정 확인
    local dfstab_entries=""
    if [ -f /etc/dfs/dfstab ]; then
        probe_available=true
        dfstab_entries=$(grep -v '^#' /etc/dfs/dfstab 2>/dev/null | grep -v '^[[:space:]]*$' || echo "")
        raw_output="${raw_output}[Command: cat /etc/dfs/dfstab]${newline}${dfstab_entries:-공유(share) 설정 없음}${newline}"
        if [ -n "$dfstab_entries" ] && [ "$nfs_active" = true ]; then
            active_evidence+=("/etc/dfs/dfstab에 공유(share) 설정 존재")
        fi
    else
        raw_output="${raw_output}[File: /etc/dfs/dfstab] 파일 없음${newline}"
    fi

    # 4) /etc/rc.config.d/nfsconf NFS_SERVER 설정 확인
    local nfsconf_setting=""
    if [ -f /etc/rc.config.d/nfsconf ]; then
        probe_available=true
        nfsconf_setting=$(grep -E '^[[:space:]]*NFS_SERVER=' /etc/rc.config.d/nfsconf 2>/dev/null | tail -1 || echo "")
        raw_output="${raw_output}[Command: grep NFS_SERVER /etc/rc.config.d/nfsconf]${newline}${nfsconf_setting:-NFS_SERVER 설정 없음}${newline}"
        if echo "$nfsconf_setting" | grep -q 'NFS_SERVER=1'; then
            nfs_active=true
            active_evidence+=("/etc/rc.config.d/nfsconf에 NFS_SERVER=1 설정(부팅 시 NFS 서버 기동)")
        fi
    else
        raw_output="${raw_output}[File: /etc/rc.config.d/nfsconf] 파일 없음${newline}"
    fi

    command_executed="ps -ef | grep -E 'nfsd|rpc.mountd'; ps -ef | grep -E 'rpcbind|portmap'; cat /etc/dfs/dfstab; grep NFS_SERVER /etc/rc.config.d/nfsconf"
    command_result="${raw_output}"

    # 최종 판정
    if [ "$nfs_active" = true ]; then
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="NFS 서비스가 활성화되어 있습니다: ${active_evidence[*]}"
    elif [ "$probe_available" = true ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="NFS 서버 데몬(nfsd/rpc.mountd)이 비활성화되어 있고 부팅 시 NFS 서버 기동 설정이 없습니다."
    else
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="ps 명령 및 NFS 설정 파일(/etc/dfs/dfstab, /etc/rc.config.d/nfsconf)을 확인할 수 없어 NFS 서비스 상태를 수동으로 점검해야 합니다."
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
