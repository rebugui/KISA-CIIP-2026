#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : U-41
# @Category    : Unix Server
# @Platform    : Solaris
# @Severity    : 상
# @Title       : 불필요한 automountd 제거
# @Description : automount 비활성화 확인
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


ITEM_ID="U-41"
ITEM_NAME="불필요한 automountd 제거"
SEVERITY="상"

# 가이드라인 정보
GUIDELINE_PURPOSE="로컬 공격자가 automountd 데몬에 RPC(Remote Procedure Call)를 보낼 수 있는 취약점이 존재하기 때문에 해당 서비스를 중지시키기 위함"
GUIDELINE_THREAT="파일 시스템의 마운트 옵션을 변경하여 root 권한을 획득할 수 있으며, 로컬 공격자가 automountd 프로세스 권한으로 임의의 명령을 실행할 수 있는 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="automountd 서비스가 비활성화된 경우"
GUIDELINE_CRITERIA_BAD="automountd 서비스가 활성화된 경우"
GUIDELINE_REMEDIATION="automountd 서비스 비활성화 설정"

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

    # automountd/autofs 활성화 여부 확인 (서비스/프로세스 상태 기준 판정)
    local automount_running=false
    local probe_available=false
    local automount_info=""

    # 1) autofs SMF 서비스 상태 확인 (판정 기준)
    if command -v svcs >/dev/null 2>&1; then
        probe_available=true
        local autofs_state
        autofs_state=$(svcs -H -o state svc:/system/filesystem/autofs 2>/dev/null || echo "")
        automount_info="${automount_info}autofs SMF 서비스 상태: ${autofs_state:-미등록}\\n"
        if [ "$autofs_state" = "online" ]; then
            automount_running=true
        fi
    fi

    # 2) automountd 프로세스 확인 (판정 기준)
    if command -v ps >/dev/null 2>&1; then
        probe_available=true
        local automountd_proc
        automountd_proc=$(ps -ef 2>/dev/null | grep automountd | grep -v grep || true)
        if [ -n "$automountd_proc" ]; then
            automount_running=true
            automount_info="${automount_info}automountd 프로세스 실행 중\\n${automountd_proc}\\n"
        else
            automount_info="${automount_info}automountd 프로세스: 미실행\\n"
        fi
    fi

    # 3) 설정 파일 확인 (증적 전용 — Solaris 기본 제공 파일이므로 존재 자체는 활성화 근거가 아님)
    if [ -f /etc/auto_master ]; then
        automount_info="${automount_info}[증적] /etc/auto_master 존재 (기본 제공 설정 파일)\\n$(head -5 /etc/auto_master 2>/dev/null)\\n"
    fi
    if [ -f /etc/vfstab ]; then
        local automount_entries
        automount_entries=$(grep "automount" /etc/vfstab 2>/dev/null || true)
        if [ -n "$automount_entries" ]; then
            automount_info="${automount_info}[증적] /etc/vfstab automount 엔트리:\\n${automount_entries}\\n"
        fi
    fi

    # 최종 판정 (서비스 활성 여부 기준)
    if [ "$automount_running" = true ]; then
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="automount(autofs/automountd) 서비스 활성화됨"
        command_result="${automount_info}"
        command_executed="svcs -H -o state svc:/system/filesystem/autofs; ps -ef | grep automountd; cat /etc/auto_master 2>/dev/null; grep automount /etc/vfstab"
    elif [ "$probe_available" = true ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="automount(autofs/automountd) 서비스 비활성화됨"
        command_result="${automount_info}"
        command_executed="svcs -H -o state svc:/system/filesystem/autofs; ps -ef | grep automountd"
    else
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="svcs 및 ps 명령을 사용할 수 없어 automountd 서비스 상태를 수동으로 점검해야 합니다."
        command_result="${automount_info:-svcs/ps 명령 사용 불가 환경}"
        command_executed="svcs -H -o state svc:/system/filesystem/autofs; ps -ef | grep automountd"
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
