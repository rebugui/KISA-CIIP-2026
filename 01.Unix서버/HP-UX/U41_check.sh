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
# @Platform    : HP-UX
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

    # automountd/autofs 비활성화 확인
    local automount_running=false
    local automount_info=""

    # 1) 실행 중인 automount/automountd 프로세스 확인 (1차 판정 기준)
    #    HP-UX는 /sbin/init.d/<svc> status 를 지원하지 않으므로 ps 기반으로 판정
    local automount_procs
    automount_procs=$(ps -ef 2>/dev/null | grep -E 'automountd?' | grep -v grep || true)
    if [ -n "$automount_procs" ]; then
        automount_running=true
        automount_info="${automount_info}실행 중인 automount 프로세스:\\n${automount_procs}\\n"
    fi

    # 2) init.d 스크립트 존재 여부 (판정에 사용하지 않는 참고 증거)
    local rc_script
    for rc_script in autofs amd automountd; do
        if [ -f "/sbin/init.d/${rc_script}" ]; then
            automount_info="${automount_info}/sbin/init.d/${rc_script} 스크립트 존재 (참고)\\n"
        fi
    done

    # 3) HP-UX 부팅 설정: /etc/rc.config.d/nfsconf의 AUTOFS 플래그 확인 (가이드 조치: AUTOFS=0)
    if [ -f /etc/rc.config.d/nfsconf ]; then
        local autofs_flag=$(grep -E '^[[:space:]]*AUTOFS[[:space:]]*=' /etc/rc.config.d/nfsconf 2>/dev/null | tail -1 | cut -d= -f2 | tr -d ' \t"' || true)
        if [ -n "$autofs_flag" ] && [ "$autofs_flag" != "0" ]; then
            automount_info="${automount_info}/etc/rc.config.d/nfsconf AUTOFS=${autofs_flag} (부팅 시 자동 활성화)\\n"
            automount_running=true
        fi
    fi

    # 4) /etc/fstab 확인 (automount 엔트리)
    if [ -f /etc/fstab ]; then
        local automount_entries=$(grep "automount" /etc/fstab 2>/dev/null || echo "")
        if [ -n "$automount_entries" ]; then
            automount_info="${automount_info}/etc/fstab automount 엔트리 발견\\n${automount_entries}\\n"
            automount_running=true
        fi
    fi

    # 5) autofs 설정 파일 확인 (HP-UX 마스터 맵 /etc/auto_master 포함)
    if [ -f /etc/auto.master ] || [ -f /etc/auto_master ] || ls /etc/auto.master.d/*.conf >/dev/null 2>&1; then
        automount_info="${automount_info}autofs 설정 파일 존재\\n"
        if [ -f /etc/auto.master ]; then
            automount_info="${automount_info}$(head -5 /etc/auto.master 2>/dev/null)\\n"
        fi
        if [ -f /etc/auto_master ]; then
            automount_info="${automount_info}$(head -5 /etc/auto_master 2>/dev/null)\\n"
        fi
        automount_running=true
    fi

    # 최종 판정
    if [ "$automount_running" = false ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="automount 서비스 비활성화됨"
        command_result="실행 중인 automount 프로세스 없음\\n${automount_info}"
        command_executed="ps -ef | grep -E 'automountd?' | grep -v grep; grep AUTOFS /etc/rc.config.d/nfsconf 2>/dev/null; grep automount /etc/fstab 2>/dev/null; ls /etc/auto.master /etc/auto_master 2>/dev/null"
    else
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="automount 서비스 활성화됨"
        command_result="${automount_info}"
        command_executed="ps -ef | grep -E 'automountd?' | grep -v grep; cat /etc/auto.master 2>/dev/null; grep automount /etc/fstab"
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
