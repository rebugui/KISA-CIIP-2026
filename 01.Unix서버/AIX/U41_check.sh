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
# @Platform    : AIX
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

    # automountd/autofs 비활성화 확인 (AIX)
    local automount_running=false
    local automount_info=""

    # 1) AIX automount 서비스 확인 (lssrc -a)
    if lssrc -a 2>/dev/null | grep -q "autof "; then
        local autofs_lssrc=$(lssrc -s autof 2>/dev/null || echo "")
        local autofs_status="inoperative"
        if echo "$autofs_lssrc" | grep -q "active"; then
            autofs_status="active"
        fi
        automount_info="${automount_info}autof 서비스: ${autofs_status}\\n"

        if [ "$autofs_status" = "active" ]; then
            automount_running=true
        fi
    fi

    # 2) automountd 서비스 확인 (SRC subsystem)
    if lssrc -a 2>/dev/null | grep -q "automountd "; then
        local automountd_lssrc=$(lssrc -s automountd 2>/dev/null || echo "")
        local automountd_status="inoperative"
        if echo "$automountd_lssrc" | grep -q "active"; then
            automountd_status="active"
        fi
        automount_info="${automount_info}automountd 서비스: ${automountd_status}\\n"

        if [ "$automountd_status" = "active" ]; then
            automount_running=true
        fi
    fi

    # 2b) 프로세스 확인 (가이드 [process 점검]: SRC 외부에서 기동된 automountd 탐지)
    local automount_ps=$(ps -ef 2>/dev/null | grep -E "[a]utomountd|[a]utofsd|[a]utomount" | head -3 || echo "")
    if [ -n "$automount_ps" ]; then
        automount_info="${automount_info}automount 프로세스 실행 중:\\n${automount_ps}\\n"
        automount_running=true
    fi

    # 2c) /etc/inittab 기동 항목 확인
    if [ -f /etc/inittab ]; then
        local inittab_auto=$(grep -i "automount" /etc/inittab 2>/dev/null | grep -Ev '^[[:space:]]*[:#]' || echo "")
        if [ -n "$inittab_auto" ]; then
            automount_info="${automount_info}/etc/inittab automount 엔트리 발견\\n${inittab_auto}\\n"
            automount_running=true
        fi
    fi

    # 3) /etc/filesystems 확인 (automount 엔트리)
    if [ -f /etc/filesystems ]; then
        local automount_entries=$(grep -i "automount\|auto_mount" /etc/filesystems 2>/dev/null || echo "")
        if [ -n "$automount_entries" ]; then
            automount_info="${automount_info}/etc/filesystems automount 엔트리 발견\\n${automount_entries}\\n"
            automount_running=true
        fi
    fi

    # 4) automount 설정 파일 확인 (증적 전용 — 기본 제공/잔존 파일이므로 존재 자체는 활성화 근거가 아님)
    local auto_master_file=""
    for auto_master_file in /etc/auto_master /etc/auto.master; do
        if [ -f "$auto_master_file" ]; then
            automount_info="${automount_info}autofs 설정 파일 존재 (${auto_master_file})\\n"
            automount_info="${automount_info}$(head -5 "$auto_master_file" 2>/dev/null)\\n"
        fi
    done

    # AIX에서 auto.master.d/*.conf glob은 직접 처리 (증적 전용)
    if [ -d /etc/auto.master.d ]; then
        local auto_conf_files=$(ls /etc/auto.master.d/*.conf 2>/dev/null)
        if [ -n "$auto_conf_files" ]; then
            automount_info="${automount_info}autofs 설정 파일 존재\\n"
        fi
    fi

    # 최종 판정
    if [ "$automount_running" = false ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="automount 서비스 비활성화됨"
        local lssrc_out=$(lssrc -a | grep -E 'autof|automount' 2>/dev/null || echo "No automount services")
        command_result="[Command: lssrc -a | grep automount]${newline}${lssrc_out}"
        command_executed="lssrc -a | grep -E 'autof|automount'; cat /etc/filesystems 2>/dev/null"
    else
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="automount 서비스 활성화됨"
        command_result="${automount_info}"
        command_executed="lssrc -s autof automountd; ps -ef | grep automountd; grep automount /etc/inittab; cat /etc/auto_master /etc/auto.master 2>/dev/null; grep -i automount /etc/filesystems"
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
