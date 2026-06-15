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
# @Platform    : Debian
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

    # 1) autofs 서비스 확인
    if systemctl list-unit-files | grep -q "^autofs.service"; then
        local active=$(systemctl is-active autofs 2>/dev/null || echo "inactive")
        local enabled=$(systemctl is-enabled autofs 2>/dev/null || echo "disabled")

        automount_info="${automount_info}autofs 서비스: ${active}, ${enabled}${newline}"

        if [ "$active" = "active" ]; then
            automount_running=true
        fi
    fi

    # 2) amd(Automount Daemon) 서비스 확인
    if systemctl list-unit-files | grep -q "^amd.service"; then
        local active=$(systemctl is-active amd 2>/dev/null || echo "inactive")
        local enabled=$(systemctl is-enabled amd 2>/dev/null || echo "disabled")

        automount_info="${automount_info}amd 서비스: ${active}, ${enabled}${newline}"

        if [ "$active" = "active" ]; then
            automount_running=true
        fi
    fi

    # 3) automountd 서비스 확인 (legacy)
    if systemctl list-unit-files | grep -q "automount"; then
        while read -r svc state; do
            if [[ "$svc" =~ automount ]]; then
                local active=$(systemctl is-active "$svc" 2>/dev/null || echo "inactive")
                automount_info="${automount_info}${svc}: ${active}${newline}"
                if [ "$active" = "active" ]; then
                    automount_running=true
                fi
            fi
        done < <(systemctl list-unit-files | grep automount) || true
    fi

    # 4) /etc/fstab 확인 (automount 엔트리)
    if [ -f /etc/fstab ]; then
        local automount_entries=$(grep "automount" /etc/fstab 2>/dev/null || echo "")
        if [ -n "$automount_entries" ]; then
            automount_info="${automount_info}/etc/fstab automount 엔트리 발견${newline}${automount_entries}${newline}"
            automount_running=true
        fi
    fi

    # 5) autofs 설정 파일 확인
    # 주의: [ -f /etc/auto.master.d/*.conf ] 는 glob 이 2개 이상 매칭되면
    #       set -euo pipefail 하에서 "binary operator expected" 로 실패하므로
    #       glob-safe 한 방식(compgen)으로 설정 파일 존재 여부를 확인함.
    local autofs_conf_present=false
    if [ -f /etc/auto.master ]; then
        autofs_conf_present=true
    elif compgen -G "/etc/auto.master.d/*.conf" >/dev/null 2>&1; then
        autofs_conf_present=true
    fi
    if [ "$autofs_conf_present" = true ]; then
        automount_info="${automount_info}autofs 설정 파일 존재\\n"
        if [ -f /etc/auto.master ]; then
            automount_info="${automount_info}$(head -5 /etc/auto.master 2>/dev/null)\\n"
        fi
        automount_running=true
    fi

    # 6) 실행 중인 automount/automountd/autofs 프로세스 확인 (process-based)
    #    SysV-init 또는 systemd 에 등록되지 않은 상태로 실제 구동 중인 autofs 를
    #    systemctl 만으로는 탐지하지 못하므로 ps 기반으로 보강함.
    local automount_proc=""
    automount_proc=$(ps -e -o args= 2>/dev/null | grep -E '(^|/)(automount|automountd|autofs)( |$)' | grep -v 'grep' || true)
    if [ -n "$automount_proc" ]; then
        automount_info="${automount_info}실행 중인 automount 프로세스 발견:${newline}${automount_proc}${newline}"
        automount_running=true
    fi

    # 최종 판정
    if [ "$automount_running" = false ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="automount 서비스 비활성화됨"
        command_result="[Automount Service Check]${newline}$(systemctl list-unit-files 2>/dev/null | grep -E 'autofs|amd|automount' || echo 'No automount services found')${newline}${newline}[Service Status]${newline}$(systemctl is-active autofs 2>&1 || echo 'inactive')${newline}$(systemctl is-active amd 2>&1 || echo 'inactive')"
        command_executed="systemctl list-unit-files | grep -E 'autofs|amd|automount'; systemctl is-active autofs amd"
    else
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="automount 서비스 활성화됨"
        command_result="${automount_info}"
        command_executed="systemctl is-active autofs amd; cat /etc/auto.master 2>/dev/null; grep automount /etc/fstab"
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
