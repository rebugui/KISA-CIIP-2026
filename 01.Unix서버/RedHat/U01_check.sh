#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-04-20
# ============================================================================
# [점검 항목 상세]
# @ID          : U-01
# @Category    : UNIX > 1. 계정 관리
# @Platform    : SOLARIS, LINUX, AIX, HP-UX 등
# @Severity    : (상)
# @Title       : root 계정 원격 접속 제한
# @Description : 원격 터미널을 이용한 root 계정의 직접 접속 제한 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

set -euo pipefail

# 스크립트 디렉토리 설정
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../../lib"

# 필수 라이브러리 로드
source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/metadata_parser.sh"

ITEM_ID="U-01"
ITEM_NAME="root 계정 원격 접속 제한"
SEVERITY="상"

# 가이드라인 정보
GUIDELINE_PURPOSE="관리자 계정 탈취로 인한 시스템 장악을 방지하기 위해 외부 비인가자의 root 계정 접근 시도를 원천적으로 차단하기 위함"
GUIDELINE_THREAT="root 계정은 운영 체제의 모든 기능을 설정 및 변경이 가능하여(프로세스, 커널 변경 등) root 계정을 탈취하여 외부에서 원격을 이용한 시스템 장악 및 각종 공격으로(무차별 대입 공격, 사전 대입 공격 등) 인한 root 계정 사용 불가 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="원격 터미널 서비스를 사용하지 않거나, 사용 시 root 직접 접속을 차단한 경우"
GUIDELINE_CRITERIA_BAD="원격 터미널 서비스 사용 시 root 직접 접속을 허용한 경우"
GUIDELINE_REMEDIATION="원격 접속 시 root 계정으로 접속할 수 없도록 파일 내용 설정"

diagnose() {
    local status="양호"
    diagnosis_result="GOOD"
    local inspection_summary="root 계정 원격 접속 제한 설정이 적절합니다."
    local command_result=""
    local command_executed="systemctl is-active sshd; grep -i 'PermitRootLogin' /etc/ssh/sshd_config"

    local newline=$'\n'

    # ==========================================================================
    # 1. 서비스 실행 상태 확인
    # ==========================================================================
    local ssh_active=false
    local telnet_active=false

    # SSH 서비스 확인
    if systemctl is-active --quiet sshd 2>/dev/null; then
        ssh_active=true
    elif ps aux 2>/dev/null | grep -E "[s]shd" >/dev/null 2>&1; then
        ssh_active=true
    fi

    # Telnet 서비스 확인
    if systemctl is-active --quiet telnetd 2>/dev/null || systemctl is-active --quiet xinetd 2>/dev/null; then
        telnet_active=true
    elif ps aux 2>/dev/null | grep -E "in\.telnetd|telnetd" | grep -v grep >/dev/null 2>&1; then
        telnet_active=true
    fi

    # ==========================================================================
    # 2. 서비스 미사용 시 양호 판정
    # ==========================================================================
    if [ "$ssh_active" = false ] && [ "$telnet_active" = false ]; then
        command_result="[SSH] 서비스 미실행${newline}[Telnet] 서비스 미실행"
        save_dual_result \
            "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" \
            "${inspection_summary}" "${command_result}" "${command_executed}" \
            "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" \
            "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
        verify_result_saved "${ITEM_ID}"
        return 0
    fi

    # ==========================================================================
    # 3. 서비스 실행 중인 경우 상세 진단
    # ==========================================================================
    local ssh_secure=true
    local telnet_secure=true
    local details=""

    # --- SSH 진단 ---
    if [ "$ssh_active" = true ]; then
        local sshd_config="/etc/ssh/sshd_config"
        if [ -f "$sshd_config" ]; then
            local ssh_val=$(grep -i "^PermitRootLogin" "$sshd_config" 2>/dev/null | awk '{print $2}' | head -1 || true)
            if [ -z "$ssh_val" ]; then
                # 설정 라인이 없으면 주석이나 미설정 → 기본값 확인 필요
                ssh_secure=false
                details="${details}[SSH] PermitRootLogin 미설정 (기본값). "
            else
                case "$ssh_val" in
                    no|prohibit-password|without-password)
                        details="${details}[SSH] PermitRootLogin=${ssh_val} (양호). "
                        ;;
                    yes)
                        ssh_secure=false
                        details="${details}[SSH] PermitRootLogin=yes (취약). "
                        ;;
                    *)
                        ssh_secure=false
                        details="${details}[SSH] PermitRootLogin=${ssh_val} (확인필요). "
                        ;;
                esac
            fi
        else
            # sshd_config 파일 자체가 없음 → MANUAL 처리
            diagnosis_result="MANUAL"
            status="수동진단"
            inspection_summary="SSH 설정 파일(${sshd_config})이 없습니다."
            command_result="[SSH] 설정 파일 없음"
            save_dual_result \
                "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" \
                "${inspection_summary}" "${command_result}" "${command_executed}" \
                "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" \
                "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
            verify_result_saved "${ITEM_ID}"
            return 0
        fi
    fi

    # --- Telnet 진단 ---
    if [ "$telnet_active" = true ]; then
        local securetty_pts=$(grep -E "^pts/" /etc/securetty 2>/dev/null || true)
        if [ -n "$securetty_pts" ]; then
            telnet_secure=false
            details="${details}[Telnet] /etc/securetty에 pts 설정 존재 (취약). "
        else
            details="${details}[Telnet] /etc/securetty에 pts 설정 없음 (양호). "
        fi
    fi

    # ==========================================================================
    # 4. 종합 판정
    # ==========================================================================
    if [ "$ssh_secure" = true ] && [ "$telnet_secure" = true ]; then
        status="양호"
        diagnosis_result="GOOD"
        inspection_summary="root 계정 원격 접속 제한 적절 (${details})"
    else
        status="취약"
        diagnosis_result="VULNERABLE"
        inspection_summary="root 계정 원격 접속 제한 미설정 또는 부적절 (${details})"
    fi

    command_result="${details}"

    save_dual_result \
        "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" \
        "${inspection_summary}" "${command_result}" "${command_executed}" \
        "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" \
        "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"

    verify_result_saved "${ITEM_ID}"
    return 0
}

main() {
    show_diagnosis_start "${ITEM_ID}" "${ITEM_NAME}"
    [ "$EUID" -ne 0 ] && { echo "root 권한이 필요합니다."; exit 1; }
    diagnose
    show_diagnosis_complete "${ITEM_ID}" "${diagnosis_result}"
    exit 0
}

main "$@"
