#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-18
# ============================================================================
# [점검 항목 상세]
# @ID          : U-01
# @Category    : Unix Server
# @Platform    : AIX
# @Severity    : 상
# @Title       : root 계정 원격 접속 제한
# @Description : PermitRootLogin no 설정 확인
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


ITEM_ID="U-01"
ITEM_NAME="root 계정 원격 접속 제한"
SEVERITY="상"

# 가이드라인 정보
GUIDELINE_PURPOSE="관리자 계정 탈취로 인한 시스템 장악을 방지하기 위해 외부 비인가자의 root 계정 접근 시도를 원천적으로 차단하기 위함"
GUIDELINE_THREAT="root 계정은 운영 체제의 모든 기능을 설정 및 변경이 가능하여(프로세스, 커널 변경 등) root 계정을 탈취하여 외부에서 원격을 이용한 시스템 장악 및 각종 공격으로(무차별 대입 공격, 사전 대입 공격 등) 인한 root 계정 사용 불가 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="원격 터미널 서비스를 사용하지 않거나, 사용 시 root 직접 접속을 차단한 경우"
GUIDELINE_CRITERIA_BAD="원격 터미널 서비스 사용 시 root 직접 접속을 허용한 경우"
GUIDELINE_REMEDIATION="원격 접속 시 root 계정으로 접속할 수 없도록 파일 내용 설정"

# ============================================================================
# 진단 함수
# ============================================================================

diagnose() {

    diagnosis_result="unknown"
    local status="미진단"
    local inspection_summary=""
    local command_result=""
    local command_executed=""

    # ==========================================================================
    # 서비스 실행 상태 확인 (AIX 플랫폼 특화: lssrc)
    # ==========================================================================
    local ssh_active=false
    local telnet_active=false
    local ssh_service_output=""
    local telnet_service_output=""
    local newline=$'\n'

    # -------------------------------------------------------------------------
    # SSH 서비스 실행 확인 (lssrc -s sshd)
    # -------------------------------------------------------------------------
    if command -v lssrc >/dev/null 2>&1; then
        local ssh_lssrc=$(lssrc -s sshd 2>/dev/null || echo "")
        if echo "$ssh_lssrc" | grep -q "active"; then
            ssh_active=true
            ssh_service_output="[SSH Service Status]${newline}${ssh_lssrc}${newline}${newline}"
        fi
    fi

    # 프로세스 확인 (최후의 수단)
    if [ "$ssh_active" = false ]; then
        local ssh_ps=$(ps -ef 2>/dev/null | grep -E "sshd.*-D|sshd$" | grep -v grep | head -1 || echo "")
        if [ -n "$ssh_ps" ]; then
            ssh_active=true
            ssh_service_output="[SSH Process]${newline}${ssh_ps}${newline}${newline}"
        fi
    fi

    # -------------------------------------------------------------------------
    # Telnet 서비스 실행 확인 (lssrc -s telnet)
    # -------------------------------------------------------------------------
    if command -v lssrc >/dev/null 2>&1; then
        local telnet_lssrc=$(lssrc -s telnet 2>/dev/null || echo "")
        if echo "$telnet_lssrc" | grep -q "active"; then
            telnet_active=true
            telnet_service_output="[Telnet Service Status]${newline}${telnet_lssrc}${newline}${newline}"
        fi
    fi

    # 프로세스 및 포트 확인 (최후의 수단)
    if [ "$telnet_active" = false ]; then
        local telnet_ps=$(ps -ef 2>/dev/null | grep -E "telnetd|in\.telnetd" | grep -v grep | head -1 || echo "")
        local telnet_port=$(netstat -an 2>/dev/null | grep "\.23 " | grep LISTEN || echo "")
        if [ -n "$telnet_ps" ] || [ -n "$telnet_port" ]; then
            telnet_active=true
            telnet_service_output="[Telnet Process/Port]${newline}${telnet_ps}${newline}${telnet_port}${newline}${newline}"
        fi
    fi

    # ==========================================================================
    # 서비스 미사용 시 양호 판정
    # ==========================================================================
    if [ "$ssh_active" = false ] && [ "$telnet_active" = false ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="SSH/Telnet 서비스 미사용 (root 원격 접속 제한 양호)"

        local ssh_status_raw=$(lssrc -s sshd 2>/dev/null || echo "Service not found")
        local telnet_status_raw=$(lssrc -s telnet 2>/dev/null || echo "Service not found")
        command_result="[Command: lssrc -s sshd]${newline}${ssh_status_raw}${newline}${newline}[Command: lssrc -s telnet]${newline}${telnet_status_raw}"
        command_executed="lssrc -s sshd; lssrc -s telnet"
    else
        # ==========================================================================
        # 서비스 실행 중인 경우 상세 진단
        # ==========================================================================
        local ssh_secure=false
        local telnet_secure=false
        local manual_required=false
        local config_details=""
        local ssh_config_output=""

    # -------------------------------------------------------------------------
    # 1. SSH 진단 (SSH 서비스 실행 중인 경우에만 검사)
    # -------------------------------------------------------------------------
    if [ "$ssh_active" = true ]; then
        local sshd_config_file="/etc/ssh/sshd_config"

        if [ ! -f "$sshd_config_file" ]; then
            manual_required=true
            inspection_summary="SSH 설정 파일이 존재하지 않음 (${sshd_config_file})"
            ssh_config_output="[FILE NOT FOUND]"
            ssh_secure=false
            config_details="[SSH] 설정 파일 없음 (수동 확인 필요)"
        else
            # PermitRootLogin 설정 확인
            local ssh_config_commented=$(grep -E "^\s*#\s*PermitRootLogin" "$sshd_config_file" 2>/dev/null | head -1 || true)
            ssh_config_output=$(grep -E "^\s*PermitRootLogin" "$sshd_config_file" 2>/dev/null | grep -v "^\s*#" | head -1 || true)
            local permit_root_setting=$(echo "$ssh_config_output" | awk '{print $2}')

            if [ -z "$permit_root_setting" ]; then
                config_details="[SSH] PermitRootLogin 설정 없음 (기본값: yes)"
                ssh_secure=false
                if [ -n "$ssh_config_commented" ]; then
                    ssh_config_output="${ssh_config_commented} (commented out)"
                else
                    ssh_config_output="설정 없음 (기본값: yes)"
                fi
            else
                config_details="[SSH] PermitRootLogin ${permit_root_setting}"
                case "$permit_root_setting" in
                    no)
                        ssh_secure=true
                        ;;
                    yes|prohibit-password|without-password)
                        ssh_secure=false
                        ;;
                    *)
                        config_details="${config_details} (알 수 없는 설정)"
                        ssh_secure=false
                        ;;
                esac
            fi
        fi
    else
        ssh_secure=true
        config_details="[SSH] 서비스 미실행 (양호)"
        ssh_config_output="N/A"
    fi

    # -------------------------------------------------------------------------
    # 2. Telnet 진단 (Telnet 서비스 실행 중인 경우에만 검사)
    # -------------------------------------------------------------------------
    local telnet_details=""
    local login_cfg_output=""

    if [ "$telnet_active" = true ]; then
        # AIX는 /etc/security/user의 root 스탠자 rlogin 속성으로 원격 root 접속 차단 여부 판단
        local security_user_file="/etc/security/user"
        local rlogin_val=""

        # 1차: lsuser 명령으로 확인
        if command -v lsuser >/dev/null 2>&1; then
            rlogin_val=$(lsuser -a rlogin root 2>/dev/null | awk -F'=' '/rlogin/ {gsub(/[[:space:]]/,"",$2); print tolower($2)}' | head -1 || true)
        fi

        # 2차: /etc/security/user의 root 스탠자 직접 파싱
        if [ -z "$rlogin_val" ] && [ -f "$security_user_file" ]; then
            rlogin_val=$(awk '
                /^[[:space:]]*root:[[:space:]]*$/ {in_root=1; next}
                /^[^[:space:]#].*:[[:space:]]*$/ {in_root=0}
                in_root && /^[[:space:]]*rlogin[[:space:]]*=/ {
                    split($0, a, "=");
                    gsub(/[[:space:]]/, "", a[2]);
                    print tolower(a[2]);
                    exit
                }' "$security_user_file" 2>/dev/null || true)
        fi

        if [ "$rlogin_val" = "false" ]; then
            telnet_secure=true
            telnet_details="[Telnet] root rlogin=false (원격 root 접속 차단, 양호)"
            login_cfg_output="root rlogin=${rlogin_val}"
        elif [ -n "$rlogin_val" ]; then
            telnet_secure=false
            telnet_details="[Telnet] root rlogin=${rlogin_val} (원격 root 접속 허용, 취약)"
            login_cfg_output="root rlogin=${rlogin_val}"
        else
            # rlogin 속성 미확인: AIX 기본값 true → 취약
            telnet_secure=false
            telnet_details="[Telnet] root rlogin 설정 미확인 (기본값 true, 취약)"
            login_cfg_output="rlogin 설정 확인 불가 (기본값: true)"
        fi
    else
        telnet_secure=true
        telnet_details="[Telnet] 서비스 미실행 (양호)"
        login_cfg_output="N/A"
    fi

    # -------------------------------------------------------------------------
    # 3. 종합 판정
    # -------------------------------------------------------------------------
    local is_secure=false
    if [ "$ssh_secure" = true ] && [ "$telnet_secure" = true ]; then
        is_secure=true
    else
        is_secure=false
    fi

    config_details="${config_details} | ${telnet_details}"

    # -------------------------------------------------------------------------
    # 4. command_result 및 command_executed 구성
    # -------------------------------------------------------------------------
    # SSH 부분
    if [ "$ssh_active" = true ]; then
        command_result="${ssh_service_output}[/etc/ssh/sshd_config]${newline}${ssh_config_output}${newline}${newline}"
        command_executed="lssrc -s sshd; grep -E '^[\\s]*PermitRootLogin' /etc/ssh/sshd_config"
    else
        local ssh_status_raw=$(lssrc -s sshd 2>/dev/null || echo "Service not found")
        command_result="[Command: lssrc -s sshd]${newline}${ssh_status_raw}${newline}${newline}"
        command_executed="lssrc -s sshd"
    fi

    # Telnet 부분 추가
    if [ "$telnet_active" = true ]; then
        command_result="${command_result}${telnet_service_output}[root rlogin attribute]${newline}${login_cfg_output}"
        command_executed="${command_executed}; lssrc -s telnet; lsuser -a rlogin root"
    else
        local telnet_status_raw=$(lssrc -s telnet 2>/dev/null || echo "Service not found")
        command_result="${command_result}[Command: lssrc -s telnet]${newline}${telnet_status_raw}"
        command_executed="${command_executed}; lssrc -s telnet"
    fi

    # -------------------------------------------------------------------------
    # 5. 최종 판정
    # -------------------------------------------------------------------------
    if [ "$manual_required" = true ]; then
        diagnosis_result="MANUAL"
        status="수동 진단"
        inspection_summary="SSH 설정 파일 확인 불가, 수동 점검 필요 (${config_details})"
    elif [ "$is_secure" = true ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="root 계정 원격 접속 제한 적절 (${config_details})"
    else
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="root 계정 원격 접속 제한 미설정 또는 부적절 (${config_details})"
    fi
    fi

    # 결과 저장 (전통적 모드)
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
