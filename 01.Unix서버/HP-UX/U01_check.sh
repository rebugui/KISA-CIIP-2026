#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : U-01
# @Category    : Unix Server
# @Platform    : HP-UX
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

# 진단 수행
diagnose() {

    diagnosis_result="unknown"
    local status="미진단"
    local inspection_summary=""
    local command_result=""
    local command_executed=""

    # ==========================================================================
    # 서비스 실행 상태 확인 (HP-UX 특화)
    # 가이드라인 기준: "원격터미널서비스를 사용하지 않거나" → 서비스 미실행 시 양호(GOOD)
    # HP-UX 명령어: ps -ef, /sbin/init.d, inetd -q, netstat -an
    # ==========================================================================
    local ssh_active=false    # SSH 서비스 실행 상태 (true/false)
    local telnet_active=false # Telnet 서비스 실행 상태 (true/false)
    local ssh_service_output="" # SSH 서비스 확인 결과
    local telnet_service_output="" # Telnet 서비스 확인 결과
    local newline=$'\n'

    # -------------------------------------------------------------------------
    # 1. SSH 서비스 실행 확인 (HP-UX: ps -ef | grep sshd)
    # -------------------------------------------------------------------------
    local ssh_ps_output=$(ps -ef 2>/dev/null | grep -E "sshd.*-D|sshd$" | grep -v grep || echo "")
    if [ -n "$ssh_ps_output" ]; then
        ssh_active=true
        ssh_service_output="[SSH Process]${newline}${ssh_ps_output}${newline}${newline}"
    fi

    # -------------------------------------------------------------------------
    # 2. Telnet 서비스 실행 확인 (HP-UX: inetd, ps -ef, netstat)
    # -------------------------------------------------------------------------
    # 2-1. inetd 프로세스 확인 (HP-UX는 inetd가 Telnet을 담당)
    # inetd 실행만으로는 Telnet 사용으로 볼 수 없음 → /etc/inetd.conf에서 telnet 활성 라인까지 확인
    local inetd_ps_output=$(ps -ef 2>/dev/null | grep -E "inetd" | grep -v grep || echo "")
    if [ -n "$inetd_ps_output" ]; then
        local inetd_telnet_conf=$(grep -E "^[[:space:]]*telnet[[:space:]]" /etc/inetd.conf 2>/dev/null || echo "")
        if [ -n "$inetd_telnet_conf" ]; then
            telnet_active=true
            telnet_service_output="[inetd Process]${newline}${inetd_ps_output}${newline}[inetd.conf telnet]${newline}${inetd_telnet_conf}${newline}${newline}"
        fi
    fi

    # 2-2. telnetd 프로세스 확인
    local telnet_ps_output=$(ps -ef 2>/dev/null | grep -E "in\.telnetd|telnetd" | grep -v grep || echo "")
    if [ -n "$telnet_ps_output" ]; then
        telnet_active=true
        telnet_service_output="${telnet_service_output}[Telnet Process]${newline}${telnet_ps_output}${newline}${newline}"
    fi

    # 2-3. 포트 확인 (HP-UX: netstat -an | grep :23)
    # HP-UX netstat는 주소를 "*.23" 형태로 표시 → 포트 23이 LISTEN 상태이면 telnet 활성으로 판정
    # (구분자 [.:] 뒤 23 다음에 공백, 동일 라인에 LISTEN 존재 — U-52 SAFE 패턴과 동일)
    local telnet_port_output=$(netstat -an 2>/dev/null | grep -E '[.:]23[[:space:]].*LISTEN' || echo "")
    if [ -n "$telnet_port_output" ]; then
        telnet_active=true
        telnet_service_output="${telnet_service_output}[Telnet Port]${newline}${telnet_port_output}${newline}${newline}"
    fi

    # ==========================================================================
    # 서비스 미사용 시 양호 판정 (가이드라인: "원격터미널서비스를 사용하지 않거나")
    # ==========================================================================
    if [ "$ssh_active" = false ] && [ "$telnet_active" = false ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="SSH/Telnet 서비스 미사용으로 root 원격 접속 불가"

        local ssh_check=$(ps -ef 2>/dev/null | grep -E "sshd.*-D|sshd$" | grep -v grep || echo "No SSH process found")
        local telnet_check=$(ps -ef 2>/dev/null | grep -E "inetd" | grep -v grep || echo "No inetd process found")
        command_result="[SSH Service Status]${newline}${ssh_check}${newline}${newline}[Telnet Service Status]${newline}${telnet_check}"
        command_executed="ps -ef | grep sshd; ps -ef | grep inetd; netstat -an | grep \":23 \""
    else
        # ==========================================================================
        # 서비스 실행 중인 경우 상세 진단
        # ==========================================================================
        local ssh_secure=false
        local ssh_manual=false
        local telnet_secure=false
        local config_details=""
        local ssh_config_output=""
        local telnet_config_output=""

    # -------------------------------------------------------------------------
    # 1. SSH 진단 (SSH 서비스 실행 중인 경우에만 검사)
    # -------------------------------------------------------------------------
    if [ "$ssh_active" = true ]; then
        # HP-UX 표준 경로(/opt/ssh/etc/sshd_config) 우선, 그 외 /etc/ssh/sshd_config
        local sshd_config_file="/etc/ssh/sshd_config"
        local cfg_candidate
        for cfg_candidate in /opt/ssh/etc/sshd_config /etc/ssh/sshd_config; do
            if [ -f "$cfg_candidate" ]; then
                sshd_config_file="$cfg_candidate"
                break
            fi
        done

        # SSH 설정 파일 존재 확인
        if [ ! -f "$sshd_config_file" ]; then
            # 설정 파일을 찾지 못함 → 수동진단 대상 (최종 판정 단계에서 반영)
            ssh_manual=true
            config_details="[SSH] 설정 파일 없음 (/opt/ssh/etc/sshd_config, /etc/ssh/sshd_config)"

            local ssh_config_ls=$(ls -l /opt/ssh/etc/sshd_config /etc/ssh/sshd_config 2>/dev/null || echo "File not found: sshd_config")
            ssh_config_output="${ssh_config_ls}"
            ssh_secure=false
        else
            # PermitRootLogin 설정 확인 (주석 포함)
            local ssh_config_commented=$(grep -E "^[\s]*#*[\s]*PermitRootLogin" "$sshd_config_file" 2>/dev/null | head -1 || true)
            ssh_config_output=$(grep -E "^[\s]*PermitRootLogin" "$sshd_config_file" 2>/dev/null | grep -v "^#" | head -1 || true)
            local permit_root_setting=$(echo "$ssh_config_output" | awk '{print $2}')

            if [ -z "$permit_root_setting" ]; then
                config_details="[SSH] PermitRootLogin 설정 없음 (기본값: yes)"
                ssh_secure=false
                # 주석으로 된 설정이 있으면 보여주기
                if [ -n "$ssh_config_commented" ]; then
                    ssh_config_output="${ssh_config_commented} (주석 처리됨)"
                else
                    ssh_config_output="설정 없음 (기본값 yes 사용)"
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
        # SSH 서비스 미실행: 양호로 처리
        ssh_secure=true
        config_details="[SSH] 서비스 미실행 (양호)"
        ssh_config_output="N/A"
    fi

    # -------------------------------------------------------------------------
    # 2. Telnet 진단 (Telnet 서비스 실행 중인 경우에만 검사)
    # -------------------------------------------------------------------------
    local telnet_details=""
    local securetty_output=""
    local pam_login_output=""

    if [ "$telnet_active" = true ]; then
        # Check /etc/securetty
        local securetty_file="/etc/securetty"
        if [ -f "$securetty_file" ]; then
            securetty_output=$(grep -E "^[\s]*pts" "$securetty_file" 2>/dev/null || echo "")
            if [ -n "$securetty_output" ]; then
                telnet_secure=false
                telnet_details="[Telnet] /etc/securetty에 pts 설정 존재 (취약)"
            else
                telnet_secure=true
                telnet_details="[Telnet] /etc/securetty에 pts 설정 없음 (양호)"
            fi
        else
            # HP-UX에서 securetty 파일이 없는 경우
            # Telnet 서비스가 실행 중이면 securetty가 없는 것은 취약할 수 있음
            telnet_secure=false
            telnet_details="[Telnet] /etc/securetty 파일 없음 (취약)"
            local securetty_ls=$(ls -l "$securetty_file" 2>/dev/null || echo "File not found: $securetty_file")
            securetty_output="${securetty_ls}"
        fi

        # Check /etc/pam.d/login for pam_securetty.so (HP-UX도 PAM 사용)
        local pam_login_file="/etc/pam.d/login"
        if [ -f "$pam_login_file" ]; then
            pam_login_output=$(grep -E "^[\s]*auth.*required.*pam_securetty.so" "$pam_login_file" 2>/dev/null || echo "")
            if [ -n "$pam_login_output" ]; then
                # pam_securetty.so가 설정되어 있으면 /etc/securetty가 있어야 함
                telnet_details="${telnet_details}, [PAM] pam_securetty.so 설정됨"
            else
                # securetty 파일이 있지만 모듈이 없으면 securetty가 무시됨
                telnet_secure=false
                telnet_details="${telnet_details}, [PAM] pam_securetty.so 설정 없음 (취약)"
            fi
        else
            telnet_details="${telnet_details}, [PAM] /etc/pam.d/login 파일 없음"
            local pam_login_ls=$(ls -l "$pam_login_file" 2>/dev/null || echo "File not found: $pam_login_file")
            pam_login_output="${pam_login_ls}"
        fi
    else
        # Telnet 서비스 미실행: 양호로 처리
        telnet_secure=true
        telnet_details="[Telnet] 서비스 미실행 (양호)"
        securetty_output="N/A"
        pam_login_output="N/A"
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
        command_result="${ssh_service_output}[${sshd_config_file}]${newline}${ssh_config_output}${newline}${newline}"
        command_executed="ps -ef | grep sshd; grep -E '^[\\s]*PermitRootLogin' ${sshd_config_file}"
    else
        local ssh_ps_check=$(ps -ef 2>/dev/null | grep -E "sshd.*-D|sshd$" | grep -v grep || echo "No SSH process found")
        command_result="[SSH Service Status]${newline}${ssh_ps_check}${newline}${newline}"
        command_executed="ps -ef | grep sshd"
    fi

    # Telnet 부분 추가
    if [ "$telnet_active" = true ]; then
        command_result="${command_result}${telnet_service_output}[/etc/securetty]${newline}${securetty_output}${newline}${newline}[/etc/pam.d/login]${newline}${pam_login_output}"
        command_executed="${command_executed}; ps -ef | grep -E 'inetd|telnetd'; netstat -an | grep ':23 '; grep -E '^[\\s]*pts' /etc/securetty; grep -E '^[\\s]*auth.*required.*pam_securetty.so' /etc/pam.d/login"
    else
        local telnet_ps_check=$(ps -ef 2>/dev/null | grep -E "inetd" | grep -v grep || echo "No telnet process found")
        command_result="${command_result}[Telnet Service Status]${newline}${telnet_ps_check}"
        command_executed="${command_executed}; ps -ef | grep inetd"
    fi

    # -------------------------------------------------------------------------
    # 5. 최종 판정
    # -------------------------------------------------------------------------
    if [ "$is_secure" = true ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="root 계정 원격 접속 제한 적절 (${config_details})"
    elif [ "$ssh_manual" = true ] && [ "$telnet_secure" = true ]; then
        # SSH 설정 파일 미확인(수동진단)이며 다른 확인된 취약 요소 없음 → MANUAL 유지
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="SSH 설정 파일을 찾을 수 없어 PermitRootLogin 설정을 확인하지 못함 - 수동 점검 필요 (${config_details})"
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
