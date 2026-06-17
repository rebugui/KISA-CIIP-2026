#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : U-36
# @Category    : Unix Server
# @Platform    : Debian
# @Severity    : 상
# @Title       : r 계열 서비스 비활성화
# @Description : rlogin, rsh, rexec 서비스 비활성화 여부 확인
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


ITEM_ID="U-36"
ITEM_NAME="r 계열 서비스 비활성화"
SEVERITY="상"

# 가이드라인 정보
GUIDELINE_PURPOSE="r-command 사용을 통한 원격 접속은 NET Backup 또는 클러스터 링 등 용도로 사용되기도하나, 인증 없이 관리자 원격 접속이 가능하여 이에 대한 보안 위협을 방지하기 위함"
GUIDELINE_THREAT="rlogin, rsh, rexec 등의 r-command를 이용하여 원격에서 인증 절차 없이 터미널 접속, 쉘 명령어를 실행이 가능한 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="불필요한 r 계열 서비스가 비활성화된 경우"
GUIDELINE_CRITERIA_BAD="불필요한 r 계열 서비스가 활성화된 경우"
GUIDELINE_REMEDIATION="불필요한 r 계열 서비스 중지 및 비활성화 설정 ※ NET Backup 등 특별한 용도로 사용하지 않는다면 shell(514), login(513), exec(512)서비스 중 지 ※ rlogin, rsh, rexec 서비스는 backup, 클러스터 링 등의 용도로 종종 사용되고 있으므로 해당 서 비 스 사용 유무를 확인하여 미사용 시 서비스 중지 ※ /etc/hosts.equiv 또는 \$HOME/.rhosts 파일을 통해 해당 서비스 사용 여부 확인 (파일이 존재하지 않거나 해당 파일 내에 설정이 없다면 사용하지 않는 것으로 간주)"

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
    # r 계열 서비스 (rlogin, rsh, rexec) 비활성화 여부 점검
    # 가이드라인: 불필요한 r 계열 서비스가 비활성화된 경우 양호

    local r_services_active=false
    local active_services=""
    local raw_output=""

    # r-command 서비스 목록
    local r_services=("rlogin" "rsh" "rexec" "shell" "login" "exec")
    local r_ports=("513" "514" "512")

    # 1) systemctl 확인
    if command -v systemctl >/dev/null 2>&1 && systemctl --version >/dev/null 2>&1; then
        for svc in rlogin rsh rexec rsh.socket rlogin.socket; do
            if systemctl is-active --quiet "$svc" 2>/dev/null; then
                r_services_active=true
                active_services="${active_services}${svc} "
                raw_output="${raw_output}[systemctl] ${svc} 실행 중${newline}"
            fi
        done
    fi

    # 2) inetd/xinetd 설정 확인
    if [ "$r_services_active" = false ]; then
        # /etc/inetd.conf 확인
        if [ -f /etc/inetd.conf ]; then
            local inetd_r=$(grep -v "^#" /etc/inetd.conf 2>/dev/null | grep -iE "rlogin|rsh|rexec|shell|exec" | grep -v "bash" || echo "")
            if [ -n "$inetd_r" ]; then
                r_services_active=true
                active_services="${active_services}inetd.conf "
                raw_output="${raw_output}[/etc/inetd.conf]${inetd_r}${newline}"
            fi
        fi

        # /etc/xinetd.d/ 확인
        for svc_file in rlogin rsh rexec; do
            if [ -f "/etc/xinetd.d/$svc_file" ]; then
                local xinetd_disabled=$(grep -E '^[[:space:]]*disable' "/etc/xinetd.d/$svc_file" 2>/dev/null | awk -F= '{gsub(/[[:space:]]/,"",$2); print $2}' | tail -1 || echo "")
                xinetd_disabled=$(echo "$xinetd_disabled" | tr '[:upper:]' '[:lower:]')
                if [ "$xinetd_disabled" != "yes" ]; then
                    r_services_active=true
                    active_services="${active_services}${svc_file} "
                    raw_output="${raw_output}[/etc/xinetd.d/${svc_file}] 활성화됨${newline}"
                fi
            fi
        done
    fi

    # 3) 프로세스 및 포트 확인
    if [ "$r_services_active" = false ]; then
        local r_ps=$(ps aux 2>/dev/null | grep -E "rlogind|rshd|rexecd|in\.rlogin|in\.rsh|in\.rexec" | grep -v grep || echo "")
        if [ -n "$r_ps" ]; then
            r_services_active=true
            raw_output="${raw_output}[Process]${r_ps}${newline}"
        fi

        # 포트 확인 (513=rlogin, 514=rsh/shell, 512=exec)
        for port in "${r_ports[@]}"; do
            local port_check=$(ss -tlnp 2>/dev/null | grep ":${port} " || netstat -tlnp 2>/dev/null | grep ":${port} " || echo "")
            if [ -n "$port_check" ]; then
                r_services_active=true
                raw_output="${raw_output}[Port ${port}]${port_check}${newline}"
            fi
        done
    fi

    # 4) hosts.equiv / .rhosts 확인 (정보성)
    local hosts_equiv=""
    if [ -f /etc/hosts.equiv ]; then
        hosts_equiv=$(cat /etc/hosts.equiv 2>/dev/null | grep -v "^#" | grep -v "^$" || echo "")
    fi

    # 최종 판정
    if [ "$r_services_active" = true ]; then
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="r 계열 서비스가 활성화됨: ${active_services}"
        command_result="${raw_output}[hosts.equiv]${hosts_equiv:-없음}"
        command_executed="systemctl status rlogin rsh rexec 2>/dev/null; grep -iE 'rlogin|rsh|rexec' /etc/inetd.conf 2>/dev/null; ss -tlnp | grep -E ':51[234]'"
    else
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="r 계열 서비스가 비활성화됨"
        command_result="${raw_output}[hosts.equiv]${hosts_equiv:-없음}"
        command_executed="systemctl status rlogin rsh rexec 2>/dev/null; grep -iE 'rlogin|rsh|rexec' /etc/inetd.conf 2>/dev/null"
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
