#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.2
# @Last Updated: 2026-04-23
# ============================================================================
# [점검 항목 상세]
# @ID          : U-36
# @Category    : Unix Server
# @Platform    : AIX
# @Severity    : 상
# @Title       : r 계열 서비스 비활성화
# @Description : rlogin, rsh, rexec 등 보안에 취약한 서비스의 활성화 여부 점검
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

diagnose() {

    diagnosis_result="unknown"
    local status="미진단"
    local inspection_summary=""
    local command_result=""
    local command_executed=""
    local newline=$'\n'

    local is_secure=true
    local active_services=()
    local service_status=""

    # 확인할 r 계열 서비스 목록
    local r_services=("rsh" "rlogin" "rexec")

    # 1) AIX lssrc로 서비스 상태 확인
    for service in "${r_services[@]}"; do
        local state=$(lssrc -s "$service" 2>/dev/null | grep "$service" | awk '{print $2}' || echo "inoperative")
        if [ "$state" = "active" ]; then
            is_secure=false
            active_services+=("${service} (active)")
        fi
        service_status="${service_status}${service}: ${state}\\n"
    done || true

    # 2) AIX inetd.conf 확인 (rsh, rlogin, rexec는 inetd에서 관리)
    if [ -f /etc/inetd.conf ]; then
        for inetd_service in rsh rlogin rexec; do
            local inetd_entry=$(grep "^${inetd_service}" /etc/inetd.conf 2>/dev/null | grep -v "^#" || echo "")
            if [ -n "$inetd_entry" ]; then
                is_secure=false
                active_services+=("${inetd_service} (inetd enabled)")
                service_status="${service_status}${inetd_service}: inetd.conf에서 활성화됨\\n"
            fi
        done || true
    fi

    # 3) 프로세스 확인
    local r_procs=$(ps -ef 2>/dev/null | grep -Ei "rshd|rlogind|rexecd" | grep -v grep || echo "")
    if [ -n "$r_procs" ]; then
        is_secure=false
        active_services+=("r-command 프로세스 실행 중")
    fi

    # 명령어 결과 수집
    local lssrc_raw=""
    for svc in rsh rlogin rexec; do
        lssrc_raw="${lssrc_raw}$(lssrc -s "$svc" 2>/dev/null || echo "${svc}: service not found")${newline}"
    done
    local inetd_raw=""
    if [ -f /etc/inetd.conf ]; then
        inetd_raw=$(grep -E "^rsh|^rlogin|^rexec" /etc/inetd.conf 2>/dev/null || echo "No r-service entries in inetd.conf")
    fi

    # 최종 판정
    if [ "$is_secure" = true ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="r 계열 서비스가 비활성화되어 있습니다."
        command_result="[Command: lssrc]${newline}${lssrc_raw}${newline}[Command: grep inetd.conf]${newline}${inetd_raw}"
        command_executed="lssrc -s rsh; lssrc -s rlogin; lssrc -s rexec; grep -E '^rsh|^rlogin|^rexec' /etc/inetd.conf"
    else
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="r 계열 서비스가 활성화되어 있습니다: ${active_services[*]}"
        command_result="[Command: lssrc]${newline}${lssrc_raw}${newline}[Command: grep inetd.conf]${newline}${inetd_raw}"
        command_executed="lssrc -s rsh; lssrc -s rlogin; lssrc -s rexec; grep -E '^rsh|^rlogin|^rexec' /etc/inetd.conf"
    fi

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

    verify_result_saved "${ITEM_ID}"

    return 0
}

# ============================================================================
# 메인 실행
# ============================================================================

main() {
    show_diagnosis_start "${ITEM_ID}" "${ITEM_NAME}"

    check_disk_space

    diagnose

    show_diagnosis_complete "${ITEM_ID}" "${diagnosis_result:-UNKNOWN}"

    return 0
}

# 스크립트 직접 실행 시에만 진단 수행
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi
