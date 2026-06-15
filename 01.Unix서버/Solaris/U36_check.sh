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
# @Platform    : Solaris
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
    # r 계열 서비스 (rsh, rlogin, rexec) 비활성화 여부 점검
    # 가이드라인: 불필요한 r 계열 서비스가 비활성화된 경우 양호
    # Solaris 10+: SMF(svcs/inetadm), Solaris 9 이하: /etc/inetd.conf

    local r_services_active=false
    local probe_available=false
    local active_services=""
    local raw_output=""
    local r_fmri_pattern='network/(shell|login|rexec)|rsh|rlogin|rexec'

    # 1) SMF 서비스 상태 확인 (Solaris 10 이상)
    if command -v svcs >/dev/null 2>&1; then
        probe_available=true
        local svcs_out
        svcs_out=$(svcs -H -o state,fmri 2>/dev/null | grep -E "${r_fmri_pattern}" || echo "")
        local svcs_online
        svcs_online=$(echo "$svcs_out" | grep -E '^(online|degraded)[[:space:]]' || echo "")
        if [ -n "$svcs_online" ]; then
            r_services_active=true
            active_services="${active_services}SMF(svcs) "
            raw_output="${raw_output}[svcs -H -o state,fmri]${newline}${svcs_online}${newline}"
        else
            raw_output="${raw_output}[svcs -H -o state,fmri] r 계열 서비스(shell/login/rexec) online 항목 없음${newline}"
        fi
    fi

    # 2) inetadm 확인 (svcs 부재 시 보조)
    if [ "$probe_available" = false ] && command -v inetadm >/dev/null 2>&1; then
        probe_available=true
        local inetadm_out
        inetadm_out=$(inetadm 2>/dev/null | grep -E 'network/(shell|login|rexec)' | grep -i 'enabled' || echo "")
        if [ -n "$inetadm_out" ]; then
            r_services_active=true
            active_services="${active_services}inetadm(enabled) "
            raw_output="${raw_output}[inetadm]${newline}${inetadm_out}${newline}"
        else
            raw_output="${raw_output}[inetadm] r 계열 서비스(shell/login/rexec) enabled 항목 없음${newline}"
        fi
    fi

    # 3) 레거시 /etc/inetd.conf 확인 (Solaris 9 이하, 주석 해제된 shell/login/exec = 활성화)
    if [ "$probe_available" = false ] && [ -r /etc/inetd.conf ]; then
        probe_available=true
        local inetd_r
        inetd_r=$(grep -E '^(shell|login|exec)[[:space:]]' /etc/inetd.conf 2>/dev/null || echo "")
        if [ -n "$inetd_r" ]; then
            r_services_active=true
            active_services="${active_services}inetd.conf(shell/login/exec) "
            raw_output="${raw_output}[/etc/inetd.conf]${newline}${inetd_r}${newline}"
        else
            raw_output="${raw_output}[/etc/inetd.conf] shell/login/exec 항목이 주석 처리되었거나 존재하지 않음${newline}"
        fi
    fi

    # 4) r 계열 포트 LISTEN 확인 (512=exec, 513=login, 514=shell)
    local r_port
    r_port=$(netstat -an 2>/dev/null | grep -E '\.51[234][[:space:]].*LISTEN' || echo "")
    if [ -n "$r_port" ]; then
        r_services_active=true
        active_services="${active_services}port(512/513/514) "
        raw_output="${raw_output}[netstat -an]${newline}${r_port}${newline}"
    else
        raw_output="${raw_output}[netstat -an] 512/513/514 포트 LISTEN 없음${newline}"
    fi

    # 최종 판정
    command_executed="svcs -H -o state,fmri | grep -E '${r_fmri_pattern}'; inetadm | grep -E 'network/(shell|login|rexec)'; grep -E '^(shell|login|exec)[[:space:]]' /etc/inetd.conf; netstat -an | grep -E '\\.51[234] .*LISTEN'"
    command_result="${raw_output}"

    if [ "$r_services_active" = true ]; then
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="r 계열 서비스가 활성화됨: ${active_services}"
    elif [ "$probe_available" = true ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="r 계열 서비스(rsh/rlogin/rexec)가 비활성화됨"
    else
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="svcs/inetadm 명령 및 /etc/inetd.conf를 사용할 수 없어 r 계열 서비스 활성화 여부를 판정할 수 없음 (수동 확인 필요)"
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
