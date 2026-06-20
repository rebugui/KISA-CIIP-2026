#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : U-38
# @Category    : Unix Server
# @Platform    : Debian
# @Severity    : 상
# @Title       : DoS 공격에 취약한 서비스 비활성화
# @Description : echo, chargen, daytime 등 비활성화
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


ITEM_ID="U-38"
ITEM_NAME="DoS 공격에 취약한 서비스 비활성화"
SEVERITY="상"

# 가이드라인 정보
GUIDELINE_PURPOSE="많은 취약점을 가진 echo, discard, daytime, chargen, ntp, snmp 등의 서비스를 중지하여 시스템의 보안성을 높이기 위함"
GUIDELINE_THREAT="해당 서비스가 활성화된 경우, 시스템 정보 유출 및 DoS 공격의 대상이 될 수 있는 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="DoS 공격에"
GUIDELINE_CRITERIA_BAD="DoS 공격에 취약한 서비스가 활성화된 경우"
GUIDELINE_REMEDIATION="echo, discard, daytime, chargen, ntp, dns,snmp 등의 서비스 비활성화 설정"

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

    # DoS 취약 서비스 비활성화 확인 (echo, chargen, daytime, discard, time, etc.)
    local vulnerable_services=("echo" "chargen" "daytime" "discard" "time")
    local is_secure=true
    local enabled_services=()
    local service_status=""

    # 1) inetd/xinetd 기반 서비스 확인
    if [ -f /etc/inetd.conf ]; then
        service_status="${service_status}${newline}/etc/inetd.conf 확인:${newline}"
        for svc in "${vulnerable_services[@]}"; do
            if grep -q "^${svc}" /etc/inetd.conf 2>/dev/null; then
                # 주석 처리되었는지 확인
                if grep "^${svc}" /etc/inetd.conf | grep -q -v "^#"; then
                    is_secure=false
                    enabled_services+=("inetd: ${svc}")
                    service_status="${service_status}  ${svc}: 활성화됨${newline}"
                else
                    service_status="${service_status}  ${svc}: 주석 처리됨${newline}"
                fi
            fi
        done || true
    fi

    # 2) xinetd.d 디렉토리 확인
    if [ -d /etc/xinetd.d ]; then
        service_status="${service_status}${newline}/etc/xinetd.d 확인:${newline}"
        for svc in "${vulnerable_services[@]}"; do
            if [ -f "/etc/xinetd.d/${svc}" ]; then
                local disabled=$(grep -i "disable" /etc/xinetd.d/${svc} | grep -v "^#" | awk -F= '{gsub(/[[:space:]]/,"",$2); print $2}' | head -1)
                if [ "$disabled" != "yes" ]; then
                    is_secure=false
                    enabled_services+=("xinetd: ${svc}")
                    service_status="${service_status}  ${svc}: 활성화됨 (disable=${disabled})${newline}"
                else
                    service_status="${service_status}  ${svc}: 비활성화됨${newline}"
                fi
            fi
        done || true
    fi

    # 3) systemd 서비스 확인
    service_status="${service_status}${newline}systemd 서비스 확인:${newline}"
    for svc in "${vulnerable_services[@]}"; do
        if systemctl list-unit-files | grep -q "^${svc}.service"; then
            local active=$(systemctl is-active "${svc}.service" 2>/dev/null || echo "inactive")
            local enabled=$(systemctl is-enabled "${svc}.service" 2>/dev/null || echo "disabled")
            service_status="${service_status}  ${svc}: ${active}, ${enabled}${newline}"

            if [ "$active" = "active" ]; then
                is_secure=false
                enabled_services+=("systemd: ${svc}")
            fi
        fi
    done || true

    # 4) 포트 스캔 (echo: 7/tcp/udp, chargen: 19/tcp/udp, daytime: 13/tcp/udp)
    if command -v ss &>/dev/null; then
        service_status="${service_status}${newline}포트 확인:${newline}"
        local ports=("7" "13" "19")
        for port in "${ports[@]}"; do
            local listening=$(ss -tuln | grep ":${port} " || echo "")
            if [ -n "$listening" ]; then
                is_secure=false
                service_status="${service_status}  포트 ${port}: 활성화됨${newline}"
            fi
        done || true
    fi

    # 최종 판정
    if [ "$is_secure" = true ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="DoS 취약 서비스 비활성화됨"
        command_result="${service_status}"
        command_executed="grep -iE '^echo|^chargen|^daytime' /etc/inetd.conf 2>/dev/null; systemctl list-unit-files | grep -E 'echo|chargen|daytime'; ss -tuln | grep -E ':7|:13|:19'"
    else
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="DoS 취약 서비스 활성화됨: ${enabled_services[*]}"
        command_result="${service_status}"
        command_executed="grep -iE '^echo|^chargen|^daytime' /etc/inetd.conf 2>/dev/null; systemctl is-active echo chargen daytime 2>/dev/null"
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
