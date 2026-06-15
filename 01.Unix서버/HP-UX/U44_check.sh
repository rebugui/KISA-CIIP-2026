#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : U-44
# @Category    : Unix Server
# @Platform    : HP-UX
# @Severity    : 상
# @Title       : tftp, talk 서비스 비활성화
# @Description : tftp, talk 서비스 중지 확인
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


ITEM_ID="U-44"
ITEM_NAME="tftp, talk 서비스 비활성화"
SEVERITY="상"

# 가이드라인 정보
GUIDELINE_PURPOSE="안전하지 않거나 불필요한 서비스를 제거함으로써 시스템 보안성 및 리소스의 효율적 운용하기 위함"
GUIDELINE_THREAT="사용하지 않는 서비스나 취약점이 발표된 서비스 운용 시 공격 시도 가능한 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="tftp, talk, ntalk 서비스가 비활성화된 경우"
GUIDELINE_CRITERIA_BAD="tftp, talk, ntalk 서비스가 활성화된 경우"
GUIDELINE_REMEDIATION="불필요한 tftp, talk, ntalk 서비스 비활성화 설정"

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

    # tftp, talk 서비스 비활성화 확인
    local services_running=false
    local service_info=""
    local running_services=()

    # 1) tftp 서비스 확인
    if [ -f /sbin/init.d/tftp ]; then
        local active=$(/sbin/init.d/tftp status 2>/dev/null | grep -q "running" 2>/dev/null && echo "active" || echo "inactive")
        service_info="${service_info}tftp: ${active}\\n"
        if [ "$active" = "active" ]; then
            services_running=true
            running_services+=("tftp")
        fi
    fi

    # in.tftpd (inetd/xinetd 기반) 확인
    if [ -f /etc/xinetd.d/tftp ]; then
        local disabled=$(grep -E '^[[:space:]]*disable' /etc/xinetd.d/tftp 2>/dev/null | awk -F= '{gsub(/[[:space:]]/,"",$2); print $2}' | tail -1 || echo "")
        service_info="${service_info}xinetd tftp: disable=${disabled:-없음}\\n"
        # xinetd 기본값: disable 항목이 없으면 서비스 활성화 상태
        if [ "$disabled" != "yes" ]; then
            services_running=true
            running_services+=("tftp(xinetd)")
        fi
    fi

    # 2) talk/ntalk 서비스 확인
    for svc in talk ntalk; do
        if [ -f /sbin/init.d/"$svc" ]; then
            local active=$(/sbin/init.d/"$svc" status 2>/dev/null | grep -q "running" 2>/dev/null && echo "active" || echo "inactive")
            service_info="${service_info}${svc}: ${active}\\n"
            if [ "$active" = "active" ]; then
                services_running=true
                running_services+=("$svc")
            fi
        fi
    done || true

    # tftpd/talkd/ntalkd (inetd 기반) 확인
    if [ -f /etc/inetd.conf ]; then
        local tftp_inetd=$(grep -E "^tftp" /etc/inetd.conf | grep -v "^#" || echo "")
        if [ -n "$tftp_inetd" ]; then
            services_running=true
            running_services+=("tftp(inetd)")
            service_info="${service_info}inetd tftp 활성화됨\\n"
        fi
        local talk_services=$(grep -E "^talk|^ntalk" /etc/inetd.conf | grep -v "^#" || echo "")
        if [ -n "$talk_services" ]; then
            services_running=true
            running_services+=("talk(inetd)")
            service_info="${service_info}inetd talk 활성화됨\\n"
        fi
    fi

    # 3) 포트 확인 (tftp: 69/udp, talk: 517/518)
    if command -v ss &>/dev/null; then
        local tftp_port=$(ss -uln | grep ":69 " || echo "")
        local talk_port=$(ss -tuln | grep -E ":517 |:518 " || echo "")

        if [ -n "$tftp_port" ]; then
            services_running=true
            service_info="${service_info}UDP 포트 69 (tftp) 활성화\\n"
        fi

        if [ -n "$talk_port" ]; then
            services_running=true
            service_info="${service_info}포트 517/518 (talk) 활성화\\n"
        fi
    fi

    # 최종 판정
    if [ "$services_running" = false ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="tftp, talk 서비스 비활성화됨"
        local service_check=$(/sbin/init.d/tftp status 2>/dev/null | head -2; /sbin/init.d/talk status 2>/dev/null | head -2; /sbin/init.d/ntalk status 2>/dev/null | head -2; ss -tuln 2>/dev/null | grep -E ':69|:517|:518' || echo "Services not running")
        command_result="${service_check}"
        command_executed="/sbin/init.d/tftp status; /sbin/init.d/talk status; /sbin/init.d/ntalk status; ss -tuln | grep -E ':69|:517|:518'"
    else
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="불필요한 서비스 활성화됨: ${running_services[*]}"
        command_result="${service_info}"
        command_executed="/sbin/init.d/tftp status; /sbin/init.d/talk status; /sbin/init.d/ntalk status; grep -E '^tftp|^talk|^ntalk' /etc/inetd.conf"
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
