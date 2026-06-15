#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-28
# ============================================================================
# [점검 항목 상세]
# @ID          : U-49
# @Category    : UNIX > 3. 서비스 관리
# @Platform    : RedHat
# @Severity    : 상
# @Title       : DNS 보안 버전 패치
# @Description : DNS 서비스(BIND)의 최신 보안 패치 적용 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/metadata_parser.sh"

ITEM_ID="U-49"
ITEM_NAME="DNS 보안 버전 패치"
SEVERITY="상"

GUIDELINE_PURPOSE="취약점이 발표되지 않은 BIND 버전을 사용하여 시스템 보안성을 높이기 위함"
GUIDELINE_THREAT="취약점이 내포된 BIND 버전을 사용할 경우, DoS 공격, 버퍼 오버 플로우(Buffer Overflow) 및 DNS 서버 원격 침입 등의 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="주기적으로 패치를 관리하는 경우"
GUIDELINE_CRITERIA_BAD="주기적으로 패치를 관리하고 있지 않은 경우"
GUIDELINE_REMEDIATION="DNS 서비스를 사용하지 않는 경우 서비스 중지 및 비활성화 설정 DNS 서비스 사용 시 패치 관리 정책 수립 및 주기적으로 패치 적용 설정 ※ DNS 서비스의 경우 대부분의 버전에서 취약점이 보고되고 있으므로 OS 관리자, 서비스 개발자가 패치 적용에 따른 서비스 영향 정도를 정확히 파악하여 주기적인 패치 적용 정책 수리 후 적용"

diagnose() {
    local status="미진단"
    diagnosis_result="unknown"
    local inspection_summary=""
    local command_result=""
    local command_executed=""
    local newline=$'\n'

    # DNS 보안 버전 패치 확인
    local dns_installed=false
    local dns_info=""

    # 1) BIND(named) 설치 및 버전 확인
    if command -v named &>/dev/null; then
        dns_installed=true
        local bind_version=$(named -v 2>/dev/null || echo "Unknown")
        dns_info="${dns_info}BIND 버전: ${bind_version}\\n"

        # 버전에서 메이저/마이너 번호 추출
        local version_number=$(echo "$bind_version" | sed -n 's/^[^0-9]*\([0-9][0-9]*\.[0-9][0-9]*\).*/\1/p' | head -1 || true)
        dns_info="${dns_info}버전 번호: ${version_number}\\n"
    fi

    # 2) bind9-utils 확인
    if rpm -qa | grep -q "bind9-utils"; then
        dns_installed=true
        local bind_version=$(rpm -qa | grep "bind9-utils" | awk '{print $1}' | head -1)
        dns_info="${dns_info}설치된 bind9-utils 버전: ${bind_version}\\n"
    fi

    # 3) DNS 서비스 실행 확인
    if systemctl is-active --quiet named 2>/dev/null; then
        dns_installed=true
        dns_info="${dns_info}DNS 서비스 실행 중\\n"
    fi

    # 4) 포트 확인 (DNS: 53)
    if command -v ss &>/dev/null; then
        local dns_port=$(ss -tuln | grep ":53 " || echo "")
        if [ -n "$dns_port" ]; then
            dns_installed=true
            dns_info="${dns_info}DNS 포트 53 활성화\\n"
        fi
    fi

    # 최종 판정
    if [ "$dns_installed" = false ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="DNS 서비스 미설치됨"
        local cmd_check=$(command -v named 2>/dev/null || echo "named not found")
        local svc_check=$(systemctl is-active --quiet named 2>/dev/null && echo "named: active" || echo "named: inactive")
        local ss_out=$(ss -tuln | grep ":53 " 2>/dev/null || echo "DNS ports not listening")
        command_result="[Command: command -v named]${newline}${cmd_check}${newline}${newline}[Command: ss -tuln | grep :53]${newline}${ss_out}"
        command_executed="command -v named; systemctl is-active --quiet named; ss -tuln | grep ':53'"
    else
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="DNS 서비스 설치됨 - 최신 보안 패치 적용 여부 수동 확인 필요"
        command_result="${dns_info}"
        command_executed="named -v; ss -tuln | grep ':53'"
    fi

    save_dual_result \
        "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" \
        "${inspection_summary}" "${command_result}" "${command_executed}" \
        "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" \
        "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" \
        "${GUIDELINE_REMEDIATION}"

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
