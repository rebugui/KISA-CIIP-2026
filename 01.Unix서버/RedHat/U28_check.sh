#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-28
# ============================================================================
# [점검 항목 상세]
# @ID          : U-28
# @Category    : UNIX > 3. 서비스 관리
# @Platform    : RedHat
# @Severity    : 상
# @Title       : 접속 IP 및 포트 제한
# @Description : 허용할 호스트에 대한 접속 IP주소 제한 및 포트 제한 설정 여부 점검
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

ITEM_ID="U-28"
ITEM_NAME="접속 IP 및 포트 제한"
SEVERITY="상"

# 가이드라인 정보 (PDF 55페이지 내용 반영)
GUIDELINE_PURPOSE="허용한 호스트만 서비스를 사용하게하여 서비스 취약점을 이용한 외부자 공격을 방지하기 위함"
GUIDELINE_THREAT="허용할 호스트에 대한 IP 및 포트 제한이 적용되지 않을 경우, Telnet, FTP 같은 보안에 취약한 네트워크 서비스를 통하여 불법적인 접근 및 시스템 침해 사고가 발생할 수 있는 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="접속을 허용할 특정 호스트에 대한 IP 주소 및 포트 제한을 설정한 경우"
GUIDELINE_CRITERIA_BAD="접속을 허용할 특정 호스트에 대한 IP 주소 및 포트 제한을 설정하지 않은 경우"
GUIDELINE_REMEDIATION="OS에 기본으로 제공하는 방화벽 애플리케이션이나 TCP Wrapper와 같은 호스트별 서비스 제한 애플리케이션을 사용하여 접근 허용 IP 등록 설정"

diagnose() {
    # [중요] 파싱 에러 방지를 위한 기존 변수 초기값 유지
    local status="양호"
    diagnosis_result="GOOD"
    local inspection_summary="접속 IP 및 포트 제한 설정이 적절합니다."
    local command_result=""
    local command_executed="cat /etc/hosts.allow /etc/hosts.deny"

    # 1. 실제 데이터 추출: TCP Wrapper 설정 확인
    local allow_content=$(cat /etc/hosts.allow 2>/dev/null | grep -v "^#" | xargs || echo "empty")
    local deny_content=$(cat /etc/hosts.deny 2>/dev/null | grep -v "^#" | xargs || echo "empty")

    # 2. 판정 로직: hosts.deny에 ALL: ALL 설정이 있는지 확인 (기본적인 접근 차단 정책)
    if ! grep -qi "ALL: ALL" /etc/hosts.deny 2>/dev/null; then
        status="취약"
        diagnosis_result="VULNERABLE"
        inspection_summary="접속 IP 및 포트 제한 설정(TCP Wrapper)이 미흡합니다."
    fi

    # 3. command_result에 실제 설정값 기록 (증적 데이터)
    command_result="[hosts.allow]: ${allow_content} | [hosts.deny]: ${deny_content}"

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
