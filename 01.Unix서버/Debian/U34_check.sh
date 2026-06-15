#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : U-34
# @Category    : Unix Server
# @Platform    : Debian
# @Severity    : 상
# @Title       : Finger 서비스 비활성화
# @Description : Finger 서비스 비활성화 여부 확인
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


ITEM_ID="U-34"
ITEM_NAME="Finger 서비스 비활성화"
SEVERITY="상"

# 가이드라인 정보
GUIDELINE_PURPOSE="Finger 서비스를 통해 네트워크 외부에서 해당 시스템에 등록된 사용자 정보를 확인할 수 있어 비인가자에게 사용자 정보가 조회되는 것을 방지하기 위함"
GUIDELINE_THREAT="Finger 서비스가 활성화되어 있을 경우, 비인가자가 Finger 서비스를 사용하여 사용자 정보를 조회한 후 비밀번호 공격을 통해 계정을 탈취할 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="Finger 서비스가 비활성화된 경우"
GUIDELINE_CRITERIA_BAD="Finger 서비스가 활성화된 경우"
GUIDELINE_REMEDIATION="Finger 서비스 비활성화 설정"

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
    # Finger 서비스 비활성화 여부 점검
    # 가이드라인: Finger 서비스가 비활성화된 경우 양호

    local finger_active=false
    local raw_output=""

    # 1) systemctl 확인
    if command -v systemctl >/dev/null 2>&1 && systemctl --version >/dev/null 2>&1; then
        if systemctl is-active --quiet finger 2>/dev/null || systemctl is-active --quiet fingerd 2>/dev/null; then
            finger_active=true
            raw_output="[systemctl] Finger 서비스 실행 중"
        fi
    fi

    # 2) inetd/xinetd 설정 확인
    if [ "$finger_active" = false ]; then
        # /etc/inetd.conf 확인
        if [ -f /etc/inetd.conf ]; then
            local inetd_finger=$(grep -v "^#" /etc/inetd.conf 2>/dev/null | grep -i "finger" || echo "")
            if [ -n "$inetd_finger" ]; then
                finger_active=true
                raw_output="${raw_output}[/etc/inetd.conf]${inetd_finger}"
            fi
        fi

        # /etc/xinetd.d/finger 확인 (disable 항목이 없거나 yes가 아니면 활성화 - xinetd 기본값: 활성)
        if [ -f /etc/xinetd.d/finger ]; then
            local xinetd_disabled=$(grep -E '^[[:space:]]*disable' /etc/xinetd.d/finger 2>/dev/null | awk -F= '{gsub(/[[:space:]]/,"",$2); print $2}' | tail -1 || echo "")
            xinetd_disabled=$(echo "$xinetd_disabled" | tr '[:upper:]' '[:lower:]')
            if [ "$xinetd_disabled" != "yes" ]; then
                finger_active=true
                raw_output="${raw_output}[/etc/xinetd.d/finger] 활성화됨 (disable=${xinetd_disabled:-없음})"
            fi
        fi
    fi

    # 3) 프로세스 확인
    if [ "$finger_active" = false ]; then
        local finger_ps=$(ps aux 2>/dev/null | grep -E "in\.fingerd|fingerd" | grep -v grep || echo "")
        if [ -n "$finger_ps" ]; then
            finger_active=true
            raw_output="${raw_output}[Process]${finger_ps}"
        fi
    fi

    # 4) finger 패키지 설치 확인 (정보성)
    local finger_pkg=""
    if command -v dpkg >/dev/null 2>&1; then
        finger_pkg=$(dpkg -l 2>/dev/null | grep -i "finger" | grep "^ii" || echo "")
    fi

    # 최종 판정
    if [ "$finger_active" = true ]; then
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="Finger 서비스가 활성화되어 있음"
        command_result="${raw_output}${newline}[Package]${finger_pkg:-미설치}"
        command_executed="systemctl status finger fingerd 2>/dev/null; grep finger /etc/inetd.conf 2>/dev/null; ps aux | grep fingerd"
    else
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="Finger 서비스가 비활성화됨"
        command_result="${raw_output}${newline}[Package]${finger_pkg:-미설치}"
        command_executed="systemctl status finger fingerd 2>/dev/null; grep finger /etc/inetd.conf 2>/dev/null"
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
