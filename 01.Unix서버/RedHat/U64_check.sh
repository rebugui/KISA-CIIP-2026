#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-04-20
# ============================================================================
# [점검 항목 상세]
# @ID          : U-64
# @Category    : UNIX > 3. 서비스 관리
# @Platform    : SOLARIS, LINUX, AIX, HP-UX 등
# @Severity    : (상)
# @Title       : 주기적 보안 패치 적용
# @Description : OS 보안 패치 적용 상태 및 패치 관리 정책 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/metadata_parser.sh"

ITEM_ID="U-64"
ITEM_NAME="주기적 보안 패치 적용"
SEVERITY="상"

GUIDELINE_PURPOSE="주기적인 패치 적용을 통해 시스템 안정성 및 보안성을 확보하기 위함"
GUIDELINE_THREAT="최신 보안 패치가 적용되지 않을 경우, 이미 알려진 취약점을 통하여 공격자에 의해 시스템 침해 사고 발생할 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="패치 적용 정책을 수립하여 주기적으로 패치 관리를 하고 있으며, 패치 관련 내용을 확인하고 적용하였을 경우"
GUIDELINE_CRITERIA_BAD="패치 적용 정책이 미수립되었거나 주기적으로 패치 관리를 하지 않는 경우"
GUIDELINE_REMEDIATION="OS 관리자, 서비스 개발자가 패치 적용에 따른 서비스 영향 정도를 파악하여 OS 관리자 및 벤더에서 적용하도록 설정"

diagnose() {
    diagnosis_result="MANUAL"
    local status="수동진단"
    local inspection_summary=""
    local command_result=""
    local command_executed=""
    local newline=$'\n'

    # ==========================================================================
    # 1. 패치 관리는 수동 확인이 필요한 항목
    #    - 패치 정책 수립 여부는 문서 확인 필요
    #    - 보안 패치 적용 이력은 확인 가능하나 정책 판단은 수동
    # ==========================================================================

    # 최근 패치 이력 수집 (참고 정보)
    local patch_info=""

    if command -v rpm >/dev/null 2>&1; then
        # RHEL: 최근 업데이트된 패키지 확인
        local recent_patches=$(rpm -qa --last 2>/dev/null | head -10 || echo "확인 불가")
        local kernel_ver=$(rpm -q kernel 2>/dev/null | tail -1 || echo "확인 불가")

        patch_info="Kernel: ${kernel_ver}${newline}${newline}최근 업데이트 패키지 (최대 10개):${newline}${recent_patches}"
        command_executed="rpm -qa --last | head -10; rpm -q kernel"
    else
        patch_info="패치 이력 확인 불가 (rpm 명령어 없음)"
        command_executed="rpm -qa --last"
    fi

    inspection_summary="패치 적용 정책 수립 및 주기적 패치 관리 여부는 수동 확인이 필요합니다."
    command_result="${patch_info}"

    command_result=$(echo "$command_result" | tr -d '\n\r')

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
