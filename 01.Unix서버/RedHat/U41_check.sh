#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-28
# ============================================================================
# [점검 항목 상세]
# @ID          : U-41
# @Category    : UNIX > 3. 서비스 관리
# @Platform    : RedHat
# @Severity    : 상
# @Title       : 불필요한 automountd 제거
# @Description : automountd(또는 autofs) 서비스의 활성화 여부를 점검하여 제거
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

ITEM_ID="U-41"
ITEM_NAME="불필요한 automountd 제거"
SEVERITY="상"

# 가이드라인 정보
GUIDELINE_PURPOSE="로컬 공격자가 automountd 데몬에 RPC(Remote Procedure Call)를 보낼 수 있는 취약점이 존재하기 때문에 해당 서비스를 중지시키기 위함"
GUIDELINE_THREAT="파일 시스템의 마운트 옵션을 변경하여 root 권한을 획득할 수 있으며, 로컬 공격자가 automountd 프로세스 권한으로 임의의 명령을 실행할 수 있는 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="automountd 서비스가 비활성화된 경우"
GUIDELINE_CRITERIA_BAD="automountd 서비스가 활성화된 경우"
GUIDELINE_REMEDIATION="automountd 서비스 비활성화 설정"

diagnose() {
    # [중요] 파싱 에러 방지를 위한 초기값 설정
    local status="양호"
    diagnosis_result="GOOD"
    local inspection_summary="automountd 서비스가 비활성화되어 있습니다."
    local command_result=""
    local command_executed="ps -ef | grep -Ei 'automount|autofs'"

    # 1. 실제 데이터 추출
    local auto_procs=$(ps -ef | grep -Ei "automount|autofs" | grep -v grep || echo "")

    # 2. 판정 로직
    if [ -n "$auto_procs" ]; then
        status="취약"
        diagnosis_result="VULNERABLE"
        inspection_summary="불필요한 automountd 서비스가 활성화되어 있습니다."
        command_result="실행 중인 프로세스: [ $(echo $auto_procs | awk '{print $8}' | xargs) ]"
    else
        command_result="automountd 관련 서비스가 발견되지 않았습니다."
    fi

    # [핵심 보정] JSON 파싱 에러 방지를 위해 모든 개행 문자 제거
    command_result=$(echo "$command_result" | tr -d '\n\r')

    # U-02와 동일하게 12개의 인자를 정확히 전달
    save_dual_result \
        "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" \
        "${inspection_summary}" "${command_result}" "${command_executed}" \
        "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" \
        "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
    
    verify_result_saved "${ITEM_ID}"
    return 0
}

main() {
    # [보강] 원본 실행 구조 복구
    show_diagnosis_start "${ITEM_ID}" "${ITEM_NAME}"
    [ "$EUID" -ne 0 ] && { echo "root 권한이 필요합니다."; exit 1; }
    diagnose
    show_diagnosis_complete "${ITEM_ID}" "${diagnosis_result}"
    exit 0
}

main "$@"
