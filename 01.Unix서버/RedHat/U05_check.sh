#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-04-20
# ============================================================================
# [점검 항목 상세]
# @ID          : U-05
# @Category    : UNIX > 1. 계정 관리
# @Platform    : RedHat
# @Severity    : 상
# @Title       : root 이외의 UID가 '0' 금지
# @Description : root 계정 외에 UID 0을 사용하는 계정 존재 여부 확인
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/metadata_parser.sh"

ITEM_ID="U-05"
ITEM_NAME="root 이외의 UID가 '0' 금지"
SEVERITY="상"

# 가이드라인 정보
GUIDELINE_PURPOSE="root 계정과 동일한 UID가 존재하는지 점검하여 root 권한이 일반 사용자 계정이나 비인가자의 접근 위협에 안전하게 보호되고 있는지 확인하기 위함"
GUIDELINE_THREAT="root 계정과 동일한 UID가 설정되어 있는 일반 사용자 계정도 root 권한을 부여받아 관리자가 실행할 수 있는 모든 작업이 가능한 위험이 존재함(서비스 시작, 중지, 재부팅, root 권한 파일 편집 등) root 계정과 동일한 UID를 사용하므로 사용자 감사 추적 시 어려움 발생 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="root 계정과 동일한 UID를 갖는 계정이 존재하지 않는 경우"
GUIDELINE_CRITERIA_BAD="root 계정과 동일한 UID를 갖는 계정이 존재하는 경우"
GUIDELINE_REMEDIATION="UID가 0으로 설정된 계정을 0 이외의 중복되지 않은 UID로 변경 또는 불필요한 계정인 경우 제거하도록 설정 (사용 중인 계정인 경우 명령어를 통한 조치가 적용되지 않을 수 있으므로 /etc/passwd 파일을 통해 변경)"

diagnose() {
    local status="양호"
    diagnosis_result="GOOD"
    local inspection_summary="UID 0인 계정이 root만 존재합니다."
    local command_result=""
    local command_executed="awk -F: '\$3 == 0 {print \$1}' /etc/passwd"

    # 1. 실제 데이터 추출: UID 0 계정 리스트
    local uid_zero_names=""
    uid_zero_names=$(awk -F: '$3 == 0 {print $1}' /etc/passwd 2>/dev/null) || uid_zero_names=""
    local uid_zero_users=$(printf '%s\n' "$uid_zero_names" | xargs | sed 's/ /, /g')
    local non_root_list=$(printf '%s\n' "$uid_zero_names" | awk 'NF && $0 != "root"' | xargs | sed 's/ /, /g')
    local user_count=$(printf '%s\n' "$uid_zero_names" | awk 'NF' | wc -l)

    # 2. 판정 로직: UID 0 계정의 이름이 모두 root인지 확인 (개수가 아닌 이름 기준)
    if [ -n "$non_root_list" ]; then
        status="취약"
        diagnosis_result="VULNERABLE"
        inspection_summary="root 이외에 UID 0을 사용하는 계정이 발견되었습니다: ${non_root_list}"
    elif [ "$user_count" -eq 0 ]; then
        status="수동진단"
        diagnosis_result="MANUAL"
        inspection_summary="/etc/passwd에서 UID 0 계정을 확인할 수 없습니다(파일 손상 또는 읽기 실패 가능). 수동 점검이 필요합니다."
    fi

    # 3. command_result에 실제 데이터 기록
    command_result="UID 0 계정 목록: [ ${uid_zero_users} ] (총 ${user_count}개)"

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
