#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-28
# ============================================================================
# [점검 항목 상세]
# @ID          : U-31
# @Category    : UNIX > 2. 파일 및 디렉토리 관리
# @Platform    : RedHat
# @Severity    : 중
# @Title       : 홈 디렉토리 소유자 및 권한 설정
# @Description : 사용자별 홈 디렉터리의 소유자 및 권한 설정의 적절성 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/metadata_parser.sh"

ITEM_ID="U-31"
ITEM_NAME="홈 디렉토리 소유자 및 권한 설정"
SEVERITY="중"

GUIDELINE_PURPOSE="사용자 홈 디렉토리 내 설정 파일이 비인가자에 의한 변조를 방지하기 위함"
GUIDELINE_THREAT="홈 디렉토리 내 설정 파일 변조 시 정상적인 서비스 이용이 제한될 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="홈 디렉토리 소유자가 해당 계정이고, 타 사용자 쓰기 권한이 제거된 경우"
GUIDELINE_CRITERIA_BAD="홈 디렉토리 소유자가 해당 계정이 아니거나, 타 사용자 쓰기 권한이 부여된 경우"
GUIDELINE_REMEDIATION="사용자별 홈 디렉토리 소유주를 해당 계정으로 변경하고, 타 사용자의 쓰기 권한 제거하도록 설정 (/etc/passwd 파일에서 홈 디렉토리 확인, 사용자 홈 디렉토리 외 개별적으로 만들어 사용하는 사용자 디렉토리 존재 여부 확인하여 점검)"

diagnose() {
    # 전역 변수로 설정하여 main에서 참조 가능하게 함
    status="양호"
    diagnosis_result="GOOD"
    inspection_summary="모든 홈 디렉터리의 소유자 및 권한 설정이 적절합니다."
    command_result=""
    command_executed="stat -c '%U %a %n' /home/*"

    local checked_list=""
    local bad_count=0

    # set -e에 의해 중단되지 않도록 루프 보호
    while IFS=: read -r user pass uid gid info home shell; do
        if [ "$uid" -ge 1000 ] && [ -d "$home" ]; then
            local owner perm
            # 에러 발생 시 죽지 않도록 2>/dev/null 처리
            owner=$(stat -c "%U" "$home" 2>/dev/null) || owner="unknown"
            perm=$(stat -c "%a" "$home" 2>/dev/null) || perm="000"

            checked_list+="${user}(Owner:${owner}, Perm:${perm})\n"

            # 판정 로직: 소유자 불일치 OR 그룹 쓰기 권한 OR 타인 쓰기 권한
            local last_digit="${perm: -1}"
            local mid_digit="${perm:1:1}"
            local has_other_write=$(( last_digit & 2 ))
            local has_group_write=$(( mid_digit & 2 ))
            if [ "$owner" != "$user" ] || [ "$has_group_write" -ne 0 ] || [ "$has_other_write" -ne 0 ]; then
                status="취약"
                diagnosis_result="VULNERABLE"
                ((bad_count++))
            fi
        fi
    done < /etc/passwd

    if [ "$bad_count" -gt 0 ]; then
        inspection_summary="${bad_count}개의 홈 디렉터리 설정이 부적절합니다."
        command_result=$(echo -e "점검 결과 상세:\n${checked_list}")
    else
        command_result=$(echo -e "모든 계정 \n${checked_list}")
    fi

    # 이 함수가 반드시 호출되어야 결과 파일이 생성됨
    save_dual_result \
        "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" \
        "${inspection_summary}" "${command_result}" "${command_executed}" \
        "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" \
        "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
    
    return 0
}

main() {
    # root 권한 체크
    if [ "$EUID" -ne 0 ]; then
        echo "Error: root 권한이 필요합니다."
        exit 1
    fi

    show_diagnosis_start "${ITEM_ID}" "${ITEM_NAME}"
    
    # 진단 실행 (에러 발생해도 무시하고 진행하도록 설정 가능)
    diagnose || true 

    # 최종 결과 출력 (JSON 출력 핵심 구간)
    show_diagnosis_complete "${ITEM_ID}" "${diagnosis_result:-VULNERABLE}"
    exit 0
}
main "$@"
