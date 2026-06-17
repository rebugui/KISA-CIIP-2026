#!/bin/bash
# ============================================================================
# @ID          : U-25
# @Title       : world writable 파일 점검
# ============================================================================

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; LIB_DIR="${SCRIPT_DIR}/../../lib"
source "${LIB_DIR}/common.sh"; source "${LIB_DIR}/result_manager.sh"

ITEM_ID="U-25"; ITEM_NAME="world writable 파일 점검"; SEVERITY="(상)"
GUIDELINE_PURPOSE="worldwritable 파일을 이용한 시스템 접근 및 악의적인 코드 실행을 방지하기 위함"
GUIDELINE_THREAT="시스템 파일과 같은 중요 파일에 world writable이 적용될 경우, 일반 사용자 및 비인가자가 해당 파일을 임의로 수정, 제거할 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="worldwritable 파일이 존재하지 않거나, 존재 시 설정 이유를 인지하고 있는 경우"
GUIDELINE_CRITERIA_BAD="worldwritable 파일이 존재하나 설정 이유를 인지하지 못하고 있는 경우"
GUIDELINE_REMEDIATION="worldwritable 파일 존재 여부를 확인하고 불필요한 경우 제거하도록 설정"

diagnose() {
    local status="양호"; diagnosis_result="GOOD"
    local newline=$'\n'
    local inspection_summary="World Writable 파일이 발견되지 않았습니다."
    local command_result=""
    local command_executed="df -lP | awk 'NR>1{print \$6}'; find <마운트포인트> -xdev -type f -perm -2 2>/dev/null"

    # 로컬 마운트포인트 열거 (/만 -xdev 검사 시 /home,/var 등 별도 파티션이 누락되는 문제 보완)
    local mount_points=""
    mount_points=$(df -lP 2>/dev/null | awk 'NR>1{print $6}' | sort -u) || true
    [ -n "$mount_points" ] || mount_points="/"

    # 마운트포인트별 world writable 파일 탐색 (-xdev로 각 파일시스템 내부만 검사)
    local ww_all=""
    local mnt=""
    while IFS= read -r mnt; do
        if [ -n "$mnt" ] && [ -d "$mnt" ]; then
            local found=""
            found=$(find "$mnt" -xdev -type f -perm -2 2>/dev/null | grep -Ev '^(/tmp|/var/tmp|/var/mail|/dev/shm|/mnt|/media)(/|$)' || true)
            if [ -n "$found" ]; then
                ww_all="${ww_all}${found}${newline}"
            fi
        fi
    done <<< "$mount_points"

    # 증거 출력 제한 전에 전체 건수를 먼저 집계
    local ww_count=0
    if [ -n "$ww_all" ]; then
        ww_count=$(printf '%s' "$ww_all" | grep -c '.' || true)
    fi

    if [ "$ww_count" -gt 0 ]; then
        status="취약"; diagnosis_result="VULNERABLE"
        local ww_sample=""
        ww_sample=$(printf '%s' "$ww_all" | head -n 10 | xargs) || true
        inspection_summary="World Writable 파일 ${ww_count}건이 발견되었습니다. 설정 이유 인지 여부 확인이 필요합니다."
        command_result="발견된 World Writable 파일 ${ww_count}건(최대 10건 표시): [ ${ww_sample} ]"
    else
        local mnt_list=""
        mnt_list=$(printf '%s' "$mount_points" | xargs) || true
        command_result="검사한 마운트포인트: [ ${mnt_list} ] - World Writable 파일 없음"
    fi

    save_dual_result "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" "${inspection_summary}" "${command_result}" "${command_executed}" "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
}
main() { diagnose; }; main "$@"
