#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : U-15
# @Category    : Unix Server
# @Platform    : Debian
# @Severity    : 상
# @Title       : 파일 및 디렉터리 소유자 설정
# @Description : 소유자가 없는 파일 및 디렉터리 확인 (find -nouser -o -nogroup)
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


ITEM_ID="U-15"
ITEM_NAME="파일 및 디렉터리 소유자 설정"
SEVERITY="상"

# 가이드라인 정보
GUIDELINE_PURPOSE="소유자가 존재하지 않는 파일 및 디렉터리를 제거 또는 관리하여 임의의 사용자가 해당 파일을 열람, 수정하는 행위를 사전에 차단하기 위함"
GUIDELINE_THREAT="소유자가 존재하지 않는 파일의 UID와 동일한 값으로 특정 계정의 UID를 변경하면 해당 파일의 소유자가 되어 모든 작업이 가능한 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="소유자가 존재하지 않는 파일 및 디렉터리가 존재하지 않는 경우"
GUIDELINE_CRITERIA_BAD="소유자가 존재하지 않는 파일 및 디렉터리가 존재하는 경우"
GUIDELINE_REMEDIATION="소유자가 존재하지 않는 파일 및 디렉터리 제거 또는 소유자 변경 설정"

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
    # 가이드 Step 1) 소유자와 그룹이 존재하지 않는 파일 및 디렉터리 확인
    # 루트(/) 전체를 -xdev로 스캔하여 가이드 명령과 동일한 범위를 점검
    command_executed="find / -xdev \\( -nouser -o -nogroup \\) -ls 2>/dev/null"

    local find_output=""
    local find_status=0
    find_output=$(find / -xdev \( -nouser -o -nogroup \) -ls 2>/dev/null) || find_status=$?

    # 증거 출력 제한(최대 50건) 전에 전체 건수를 먼저 집계
    local orphan_count=0
    if [ -n "$find_output" ]; then
        orphan_count=$(printf '%s\n' "$find_output" | grep -c '.' || true)
    fi

    # 최종 판정
    if [ -n "$find_output" ] && [ "$orphan_count" -gt 0 ]; then
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="소유자 또는 그룹이 존재하지 않는 파일 및 디렉터리 ${orphan_count}건이 발견되었습니다."
        local capped_list=""
        capped_list=$(printf '%s\n' "$find_output" | head -50) || true
        command_result="[Command: ${command_executed}]${newline}발견 건수: ${orphan_count}건 (최대 50건 표시)${newline}${capped_list}"
    elif [ "$find_status" -ne 0 ]; then
        # find 명령 자체가 실패한 경우(권한 부족, 시간 초과 등) → 수동 진단
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="find 명령 수행이 실패하여(종료코드: ${find_status}) 소유자 없는 파일 및 디렉터리 존재 여부를 자동 판정할 수 없습니다. root 권한으로 수동 확인이 필요합니다."
        command_result="[Command: ${command_executed}]${newline}find 종료코드: ${find_status}, 출력 없음 (권한 부족 또는 시간 초과 가능성)"
    else
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="소유자 또는 그룹이 존재하지 않는 파일 및 디렉터리가 발견되지 않았습니다."
        command_result="[Command: ${command_executed}]${newline}발견된 파일/디렉터리 없음"
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
