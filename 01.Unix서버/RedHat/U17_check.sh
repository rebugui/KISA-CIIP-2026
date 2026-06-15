#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-04-20
# ============================================================================
# [점검 항목 상세]
# @ID          : U-17
# @Category    : UNIX > 2. 파일 및 디렉토리 관리
# @Platform    : RedHat
# @Severity    : 상
# @Title       : 시스템 시작 스크립트 권한 설정
# @Description : 시스템 시작 시 실행되는 스크립트 파일의 소유자 및 권한 설정 점검
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

ITEM_ID="U-17"
ITEM_NAME="시스템 시작 스크립트 권한 설정"
SEVERITY="상"

# 가이드라인 정보 (PDF 42페이지 내용 반영)
GUIDELINE_PURPOSE="시스템 시작 스크립트 파일을 관리자만 제어할 수 있게하여 비인가자들의 임의적인 파일 변조를 방지하기 위함"
GUIDELINE_THREAT="시스템 시작 스크립트 파일의 소유권 및 권한 설정이 미흡할 경우, 비인가자가 스크립트의 내용 변경 등을 통해 시스템 침입 등 악용할 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="시스템 시작 스크립트 파일의 소유자가 root이고, 일반 사용자의 쓰기 권한이 제거된 경우"
GUIDELINE_CRITERIA_BAD="시스템 시작 스크립트 파일의 소유자가 root가 아니거나, 일반 사용자의 쓰기 권한이 부여된 경우"
GUIDELINE_REMEDIATION="시스템 시작 스크립트 파일 소유자 및 권한 변경 설정"

diagnose() {
    # [중요] 파싱 에러 방지를 위한 기존 변수 초기값 유지
    local status="양호"
    diagnosis_result="GOOD"
    local inspection_summary="시스템 시작 스크립트의 소유자 및 권한 설정이 적절합니다."
    local command_result=""
    local command_executed="find /etc/rc.d/ /etc/init.d/ /etc/systemd/system/ -type f -perm /022; find /etc/rc.d/ /etc/init.d/ /etc/systemd/system/ -type f ! -user root"

    # 1. 실제 데이터 추출: 일반 사용자(그룹 또는 타인) 쓰기 권한 또는 소유자가 root가 아닌 파일 검색
    # criteria_bad: 일반 사용자(그룹 OR 타인)의 쓰기 권한 부여 → -perm /022 (그룹쓰기 020 또는 타인쓰기 002 중 하나라도)
    # 주요 경로 (가이드 LINUX 절: [init] + [systemd]): /etc/rc.d, /etc/init.d, /etc/systemd/system 등
    local writable_files=$(find /etc/rc.d/ /etc/init.d/ /etc/systemd/system/ -type f -perm /022 2>/dev/null | head -n 5 || true)
    local nonroot_files=$(find /etc/rc.d/ /etc/init.d/ /etc/systemd/system/ -type f ! -user root 2>/dev/null | head -n 5 || true)

    # 2. 판정 로직: 일반 사용자 쓰기 권한 또는 비root 소유 파일이 하나라도 발견되면 취약
    if [ -n "$writable_files" ] || [ -n "$nonroot_files" ]; then
        status="취약"
        diagnosis_result="VULNERABLE"
        local issue_desc=""
        [ -n "$writable_files" ] && issue_desc="일반 사용자(그룹/타인) 쓰기 권한이 허용된 파일"
        [ -n "$nonroot_files" ] && issue_desc="${issue_desc:+${issue_desc} 및 }소유자가 root가 아닌 파일"
        inspection_summary="시스템 시작 스크립트 중 ${issue_desc}이 존재합니다."
        command_result="일반 사용자 쓰기 가능 파일(일부): [ $(echo $writable_files | xargs) ] | 비root 소유 파일(일부): [ $(echo $nonroot_files | xargs) ]"
    else
        command_result="모든 시작 스크립트의 소유자가 root이며 일반 사용자(그룹/타인) 쓰기 권한이 없습니다."
    fi

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
