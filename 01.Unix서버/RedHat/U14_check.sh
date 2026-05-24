#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-04-20
# ============================================================================
# [점검 항목 상세]
# @ID          : U-14
# @Category    : UNIX > 2. 파일 및 디렉토리 관리
# @Platform    : RedHat
# @Severity    : 상
# @Title       : root 홈, 패스 디렉터리 권한 및 패스 설정
# @Description : root 계정의 PATH 환경변수에 “.”(마침표)이 포함 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/metadata_parser.sh"

ITEM_ID="U-14"
ITEM_NAME="root 홈, 패스 디렉터리 권한 및 패스 설정"
SEVERITY="상"

# 가이드라인 정보
GUIDELINE_PURPOSE="비인가자가 불법적으로 생성한 디렉터리 및 명령어를 우선으로 실행되지 않도록 설정하기 위함"
GUIDELINE_THREAT="root 계정의 PATH 환경 변수에 정상적인 관리자 명령어(ls, mv, cp 등)의 디렉터리 경로보다 현재 디렉터리를 지칭하는 '.' 표시가 우선하면 현재 디렉터리에 변조된 명령어를 삽입하여 관리자 명령어 입력 시 악의적인 기능이 실행될 수 있는 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="PATH 환경 변수에'.'이 맨 앞이나 중간에 포함되지 않은 경우"
GUIDELINE_CRITERIA_BAD="PATH 환경 변수에'.'이 맨 앞이나 중간에 포함된 경우"
GUIDELINE_REMEDIATION="root 계정의 환경 설정 파일(/.profile, /.bashrc 등)과 시스템 환경 설정 파일(/etc/profile 등)에 설정된 PATH 환경 변수에서 현재 디렉터리를 나타내는'.'을 PATH 환경 변수의 마지막으로 이동하도록 설정 ※ /etc/profile 파일,root 계정, 일반 사용자 계정의 환경 설정 파일을 순차적으로 검색하여 확인"

diagnose() {
    local status="양호"
    diagnosis_result="GOOD"
    local inspection_summary="PATH 설정이 적절합니다."
    local command_result=""
    local command_executed="echo \$PATH"

    # 1. 실제 데이터 추출
    local current_path=$PATH

    # 2. 판정 로직: 맨 앞(.) 또는 중간(:.:) 확인
    if [[ "$current_path" =~ ^\.: ]] || [[ "$current_path" =~ :\.: ]] || [[ "$current_path" =~ :: ]]; then
        status="취약"
        diagnosis_result="VULNERABLE"
        inspection_summary="PATH 환경변수에 '.' 이 맨 앞이나 중간에 포함되어 있습니다."
    fi

    # 3. command_result에 실제 PATH 전체 기록
    command_result="현재 PATH: [ ${current_path} ]"

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
