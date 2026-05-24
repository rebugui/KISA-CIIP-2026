#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : U-30
# @Category    : Unix Server
# @Platform    : Solaris
# @Severity    : 중
# @Title       : UMASK 설정 관리
# @Description : UMASK 022 또는 027 확인
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


ITEM_ID="U-30"
ITEM_NAME="UMASK 설정 관리"
SEVERITY="중"

# 가이드라인 정보
GUIDELINE_PURPOSE="잘못 설정된 UMASK 값으로 인해 신규 파일에 대한 권한이 과도하게 부여되는 것을 방지하기 위함"
GUIDELINE_THREAT="잘못 설정된 UMASK로 인해 파일 및 디렉터리 생성 시 과도한 권한이 부여되어 무단 액세스 및 데이터 유출의 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="UMASK 값이 022 이상으로 설정된 경우"
GUIDELINE_CRITERIA_BAD="UMASK 값이 022 미만으로 설정된 경우"
GUIDELINE_REMEDIATION="설정 파일에 UMASK 값을 022로 설정"

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
    # UMASK 022 또는 027 확인

    local is_secure=false
    local umask_details=""
    local config_files_checked=0

    # Capture raw grep output for all umask settings
    local umask_grep=$(grep -h 'umask' /etc/profile /etc/.login /etc/default/login /root/.bashrc 2>/dev/null | grep -v "^[[:space:]]*#" || echo "No umask settings found")
    command_result="[Command: grep -h 'umask' /etc/profile /etc/.login /etc/default/login /root/.bashrc]${newline}${umask_grep}"

    # UMASK 설정 확인 대상 파일 목록 (Solaris: /etc/default/login 추가됨)
    local umask_files=(
        "/etc/profile"
        "/etc/.login"
        "/etc/default/login"
        "/root/.bashrc"
        "/root/.profile"
    )

    # 각 설정 파일에서 UMASK 값 추출
    declare -A found_umasks

    for umask_file in "${umask_files[@]}"; do
        # 와일드카드 처리
        for actual_file in $umask_file; do
            if [ -f "$actual_file" ]; then
                ((config_files_checked++)) || true
                # umask 또는 UMASK 키워드로 검색 (주석 제외)
                local umask_value=$(grep "^[[:space:]]*umask" "$actual_file" 2>/dev/null | grep -v "^[[:space:]]*#" | awk '{print $2}' | head -1)

                if [ -n "$umask_value" ]; then
                    found_umasks["$actual_file"]="$umask_value"
                fi
            fi
        done 2>/dev/null || true
    done 2>/dev/null || true

    # 발견된 UMASK 값 검증
    local insecure_found=false
    local secure_found=false
    local all_umask_values=""

    for file in "${!found_umasks[@]}"; do
        local value="${found_umasks[$file]}"
        all_umask_values="${all_umask_values}${file}: ${value}, "

        # UMASk 값 검증 (022, 027 권장)
        if [ "$value" = "022" ] || [ "$value" = "027" ]; then
            secure_found=true
        else
            insecure_found=true
        fi
    done || true

    # 최종 판정
    if [ $config_files_checked -eq 0 ]; then
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="UMASK 설정 파일을 찾을 수 없음 (시스템 기본값 확인 필요)"
        command_executed="grep -h 'umask' /etc/profile /etc/.login /etc/default/login /root/.bashrc 2>/dev/null"
    elif [ "$insecure_found" = true ]; then
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="부적절한 UMASK 설정 존재: ${all_umask_values%, } (022 또는 027 권장)"
        command_result="${all_umask_values%, }"
        command_executed="grep -h '^umask' /etc/profile /etc/.login /etc/default/login /root/.bashrc 2>/dev/null"
    elif [ "$secure_found" = true ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="적절한 UMASK 설정됨: ${all_umask_values%, } (022 또는 027)"
        command_result="${all_umask_values%, }"
        command_executed="grep -h '^umask' /etc/profile /etc/.login /etc/default/login /root/.bashrc 2>/dev/null"
    else
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="UMASK 설정 없음 (기본값 확인 필요: 보통 022)"
        command_result="UMASK setting not found"
        command_executed="grep -h 'umask' /etc/profile /etc/.login /etc/default/login /root/.bashrc 2>/dev/null"
    fi

    # echo ""
    # echo "진단 결과: ${status}"
    # echo "판정: ${diagnosis_result}"
    # echo "설명: ${inspection_summary}"
    # echo ""

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

    return 0
}

# 스크립트 직접 실행 시에만 진단 수행
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi
