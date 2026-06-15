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
# @Platform    : AIX
# @Severity    : 중
# @Title       : UMASK 설정 관리
# @Description : UMASK 022 이상 설정 확인
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
# UMASK 판정 보조 함수
# ============================================================================

# umask 값이 022 이상(그룹 쓰기/기타 쓰기 차단 비트를 모두 포함)인지 검증
# 반환: 0=양호(022 비트 모두 포함), 1=취약(022 미만), 2=8진수로 해석 불가
check_umask_value() {
    local val="$1"
    case "${val}" in
        ''|*[!0-7]*) return 2 ;;
    esac
    if [ $(( 8#${val} & 8#022 )) -eq $(( 8#022 )) ]; then
        return 0
    fi
    return 1
}

# 발견된 umask 값을 집계 (diagnose의 지역 변수에 동적 스코프로 기록)
record_umask_value() {
    local source_name="$1"
    local value="$2"
    local rc=0
    all_umask_values="${all_umask_values}${source_name}: ${value}, "
    check_umask_value "${value}" || rc=$?
    if [ "${rc}" -eq 0 ]; then
        secure_found=true
    elif [ "${rc}" -eq 1 ]; then
        insecure_found=true
    else
        unparseable_found=true
    fi
    return 0
}

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
    # UMASK 값이 022 이상(8진수 022의 마스크 비트를 모두 포함)인지 비트 연산으로 검증
    # 여러 설정 파일 중 가장 허용적인(취약한) 값이 최종 판정을 결정

    local insecure_found=false
    local secure_found=false
    local unparseable_found=false
    local all_umask_values=""
    local config_files_checked=0

    # 증적용: 설정 파일의 umask 관련 원본 라인 수집
    local umask_grep=$(grep -h 'umask' /etc/profile /etc/bash.bashrc /root/.bashrc /root/.profile 2>/dev/null | grep -v "^[[:space:]]*#" || echo "No umask settings found")
    local secuser_grep=$(grep 'umask' /etc/security/user 2>/dev/null | grep -v "^\*" || echo "No umask attribute in /etc/security/user")
    command_result="[Command: grep -h 'umask' /etc/profile /etc/bash.bashrc /root/.bashrc /root/.profile]${newline}${umask_grep}${newline}[Command: grep 'umask' /etc/security/user]${newline}${secuser_grep}"

    # UMASK 설정 확인 대상 파일 목록 (프로파일 계열)
    local umask_files=(
        "/etc/profile"
        "/etc/bash.bashrc"
        "/etc/profile.d/*.sh"
        "/root/.bashrc"
        "/root/.profile"
    )

    # 각 설정 파일에서 umask 값 추출 (파일 내 모든 설정 중 마지막 값 적용)
    for umask_file in "${umask_files[@]}"; do
        # 와일드카드 처리
        for actual_file in $umask_file; do
            if [ -f "$actual_file" ] && [ -r "$actual_file" ]; then
                ((config_files_checked++)) || true
                local umask_value
                umask_value=$(grep "^[[:space:]]*umask[[:space:]]" "$actual_file" 2>/dev/null | awk '{print $2}' | tail -1) || true

                if [ -n "$umask_value" ]; then
                    record_umask_value "$actual_file" "$umask_value"
                fi
            fi
        done 2>/dev/null || true
    done 2>/dev/null || true

    # AIX 기본 정책: /etc/security/user 의 default 스탠자 umask 속성 확인
    if [ -f /etc/security/user ] && [ -r /etc/security/user ]; then
        ((config_files_checked++)) || true
        local secuser_value
        secuser_value=$(awk '
            /^\*/ { next }
            /^default:/ { in_def=1; next }
            /^[^ \t]/ { in_def=0 }
            in_def && /^[ \t]*umask[ \t]*=/ {
                line=$0
                sub(/^[ \t]*umask[ \t]*=[ \t]*/, "", line)
                sub(/[ \t]*$/, "", line)
                val=line
            }
            END { if (val != "") print val }
        ' /etc/security/user 2>/dev/null) || true
        if [ -n "$secuser_value" ]; then
            record_umask_value "/etc/security/user(default)" "$secuser_value"
        fi
    fi

    # 최종 판정 (가장 허용적인 값 기준)
    command_executed="grep '^umask' /etc/profile /etc/bash.bashrc /root/.bashrc /root/.profile; awk(/etc/security/user default stanza umask)"
    if [ "$insecure_found" = true ]; then
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="UMASK 값이 022 미만으로 설정된 항목 존재: ${all_umask_values%, } (022 이상 필요)"
    elif [ "$unparseable_found" = true ]; then
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="8진수로 해석할 수 없는 UMASK 값이 존재하여 수동 확인 필요: ${all_umask_values%, }"
    elif [ "$secure_found" = true ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="모든 UMASK 설정이 022 이상으로 적절함: ${all_umask_values%, }"
    elif [ "$config_files_checked" -gt 0 ]; then
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="설정 파일에 UMASK 값이 설정되어 있지 않음 (UMASK 022 이상 명시 설정 필요)"
    else
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="UMASK 설정 파일을 읽을 수 없어 수동 확인 필요"
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
