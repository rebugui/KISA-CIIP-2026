#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : U-31
# @Category    : Unix Server
# @Platform    : HP-UX
# @Severity    : 중
# @Title       : 홈 디렉토리 소유자 및 권한 설정
# @Description : 홈 디렉터리 소유자가 해당 계정이고 타사용자 쓰기 권한이 없는지 확인
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


ITEM_ID="U-31"
ITEM_NAME="홈 디렉토리 소유자 및 권한 설정"
SEVERITY="중"

# 가이드라인 정보
GUIDELINE_PURPOSE="사용자 홈 디렉토리 내 설정 파일이 비인가자에 의한 변조를 방지하기 위함"
GUIDELINE_THREAT="홈 디렉토리 내 설정 파일 변조 시 정상적인 서비스 이용이 제한될 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="홈 디렉토리 소유자가 해당 계정이고, 타 사용자 쓰기 권한이 제거된 경우"
GUIDELINE_CRITERIA_BAD="홈 디렉토리 소유자가 해당 계정이 아니거나, 타 사용자 쓰기 권한이 부여된 경우"
GUIDELINE_REMEDIATION="사용자별 홈 디렉토리 소유주를 해당 계정으로 변경하고, 타 사용자의 쓰기 권한 제거하도록 설정 (/etc/passwd 파일에서 홈 디렉토리 확인, 사용자 홈 디렉토리 외 개별적으로 만들어 사용하는 사용자 디렉토리 존재 여부 확인하여 점검)"

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
    # /etc/passwd에서 사용자 홈 디렉토리 확인 후 소유자 및 권한 점검

    local insecure_homedirs=""
    local total_users=0
    local checked_users=0
    local system_gid_threshold=1000
    local raw_stat_output=""

    # /etc/passwd 파일 파싱
    while IFS=: read -r username password uid gid gecos home shell; do
        ((total_users++)) || true

        # 시스템 계정 제외 (UID >= 100인 일반 사용자만 확인, HP-UX: 시스템 UID < 100)
        if [ "$uid" -lt 100 ]; then
            continue
        fi

        # 로그인 쉘이 없는 계정 제외 (/bin/false, /sbin/nologin)
        if [ "$shell" = "/bin/false" ] || [ "$shell" = "/sbin/nologin" ]; then
            continue
        fi

        ((checked_users++)) || true

        # 홈 디렉토리 존재 확인
        if [ ! -d "$home" ]; then
            continue
        fi

        # 홈 디렉토리 소유자 확인 (HP-UX: stat -c 대신 perl 사용)
        local owner=$(perl -e '@stat=lstat("'$home'"); $uid=$stat[4]; $user=getpwuid($uid); print "$user"' 2>/dev/null || echo "unknown")
        local perms=$(perl -e '@stat=stat("'$home'"); printf "%04o\n", $stat[2] & 07777' 2>/dev/null || echo "0000")

        # stat 결과 누적
        raw_stat_output="${raw_stat_output}${home}: owner=${owner}, perms=${perms}"$'\n'

        # 타사용자 쓰기 권한 확인 (others의 write 권한)
        local has_others_write=false
        if [[ "$perms" =~ [0-9][0-9][1357]$ ]]; then
            has_others_write=true
        fi

        # 보안 판정: 소유자가 해당 사용자가 아니거나, 타사용자 쓰기 권한이 있는 경우
        if [ "$owner" != "$username" ] || [ "$has_others_write" = true ]; then
            local reason=""
            if [ "$owner" != "$username" ]; then
                reason="소유자: ${owner}"
            fi
            if [ "$has_others_write" = true ]; then
                if [ -n "$reason" ]; then
                    reason="${reason}, "
                fi
                reason="${reason}타사용자쓰기권한있음"
            fi
            insecure_homedirs="${insecure_homedirs}${username}(${home}: ${reason}), "
        fi
    done < /etc/passwd || true

    command_executed="while IFS=: read -r user pw uid gid gecos home shell; do stat -c '%U %a' \"\$home\" 2>/dev/null; done < /etc/passwd" || true

    # 최종 판정
    if [ -z "$insecure_homedirs" ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="모든 사용자의 홈 디렉토리가 적절하게 설정되어 있습니다. (확인된 사용자: ${checked_users}명, 시스템 계정 제외)"
        command_result="[stat outputs for UID>=100 users]"$'\n'"${raw_stat_output}"
    else
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="일부 사용자의 홈 디렉토리 권한 또는 소유자가 부적절합니다: ${insecure_homedirs%, }. 홈 디렉토리 소유자를 해당 계정으로 변경하고 타사용자 쓰기 권한을 제거하세요: chown <user> <home> && chmod o-w <home>"
        command_result="[stat outputs for UID>=100 users]"$'\n'"${raw_stat_output}"
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

    # 진단 완료 표시
    show_diagnosis_complete "${ITEM_ID}" "${diagnosis_result:-UNKNOWN}"

    return 0
}

# 스크립트 직접 실행 시에만 진단 수행
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi
