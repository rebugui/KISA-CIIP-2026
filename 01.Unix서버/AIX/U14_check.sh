#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : U-14
# @Category    : Unix Server
# @Platform    : AIX
# @Severity    : 상
# @Title       : root 홈, 패스 디렉터리 권한 및 패스 설정
# @Description : root PATH 확인 (. 포함 여부)
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


ITEM_ID="U-14"
ITEM_NAME="root 홈, 패스 디렉터리 권한 및 패스 설정"
SEVERITY="상"

# 가이드라인 정보
GUIDELINE_PURPOSE="비인가자가 불법적으로 생성한 디렉터리 및 명령어를 우선으로 실행되지 않도록 설정하기 위함"
GUIDELINE_THREAT="root 계정의 PATH 환경 변수에 정상적인 관리자 명령어(ls, mv, cp 등)의 디렉터리 경로보다 현재 디렉터리를 지칭하는 '.' 표시가 우선하면 현재 디렉터리에 변조된 명령어를 삽입하여 관리자 명령어 입력 시 악의적인 기능이 실행될 수 있는 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="PATH 환경 변수에'.'이 맨 앞이나 중간에 포함되지 않은 경우"
GUIDELINE_CRITERIA_BAD="PATH 환경 변수에'.'이 맨 앞이나 중간에 포함된 경우"
GUIDELINE_REMEDIATION="root 계정의 환경 설정 파일(/.profile, /.bashrc 등)과 시스템 환경 설정 파일(/etc/profile 등)에 설정된 PATH 환경 변수에서 현재 디렉터리를 나타내는'.'을 PATH 환경 변수의 마지막으로 이동하도록 설정 ※ /etc/profile 파일,root 계정, 일반 사용자 계정의 환경 설정 파일을 순차적으로 검색하여 확인"

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
    # root PATH 확인 (. 포함 여부)

    local path_has_dot=false
    local path_issues=""
    local root_home_perms=""
    local path_dirs_issues=""

    # 1) root 계정의 PATH 환경변수 확인
    # /root/.bashrc, /root/.profile, /etc/profile 등에서 PATH 설정 확인
    local root_path=""

    # root로 su하여 PATH 확인 (실제 환경에서만 작동)
    if [ "$EUID" -eq 0 ]; then
        root_path="$PATH"
    else
        # 현재 사용자가 root가 아닌 경우, 설정 파일에서 확인
        if [ -f /root/.bashrc ]; then
            root_path=$(grep "^export PATH=" /root/.bashrc 2>/dev/null | sed 's/export PATH=//')
        fi
        if [ -z "$root_path" ] && [ -f /root/.profile ]; then
            root_path=$(grep "^PATH=" /root/.profile 2>/dev/null | sed 's/PATH=//')
        fi
    fi

    # PATH에 "." 또는 "::" (빈 디렉토리, 현재 디렉토리 의미) 포함 확인
    if [ -n "$root_path" ]; then
        # 콜론으로 구분된 PATH 검사
        local old_ifs="$IFS"
        IFS=':'
        for path_dir in $root_path; do
            if [ "$path_dir" = "." ] || [ -z "$path_dir" ]; then
                path_has_dot=true
                path_issues="${path_issues}PATH에 현재 디렉토리(.) 또는 빈 경로 포함, "
            fi
        done || true
        IFS="$old_ifs"
    fi

    # 2) root 홈 디렉토리 권한 확인
    local root_home="/root"
    if [ -d "$root_home" ]; then
        # AIX stat 명령어는 다른 옵션 사용
        # AIX: ls -l 또는 stat (AIX 6.1+)
        local home_perms=""
        local home_owner=""

        # AIX에서 권한 확인 (perl 사용 또는 ls 파싱)
        if command -v perl >/dev/null 2>&1; then
            home_perms=$(perl -e 'printf "%04o\n", (stat shift)[2] & 07777' "$root_home" 2>/dev/null)
        else
            # ls에서 권한 추출 (AIX)
            local ls_output=$(ls -ld "$root_home" 2>/dev/null)
            home_perms=$(echo "$ls_output" | awk '{print $1}' | cut -c2-10)
        fi

        # 소유자 확인
        home_owner=$(ls -ld "$root_home" 2>/dev/null | awk '{print $3}')

        # root 홈 디렉토리는 root만 접근 가능해야 함 (700, 750 권장)
        if [ "$home_owner" = "root" ]; then
            if [ "$home_perms" = "700" ] || [ "$home_perms" = "750" ] || [ "$home_perms" = "rwx------" ] || [ "$home_perms" = "rwxr-x---" ]; then
                root_home_perms="root 홈 권한: ${home_perms} (${home_owner}) [양호]"
            else
                root_home_perms="root 홈 권한: ${home_perms} (${home_owner}) [권한 700 또는 750 권장]"
            fi
        else
            root_home_perms="root 홈 소유자: ${home_owner} [root가 아님]"
        fi
    else
        root_home_perms="/root 디렉토리 없음"
    fi

    # 3) PATH에 포함된 디렉토리 권한 확인 (쓰기 권한 있는지)
    if [ -n "$root_path" ]; then
        local old_ifs="$IFS"
        IFS=':'
        for path_dir in $root_path; do
            if [ -n "$path_dir" ] && [ "$path_dir" != "." ] && [ -d "$path_dir" ]; then
                # AIX에서 권한 확인
                local dir_perms=""
                if command -v perl >/dev/null 2>&1; then
                    dir_perms=$(perl -e 'printf "%04o\n", (stat shift)[2] & 07777' "$path_dir" 2>/dev/null)
                else
                    local ls_output=$(ls -ld "$path_dir" 2>/dev/null)
                    dir_perms=$(echo "$ls_output" | awk '{print $1}')
                fi

                # others에 쓰기 권한이 있는지 확인
                if [ -n "$dir_perms" ]; then
                    # 숫자 형식인 경우 (perl 사용)
                    if echo "$dir_perms" | grep -qE '^[0-9]+$'; then
                        local others_write=$((dir_perms % 10))
                        if [ "$others_write" -ge 6 ] 2>/dev/null; then
                            path_dirs_issues="${path_dirs_issues}${path_dir} 권한 ${dir_perms} (others 쓰기 가능), "
                        fi
                    else
                        # 문자열 형식인 경우 (ls 출력)
                        # 마지막 3字符检查 others 권한
                        local last_char=$(echo "$dir_perms" | tail -c 2)
                        if [ "$last_char" = "w" ]; then
                            path_dirs_issues="${path_dirs_issues}${path_dir} 권한 ${dir_perms} (others 쓰기 가능), "
                        fi
                    fi
                fi
            fi
        done || true
        IFS="$old_ifs"
    fi

    # 최종 판정
    local all_issues="${path_issues}${root_home_perms}${path_dirs_issues}"

    if [ "$path_has_dot" = true ]; then
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="root PATH에 현재 디렉토리(.) 포함: ${path_issues%, }"
        command_result="${path_issues%, } | ${root_home_perms}"
        command_executed="echo \$PATH | grep ':' | tr ':' '\\n' | grep '^.$'"
    elif [ -n "$path_dirs_issues" ]; then
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="PATH 디렉토리 권한 문제: ${path_dirs_issues%, }"
        command_result="${root_home_perms} | ${path_dirs_issues%, }"
        command_executed="ls -ld \$(echo \$PATH | tr ':' ' ')"
    else
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="root PATH 및 홈 디렉토리 보안 설정 적절 (${root_home_perms})"
        command_result="${root_home_perms}"
        command_executed="echo \$PATH && ls -ld /root"
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
