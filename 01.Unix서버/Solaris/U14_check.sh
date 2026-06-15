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
# @Platform    : Solaris
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
# PATH 점검 헬퍼 함수
# ============================================================================

# 환경 설정 파일에서 마지막 PATH 정의 값을 추출 (export/따옴표/주석 제거)
extract_path_from_file() {
    local config_file="$1"
    local path_line=""

    [ -f "$config_file" ] && [ -r "$config_file" ] || return 0
    path_line=$(grep -E '^[[:space:]]*(export[[:space:]]+)?PATH=' "$config_file" 2>/dev/null | tail -n 1 \
        | sed -e 's/^[[:space:]]*//' -e 's/^export[[:space:]]*//' -e 's/^PATH=//' \
              -e 's/[[:space:]][[:space:]]*#.*$//' -e 's/[[:space:]]*$//' || true)
    case "$path_line" in
        \"*\") path_line="${path_line#\"}"; path_line="${path_line%\"}" ;;
        \'*\') path_line="${path_line#\'}"; path_line="${path_line%\'}" ;;
    esac
    printf '%s' "$path_line"
    return 0
}

# PATH 요소별 점검: 맨 앞/중간 위치의 '.' 또는 빈 요소만 취약으로 판정
# - 가이드 조치 방법대로 '.'(또는 빈 요소)을 맨 마지막에 둔 경우는 양호
# - PATH가 '.' 또는 빈 값 단독인 경우는 취약
# 호출 측의 path_has_dot / path_issues 변수를 갱신함
check_path_order() {
    local path_value="$1"
    local source_label="$2"
    local -a path_elems=()
    local elem_idx=0
    local elem_count=0
    local last_idx=0

    # 뒤쪽 빈 요소 보존을 위해 sentinel을 붙여 분리
    IFS=':' read -r -a path_elems <<< "${path_value}:__PATH_END__"
    elem_count=$(( ${#path_elems[@]} - 1 ))
    [ "$elem_count" -ge 1 ] || return 0
    last_idx=$(( elem_count - 1 ))

    if [ "$elem_count" -eq 1 ]; then
        if [ "${path_elems[0]}" = "." ] || [ -z "${path_elems[0]}" ]; then
            path_has_dot=true
            path_issues="${path_issues}${source_label}: PATH가 '.'(현재 디렉터리) 단독으로 설정됨, "
        fi
        return 0
    fi

    for (( elem_idx = 0; elem_idx < last_idx; elem_idx++ )); do
        if [ "${path_elems[$elem_idx]}" = "." ]; then
            path_has_dot=true
            path_issues="${path_issues}${source_label}: PATH $((elem_idx + 1))번째(맨 앞/중간) 위치에 '.' 포함, "
        elif [ -z "${path_elems[$elem_idx]}" ]; then
            path_has_dot=true
            path_issues="${path_issues}${source_label}: PATH $((elem_idx + 1))번째(맨 앞/중간) 위치에 빈 경로(현재 디렉터리 의미) 포함, "
        fi
    done
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
    # root PATH 확인 (. 포함 여부)

    local path_has_dot=false
    local path_issues=""
    local root_home_perms=""
    local path_dirs_issues=""

    # 1) root 계정의 PATH 환경변수 확인
    # root로 실행 시 런타임 PATH를 점검하고, root 환경 설정 파일의 PATH 정의도 함께 점검
    local root_path=""
    local path_evidence=""
    local checked_files=""
    local config_file=""
    local extracted=""

    if [ "$EUID" -eq 0 ]; then
        root_path="$PATH"
        path_evidence="런타임 PATH=${root_path}; "
        check_path_order "$root_path" "런타임 PATH"
    fi

    for config_file in /.profile /root/.bash_profile /root/.bashrc /root/.profile /etc/profile; do
        [ -f "$config_file" ] && [ -r "$config_file" ] || continue
        checked_files="${checked_files}${config_file} "
        extracted=$(extract_path_from_file "$config_file")
        if [ -n "$extracted" ]; then
            check_path_order "$extracted" "$config_file"
            path_evidence="${path_evidence}${config_file}: PATH=${extracted}; "
            [ -n "$root_path" ] || root_path="$extracted"
        fi
    done

    # 2) root 홈 디렉토리 권한 확인
    local root_home="/root"
    if [ -d "$root_home" ]; then
        local home_perms=$(stat -c "%a" "$root_home" 2>/dev/null)
        local home_owner=$(stat -c "%U:%G" "$root_home" 2>/dev/null)

        # root 홈 디렉토리는 root만 접근 가능해야 함 (700, 750 권장)
        if [ "$home_owner" = "root:root" ]; then
            if [ "$home_perms" = "700" ] || [ "$home_perms" = "750" ]; then
                root_home_perms="root 홈 권한: ${home_perms} (${home_owner}) [양호]"
            else
                root_home_perms="root 홈 권한: ${home_perms} (${home_owner}) [권한 700 또는 750 권장]"
            fi
        else
            root_home_perms="root 홈 소유자: ${home_owner} [root:root 아님]"
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
                local dir_perms=$(stat -c "%a" "$path_dir" 2>/dev/null)
                # others에 쓰기 권한이 있는지 확인 (777, 775 등)
                if [ -n "$dir_perms" ]; then
                    local others_write=${dir_perms: -1}
                    if [ "$others_write" -ge 6 ] 2>/dev/null; then
                        path_dirs_issues="${path_dirs_issues}${path_dir} 권한 ${dir_perms} (others 쓰기 가능), "
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
        inspection_summary="root PATH 맨 앞 또는 중간에 '.'(현재 디렉터리) 또는 빈 경로 포함: ${path_issues%, }"
        command_result="${path_issues%, } | ${path_evidence}${root_home_perms}"
        command_executed="echo \$PATH; grep -E '^(export )?PATH=' /.profile /root/.profile /etc/profile"
    elif [ -z "$root_path" ]; then
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="root 권한이 아니고 root 환경 설정 파일에서 PATH를 확인할 수 없어 root PATH 수동 점검 필요"
        command_result="확인 시도 파일: ${checked_files:-접근 가능한 파일 없음} | ${root_home_perms}"
        command_executed="grep -E '^(export )?PATH=' /.profile /root/.profile /root/.bashrc /etc/profile"
    elif [ -n "$path_dirs_issues" ]; then
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="PATH 디렉토리 권한 문제: ${path_dirs_issues%, }"
        command_result="${root_home_perms} | ${path_dirs_issues%, }"
        command_executed="stat -c '%a:%n' \$(echo \$PATH | tr ':' ' ')"
    else
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="root PATH 맨 앞/중간에 '.' 또는 빈 경로 없음 (${root_home_perms})"
        command_result="${path_evidence}${root_home_perms}"
        command_executed="echo \$PATH && stat -c '%a:%U:%G' /root"
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
