#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : U-33
# @Category    : Unix Server
# @Platform    : Solaris
# @Severity    : 하
# @Title       : 숨겨진 파일 및 디렉토리 검색 및 제거
# @Description : 숨겨진 파일(.) 및 의심스러운 파일 탐지
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


ITEM_ID="U-33"
ITEM_NAME="숨겨진 파일 및 디렉토리 검색 및 제거"
SEVERITY="하"

# 가이드라인 정보
GUIDELINE_PURPOSE="숨겨진 파일 및 디렉토리 중 의심스러운 내용은 정상 사용자가 아닌 공격자에 의해 생성되었을 가능성이 높으므로 이를 제거하여 보안 위협을 방지하기 위함"
GUIDELINE_THREAT="숨겨진 파일 및 디렉토리를 방치할 경우, 비인가자가 생성한 악성 파일 또는 백 도어 등을 탐지하지 못할 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="불필요하거나 의심스러운 숨겨진 파일 및 디렉토리를 제거한 경우"
GUIDELINE_CRITERIA_BAD="불필요하거나 의심스러운 숨겨진 파일 및 디렉토리를 제거하지 않은 경우"
GUIDELINE_REMEDIATION="ls-al 명령어로 숨겨진 파일 존재 파악 후 불법적이거나 의심스러운 파일을 제거하도록 설정".*\^" -ls로 확인 후 rm -rf로 제거"

# ============================================================================
# 진단 함수
# ============================================================================

# 홈 디렉토리 1단계 숨김 항목 열거 (find -maxdepth 미지원 환경 대응: 쉘 글롭 사용)
list_hidden_entries() {
    local dir="$1"
    local entry
    for entry in "$dir"/.[!.]* "$dir"/..?*; do
        if [ -e "$entry" ] || [ -L "$entry" ]; then
            printf '%s\n' "$entry"
        fi
    done
    return 0
}

# 진단 수행
diagnose() {


    diagnosis_result="unknown"
    local status="미진단"
    local inspection_summary=""
    local command_result=""
    local command_executed=""
    local newline=$'\n'

    # 진단 로직 구현
    # 사용자 홈 디렉토리 내 숨겨진 파일(.) 및 디렉토리 검색
    # 의심스러운 파일 패턴 확인 (.ssh, .bashrc 등 제외한 숨김파일)

    local suspicious_files=""
    local review_files=""
    local total_hidden=0
    local suspicious_count=0
    local review_count=0
    local checked_homedirs=0
    local unreadable_homedirs=0
    local system_uid_threshold=100
    local raw_find_output=""  # 원본 find 명령어 결과 누적

    # 정상적인 숨겨진 파일 목록 (백도어 후보에서 제외)
    local normal_hidden_patterns=(
        "\.bashrc"
        "\.bash_profile"
        "\.bash_logout"
        "\.bash_history"
        "\.sh_history"
        "\.profile"
        "\.cshrc"
        "\.kshrc"
        "\.login"
        "\.logout"
        "\.ssh"
        "\.gitconfig"
        "\.gitignore"
        "\.vimrc"
        "\.viminfo"
        "\.lesshst"
        "\.Xauthority"
        "\.ICEauthority"
        "\.cache"
        "\.config"
        "\.local"
        "\.mozilla"
        "\.gnupg"
    )

    # 사용자 홈 디렉토리 확인
    while IFS=: read -r username password uid gid gecos home shell; do
        # 시스템 계정 제외 (root(UID 0) 및 UID >= 100인 일반 사용자 확인, Solaris)
        # root 홈(/root)의 숨김 백도어 미탐(false-good) 방지를 위해 root 포함
        if [ "$uid" -ne 0 ] && [ "$uid" -lt "$system_uid_threshold" ]; then
            continue
        fi

        # 로그인 쉘이 없는 계정 제외
        if [ "$shell" = "/bin/false" ] || [ "$shell" = "/sbin/nologin" ]; then
            continue
        fi

        # 홈 디렉토리 존재 확인
        if [ ! -d "$home" ]; then
            continue
        fi

        ((checked_homedirs++)) || true

        # 읽을 수 없는 홈 디렉토리는 점검 불가로 건너뜀
        if [ ! -r "$home" ] || [ ! -x "$home" ]; then
            ((unreadable_homedirs++)) || true
            continue
        fi

        # 숨겨진 파일 및 디렉토리 검색 (.)
        # 쉘 글롭 기반 1단계 열거 실행 및 결과 저장
        local find_result=$(list_hidden_entries "$home" 2>/dev/null)

        if [ -n "$find_result" ]; then
            raw_find_output="${raw_find_output}[Directory: $home]${newline}${find_result}${newline}${newline}"
        fi

        while IFS= read -r hidden_file; do
            if [ -z "$hidden_file" ]; then
                continue
            fi

            ((total_hidden++)) || true

            # 파일명만 추출
            local filename=$(basename "$hidden_file")

            # 정상적인 숨겨진 파일인지 확인
            local is_normal=false
            for pattern in "${normal_hidden_patterns[@]}"; do
                if [[ "$filename" =~ ^${pattern}$ ]]; then
                    is_normal=true
                    break
                fi
            done || true

            # 의심스러운 숨겨진 파일
            if [ "$is_normal" = false ]; then
                # 파일 타입 확인
                local filetype=""
                if [ -f "$hidden_file" ]; then
                    filetype="file"
                elif [ -d "$hidden_file" ]; then
                    filetype="dir"
                elif [ -L "$hidden_file" ]; then
                    filetype="symlink"
                fi

                # 미인식 숨김 항목은 악성 여부를 정적으로 판정할 수 없으므로
                # (실행 권한 유무와 무관하게) 모두 '수동진단'(MANUAL) 대상으로 분류한다.
                # 실행 권한이 있는 정상 부산물(.xinitrc/.xprofile 0755, 관리자 헬퍼 0700/0750 등)을
                # 자동 '취약'으로 오판(false-positive)하지 않도록 가이드라인(ls -al 수동 확인) 및
                # 동일 항목 AIX U-33과 동일하게 수동 검토로 라우팅한다.
                local perms=""
                if [ -f "$hidden_file" ]; then
                    perms=$(perl -e 'if (-f $ARGV[0]) { printf "%04o\n", (stat($ARGV[0]))[2] & 07777; }' "$hidden_file" 2>/dev/null || echo "000")
                    if [[ "$perms" =~ ^[0-9]*[1357][0-9]*$ ]]; then
                        # 실행 권한이 있는 미인식 파일 → 정적 판정 불가, 수동 검토
                        review_files="${review_files}${home}/${filename}(${filetype}, perms: ${perms}), "
                        ((review_count++)) || true
                    else
                        # 비실행 미인식 파일 → 수동 검토
                        review_files="${review_files}${home}/${filename}(${filetype}), "
                        ((review_count++)) || true
                    fi
                else
                    # 미인식 디렉터리/심볼릭 링크 → 수동 검토
                    review_files="${review_files}${home}/${filename}(${filetype}), "
                    ((review_count++)) || true
                fi
            fi
        done < <(list_hidden_entries "$home" 2>/dev/null | head -50) || true
    done < /etc/passwd || true

    command_executed="while IFS=: read -r user pw uid gid gecos home shell; do for f in \"\$home\"/.[!.]* \"\$home\"/..?*; do [ -e \"\$f\" ] || [ -L \"\$f\" ] || continue; echo \"\$f\"; done; done < /etc/passwd | grep -v -E '\.(bashrc|bash_profile|profile|ssh|gitconfig|gitignore|vimrc|viminfo)$'" || true

    # 최종 판정
    if [ "$checked_homedirs" -gt 0 ] && [ "$unreadable_homedirs" -eq "$checked_homedirs" ]; then
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="점검 대상 홈 디렉토리 ${checked_homedirs}개를 모두 읽을 수 없어 숨겨진 파일 점검을 수행하지 못했습니다. ls -al 명령어로 각 홈 디렉토리의 숨겨진 파일을 수동으로 확인하세요."
        command_result="[Hidden files search results]${newline}[All ${checked_homedirs} home directories were unreadable; hidden file scan could not be performed]"
    elif [ "$suspicious_count" -gt 0 ]; then
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="실행 권한이 있는 의심스러운 숨겨진 파일 ${suspicious_count}개가 발견되었습니다: ${suspicious_files%, }. 해당 파일들을 검토한 후 불필요하거나 악성적인 경우 제거하세요: rm -rf <file>"
        command_result="[Hidden files search results]${newline}${raw_find_output}${newline}[Suspicious files found]${newline}${suspicious_files%, }"
    elif [ "$review_count" -gt 0 ]; then
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="통상적이지 않은 숨겨진 파일/디렉터리 ${review_count}개가 발견되었습니다: ${review_files%, }. 불필요하거나 의심스러운 항목인지 ls -al 명령어로 수동 확인 후 제거하세요."
        command_result="[Hidden files search results]${newline}${raw_find_output}${newline}[Manual review required]${newline}${review_files%, }"
    else
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="의심스러운 숨겨진 파일이 발견되지 않았습니다. (확인된 홈 디렉토리: ${checked_homedirs}개, 전체 숨겨진 파일: ${total_hidden}개)"
        command_result="[Hidden files search results]${newline}${raw_find_output}${newline}[No suspicious files found (checked ${checked_homedirs} home directories, ${total_hidden} total hidden files)]"
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
