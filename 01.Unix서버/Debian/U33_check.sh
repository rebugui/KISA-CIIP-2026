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
# @Platform    : Debian
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
    local total_hidden=0
    local suspicious_count=0
    local home_unrecognized=""   # 홈 디렉터리 내 미인식 dot 항목(→ 수동진단)
    local home_unrecognized_count=0
    local checked_homedirs=0
    local system_uid_threshold=1000
    local raw_find_output=""  # 원본 find 명령어 결과 누적
    local unreadable_areas=""  # 읽기 불가로 점검하지 못한 영역(→ 수동진단)

    # 정상적인 숨겨진 파일 목록 (백도어 후보에서 제외)
    # RedHat U33 제외 집합과 정렬: 통상적인 환경설정/대화형 셸 산출물(.bash_history,
    # .lesshst, .Xauthority 등)을 포함하여 정상 시스템 오탐(false-positive) 방지
    local normal_hidden_patterns=(
        "\.bashrc"
        "\.bash_profile"
        "\.bash_logout"
        "\.bash_history"
        "\.profile"
        "\.cshrc"
        "\.tcshrc"
        "\.kshrc"
        "\.login"
        "\.logout"
        "\.ssh"
        "\.gitconfig"
        "\.gitignore"
        "\.vimrc"
        "\.viminfo"
        "\.emacs"
        "\.emacs\.d"
        "\.lesshst"
        "\.cache"
        "\.config"
        "\.local"
        "\.mozilla"
        "\.gnupg"
        "\.gnupg2"
        "\.pki"
        "\.java"
        "\.ansible"
        "\.kube"
        "\.docker"
        "\.m2"
        "\.npm"
        "\.wget-hsts"
        "\.Xauthority"
        "\.ICEauthority"
        "\.selected_editor"
        "\.sudo_as_admin_successful"
        "\.history"
        "\.sh_history"
        "\.mysql_history"
        "\.psql_history"
        "\.python_history"
        "\.rnd"
    )

    # 사용자 홈 디렉토리 확인
    while IFS=: read -r username password uid gid gecos home shell; do
        # 시스템 계정 제외 (root(UID 0) 및 UID >= 1000인 일반 사용자 확인)
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

        # 숨겨진 파일 및 디렉토리 검색 (.)
        # 홈 디렉터리 1단계(-maxdepth 1)만 스캔하여 ls -al 의미와 일치시키고,
        # 하위 트리의 정상 dot 항목(.cache/.git 등) 재귀 오탐을 방지.
        # 단, 출력은 head -50으로 제한하여 타임아웃 방지(whole-/ 스캔은 하지 않음).
        # 홈 디렉터리가 읽기 불가일 경우 수동 점검 대상으로 표시.
        if [ ! -r "$home" ]; then
            unreadable_areas="${unreadable_areas}${home} "
            continue
        fi
        local find_result=$(find "$home" -maxdepth 1 -name ".*" 2>/dev/null | head -50)

        if [ -n "$find_result" ]; then
            raw_find_output="${raw_find_output}[Directory: $home]\\n${find_result}\\n\\n"
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

            # 통상적이지 않은 홈 dot 항목: 정상/악성 판정은 정적으로 단정할 수 없으므로
            # 취약(VULNERABLE)이 아닌 수동진단(MANUAL) 대상으로 분류(오라클·RedHat U33과 정렬).
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

                # 실행 가능 여부는 수동 판정 보조 정보로만 기록
                local perms=""
                if [ -f "$hidden_file" ]; then
                    perms=$(stat -c "%a" "$hidden_file" 2>/dev/null || echo "000")
                    if [[ "$perms" =~ ^[0-9]*[1357][0-9]*$ ]]; then
                        home_unrecognized="${home_unrecognized}${home}/${filename}(${filetype}, executable: ${perms}), "
                    else
                        home_unrecognized="${home_unrecognized}${home}/${filename}(${filetype}), "
                    fi
                else
                    home_unrecognized="${home_unrecognized}${home}/${filename}(${filetype}), "
                fi
                ((home_unrecognized_count++)) || true
            fi
        done < <(find "$home" -maxdepth 1 -name ".*" 2>/dev/null | head -50) || true
    done < /etc/passwd || true

    # 공용 임시/공유 디렉터리(/tmp, /var/tmp, /dev/shm)의 숨김 파일 점검 (백도어 은닉 상습 경로)
    local tmp_dir
    for tmp_dir in /tmp /var/tmp /dev/shm; do
        [ -d "$tmp_dir" ] || continue
        if [ ! -r "$tmp_dir" ]; then
            unreadable_areas="${unreadable_areas}${tmp_dir} "
            continue
        fi
        local tmp_find=$(find "$tmp_dir" -maxdepth 1 -name ".*" 2>/dev/null | head -50 || true)
        if [ -n "$tmp_find" ]; then
            raw_find_output="${raw_find_output}[Directory: $tmp_dir]\\n${tmp_find}\\n\\n"
        fi
        while IFS= read -r hidden_file; do
            [ -z "$hidden_file" ] && continue
            ((total_hidden++)) || true
            local tmp_name=$(basename "$hidden_file")
            # X11/ICE 등 표준 소켓·락 항목은 정상으로 간주
            case "$tmp_name" in
                .X11-unix|.ICE-unix|.XIM-unix|.font-unix|.Test-unix|.X*-lock)
                    continue ;;
            esac
            local tmp_type="file"
            if [ -d "$hidden_file" ]; then tmp_type="dir"; fi
            if [ -L "$hidden_file" ]; then tmp_type="symlink"; fi
            suspicious_files="${suspicious_files}${hidden_file}(${tmp_type}), "
            ((suspicious_count++)) || true
        done <<< "$tmp_find" || true
    done

    command_executed="while IFS=: read -r user pw uid gid gecos home shell; do find \"\$home\" -maxdepth 1 -name \".*\" 2>/dev/null; done < /etc/passwd; for d in /tmp /var/tmp /dev/shm; do find \"\$d\" -maxdepth 1 -name \".*\" 2>/dev/null; done" || true

    # 점검 범위 안내(홈 디렉터리 1단계 + /tmp,/var/tmp,/dev/shm 1단계)
    local scope_note="[점검 범위] 로그인 사용자 홈 디렉터리 1단계(-maxdepth 1, 출력 head -50 제한) + /tmp, /var/tmp, /dev/shm. 전체 파일시스템(/) 스캔은 타임아웃 방지를 위해 제외함."
    [ -n "$unreadable_areas" ] && scope_note="${scope_note}${newline}[읽기 불가로 미점검] ${unreadable_areas% }"

    # 최종 판정
    # - /tmp,/var/tmp,/dev/shm 의 비표준 숨김 항목은 백도어 은닉 상습 경로이므로 취약(VULNERABLE).
    # - 홈 디렉터리의 통상적이지 않은 dot 항목은 정상/악성을 정적으로 단정할 수 없어 수동진단(MANUAL).
    # - 읽기 불가 영역이 있어도 수동진단(MANUAL).
    if [ "$suspicious_count" -gt 0 ]; then
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="임시/공유 디렉터리(/tmp, /var/tmp, /dev/shm)에서 의심스러운 숨겨진 파일 ${suspicious_count}개가 발견되었습니다: ${suspicious_files%, }. 해당 파일들을 검토한 후 불필요하거나 악성적인 경우 제거하세요: rm -rf <file>"
        command_result="[Hidden files search results]${newline}${raw_find_output}${newline}[Suspicious files found]${newline}${suspicious_files%, }${newline}${scope_note}"
    elif [ "$home_unrecognized_count" -gt 0 ] || [ -n "$unreadable_areas" ]; then
        diagnosis_result="MANUAL"
        status="수동진단"
        local manual_detail=""
        [ "$home_unrecognized_count" -gt 0 ] && manual_detail="홈 디렉터리 내 통상적이지 않은 숨김 항목 ${home_unrecognized_count}개: ${home_unrecognized%, }. 불필요하거나 의심스러운 항목인지 수동으로 확인하세요."
        [ -n "$unreadable_areas" ] && manual_detail="${manual_detail}${manual_detail:+ }일부 영역을 읽을 수 없어 수동 점검 필요 (읽기 불가: ${unreadable_areas% })."
        inspection_summary="${manual_detail} 확인된 홈 디렉토리: ${checked_homedirs}개, 전체 숨겨진 파일: ${total_hidden}개"
        command_result="[Hidden files search results]${newline}${raw_find_output}${newline}[Home hidden items requiring manual review]${newline}${home_unrecognized%, }${newline}${scope_note}"
    else
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="의심스러운 숨겨진 파일이 발견되지 않았습니다. (확인된 홈 디렉토리: ${checked_homedirs}개, 전체 숨겨진 파일: ${total_hidden}개)"
        command_result="[Hidden files search results]${newline}${raw_find_output}${newline}[No suspicious files found (checked ${checked_homedirs} home directories, ${total_hidden} total hidden files)]${newline}${scope_note}"
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
