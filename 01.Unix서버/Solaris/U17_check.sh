#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : U-17
# @Category    : Unix Server
# @Platform    : Solaris
# @Severity    : 상
# @Title       : 시스템 시작 스크립트 권한 설정
# @Description : /etc/init.d, /etc/rc*.d 시작 스크립트 소유자/권한 확인
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


ITEM_ID="U-17"
ITEM_NAME="시스템 시작 스크립트 권한 설정"
SEVERITY="상"

# 가이드라인 정보
GUIDELINE_PURPOSE="시스템 시작 스크립트 파일을 관리자만 제어할 수 있게하여 비인가자들의 임의적인 파일 변조를 방지하기 위함"
GUIDELINE_THREAT="시스템 시작 스크립트 파일의 소유권 및 권한 설정이 미흡할 경우, 비인가자가 스크립트의 내용 변경 등을 통해 시스템 침입 등 악용할 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="시스템 시작 스크립트 파일의 소유자가 root이고, 일반 사용자의 쓰기 권한이 제거된 경우"
GUIDELINE_CRITERIA_BAD="시스템 시작 스크립트 파일의 소유자가 root가 아니거나, 일반 사용자의 쓰기 권한이 부여된 경우"
GUIDELINE_REMEDIATION="시스템 시작 스크립트 파일 소유자 및 권한 변경 설정"

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
    # Solaris 시스템 시작 스크립트 점검: /etc/init.d/*, /etc/rc*.d/*
    # 가이드라인: 소유자 root, 일반 사용자(others) 쓰기 권한 제거

    local vulnerable_files=""
    local vulnerable_count=0
    local vuln_listed=0
    local total_files=0
    local unreadable_dirs=""
    local found_dirs=""
    local raw_output=""
    local evidence_lines=0
    local rc_dir=""
    local entry=""

    for rc_dir in /etc/init.d /etc/rc*.d; do
        [ -d "$rc_dir" ] || continue
        found_dirs="${found_dirs}${rc_dir} "

        # 디렉터리 읽기 불가 시 수동 진단 대상
        if [ ! -r "$rc_dir" ]; then
            unreadable_dirs="${unreadable_dirs}${rc_dir}, "
            continue
        fi

        for entry in "$rc_dir"/*; do
            # glob 미일치(리터럴 패턴) 및 존재하지 않는 항목 제외
            [ -e "$entry" ] || continue
            # 일반 파일만 점검 (심볼릭 링크는 stat이 대상 파일 기준, dangling link 제외)
            [ -f "$entry" ] || continue
            ((total_files++)) || true

            # Solaris: perl stat으로 4자리 8진수 권한 + 소유자 확인
            # (stat(shift)로 파일 인자를 반드시 소비 - U-63 형 bare (stat) 버그 방지)
            local stat_out=""
            stat_out=$(perl -e '@s=stat(shift) or exit 1; $o=getpwuid($s[4]); $o=$s[4] unless defined($o) && length($o); printf "%04o %s", $s[2] & 07777, $o' "$entry" 2>/dev/null || true)
            [ -n "$stat_out" ] || continue
            local perms="${stat_out%% *}"
            local owner="${stat_out#* }"

            # 증거 출력은 20개까지만 기록 (개수는 전체 집계)
            if [ "$evidence_lines" -lt 20 ]; then
                raw_output="${raw_output}${perms} ${owner} ${entry}${newline}"
                ((evidence_lines++)) || true
            fi

            if [ "$owner" != "root" ]; then
                ((vulnerable_count++)) || true
                if [ "$vuln_listed" -lt 20 ]; then
                    vulnerable_files="${vulnerable_files}${entry} (소유자: ${owner}), "
                    ((vuln_listed++)) || true
                fi
            else
                # 일반 사용자(그룹 또는 others) 쓰기 권한: 4자리 8진수 문자열에서
                # others(마지막 자리) 또는 group(끝에서 2번째 자리)이 2,3,6,7이면 취약
                # (산술 % 10 사용 금지 - bash가 선행 0을 8진수로 해석하여 오판)
                local others_oct="${perms: -1}"
                local group_oct="${perms: -2:1}"
                case "$others_oct" in
                    2|3|6|7)
                        ((vulnerable_count++)) || true
                        if [ "$vuln_listed" -lt 20 ]; then
                            vulnerable_files="${vulnerable_files}${entry} (권한: ${perms}, others 쓰기 가능), "
                            ((vuln_listed++)) || true
                        fi
                        ;;
                    *)
                        case "$group_oct" in
                            2|3|6|7)
                                ((vulnerable_count++)) || true
                                if [ "$vuln_listed" -lt 20 ]; then
                                    vulnerable_files="${vulnerable_files}${entry} (권한: ${perms}, group 쓰기 가능), "
                                    ((vuln_listed++)) || true
                                fi
                                ;;
                        esac
                        ;;
                esac
            fi
        done
    done

    if [ "$total_files" -gt "$evidence_lines" ]; then
        raw_output="${raw_output}... (총 ${total_files}개 중 ${evidence_lines}개 표시)${newline}"
    fi
    if [ -n "$unreadable_dirs" ]; then
        raw_output="${raw_output}[읽기 불가 디렉터리] ${unreadable_dirs%, }${newline}"
    fi

    local exec_cmd="find /etc/init.d /etc/rc*.d -type f 2>/dev/null; perl -e '@s=stat(shift); printf \"%04o %s\", \$s[2] & 07777, scalar getpwuid(\$s[4])' <파일>"

    # 결과 판정
    if [ "$vulnerable_count" -gt 0 ]; then
        diagnosis_result="VULNERABLE"
        status="취약"
        local vuln_extra=""
        if [ "$vulnerable_count" -gt "$vuln_listed" ]; then
            vuln_extra=" 외 $((vulnerable_count - vuln_listed))개"
        fi
        inspection_summary="취약한 시작 스크립트 ${vulnerable_count}개 발견 (검사 ${total_files}개): ${vulnerable_files%, }${vuln_extra}"
        command_result="[Command: ${exec_cmd}]${newline}${raw_output}"
        command_executed="${exec_cmd}"
    elif [ -n "$unreadable_dirs" ]; then
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="시작 스크립트 디렉터리 접근 불가로 수동 확인 필요: ${unreadable_dirs%, }"
        command_result="[Command: ${exec_cmd}]${newline}${raw_output}"
        command_executed="${exec_cmd}"
    elif [ -z "$found_dirs" ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="시스템 시작 스크립트 디렉터리(/etc/init.d, /etc/rc*.d) 없음"
        command_result="[Command: ${exec_cmd}]${newline}[DIR NOT FOUND: /etc/init.d, /etc/rc*.d]"
        command_executed="${exec_cmd}"
    elif [ "$total_files" -eq 0 ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="시작 스크립트 디렉터리(${found_dirs% })에 점검 대상 파일 없음"
        command_result="[Command: ${exec_cmd}]${newline}[NO FILES FOUND in ${found_dirs% }]"
        command_executed="${exec_cmd}"
    else
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="모든 시작 스크립트 소유자 root, others 쓰기 권한 없음 (${total_files}개 검사)"
        command_result="[Command: ${exec_cmd}]${newline}${raw_output}"
        command_executed="${exec_cmd}"
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

    return 0
}

# 스크립트 직접 실행 시에만 진단 수행
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi
