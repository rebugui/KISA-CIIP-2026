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
# @Platform    : Debian
# @Severity    : 상
# @Title       : 시스템 시작 스크립트 권한 설정
# @Description : /etc/init.d/* 권한 755 확인
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
    # 시스템 시작 스크립트 점검 (가이드 LINUX 절: [init] + [systemd])
    # [Leg 1] /etc/init.d/* — [Leg 2] /etc/systemd/system/* 유닛 파일 (동일 기준)
    # 가이드라인: 소유자 root, 일반 사용자(other) 쓰기 권한 제거

    local init_dir="/etc/init.d"
    local systemd_dir="/etc/systemd/system"
    local vulnerable_files=""
    local vulnerable_count=0
    local total_files=0
    local raw_output=""
    local checked_dirs=""
    local file_perms file_owner script_name others_perm group_perm unit_file

    # [Leg 1] /etc/init.d 내 모든 스크립트 점검
    if [ -d "$init_dir" ]; then
        checked_dirs="${init_dir} "
        for script_file in "$init_dir"/*; do
            [ -f "$script_file" ] || continue
            ((total_files++)) || true

            file_perms=$(stat -c "%a" "$script_file" 2>/dev/null || true)
            file_owner=$(stat -c "%U:%G" "$script_file" 2>/dev/null || true)
            script_name=$(basename "$script_file")

            raw_output="${raw_output}${script_name}: ${file_owner} ${file_perms}${newline}"

            # 소유자가 root가 아닌 경우
            if [ "$file_owner" != "root:root" ]; then
                ((vulnerable_count++)) || true
                vulnerable_files="${vulnerable_files}${script_name} (소유자: ${file_owner}), "
            else
                # 일반 사용자(그룹 또는 others) 쓰기 권한 확인
                # group 자리(끝에서 2번째) 또는 others 자리(마지막)에 쓰기비트(2,3,6,7)가 있으면 취약
                others_perm=${file_perms: -1}
                group_perm=${file_perms: -2:1}
                case "$others_perm" in
                    2|3|6|7)
                        ((vulnerable_count++)) || true
                        vulnerable_files="${vulnerable_files}${script_name} (권한: ${file_perms}, others 쓰기 가능), "
                        ;;
                    *)
                        case "$group_perm" in
                            2|3|6|7)
                                ((vulnerable_count++)) || true
                                vulnerable_files="${vulnerable_files}${script_name} (권한: ${file_perms}, group 쓰기 가능), "
                                ;;
                        esac
                        ;;
                esac
            fi
        done
    fi

    # [Leg 2] /etc/systemd/system 유닛 파일 점검 (init.d와 동일한 파일별 기준)
    if [ -d "$systemd_dir" ]; then
        checked_dirs="${checked_dirs}${systemd_dir} "
        while IFS= read -r unit_file; do
            [ -z "$unit_file" ] && continue
            ((total_files++)) || true

            file_perms=$(stat -c "%a" "$unit_file" 2>/dev/null || true)
            file_owner=$(stat -c "%U:%G" "$unit_file" 2>/dev/null || true)
            script_name="systemd:${unit_file#${systemd_dir}/}"

            raw_output="${raw_output}${script_name}: ${file_owner} ${file_perms}${newline}"

            # 소유자가 root가 아닌 경우
            if [ "$file_owner" != "root:root" ]; then
                ((vulnerable_count++)) || true
                vulnerable_files="${vulnerable_files}${script_name} (소유자: ${file_owner}), "
            else
                # 일반 사용자(그룹 또는 others) 쓰기 권한 확인
                others_perm=${file_perms: -1}
                group_perm=${file_perms: -2:1}
                case "$others_perm" in
                    2|3|6|7)
                        ((vulnerable_count++)) || true
                        vulnerable_files="${vulnerable_files}${script_name} (권한: ${file_perms}, others 쓰기 가능), "
                        ;;
                    *)
                        case "$group_perm" in
                            2|3|6|7)
                                ((vulnerable_count++)) || true
                                vulnerable_files="${vulnerable_files}${script_name} (권한: ${file_perms}, group 쓰기 가능), "
                                ;;
                        esac
                        ;;
                esac
            fi
        done < <(find "$systemd_dir" -type f 2>/dev/null || true)
    fi

    # 최종 판정
    if [ "$total_files" -eq 0 ]; then
        diagnosis_result="GOOD"
        status="양호"
        if [ -z "$checked_dirs" ]; then
            inspection_summary="시작 스크립트 디렉토리(${init_dir}, ${systemd_dir}) 없음"
            raw_output="[DIR NOT FOUND: ${init_dir} ${systemd_dir}]"
        else
            inspection_summary="점검 대상 디렉토리(${checked_dirs% })에 스크립트 파일 없음"
            raw_output="[NO FILES FOUND in ${checked_dirs% }]"
        fi
        command_result="${raw_output}"
        command_executed="ls -la $init_dir; find $systemd_dir -type f"
    elif [ "$vulnerable_count" -eq 0 ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="모든 시작 스크립트 권한 양호 (${total_files}개 검사: ${checked_dirs% })"
        command_result="${raw_output}"
        command_executed="stat -c '%a %U:%G' $init_dir/*; find $systemd_dir -type f -exec stat -c '%a %U:%G %n' {} +"
    else
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="취약한 시작 스크립트 ${vulnerable_count}개: ${vulnerable_files%, }"
        command_result="${raw_output}"
        command_executed="stat -c '%a %U:%G' $init_dir/*; find $systemd_dir -type f -exec stat -c '%a %U:%G %n' {} +"
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
