#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : U-37
# @Category    : Unix Server
# @Platform    : HP-UX
# @Severity    : 상
# @Title       : crontab 설정 파일 권한 설정 미흡
# @Description : /usr/bin/crontab·at 권한(750 이하) 및 /var/adm/cron(/usr/lib/cron), /var/spool/cron 관련 파일 권한(640 이하) 확인
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


ITEM_ID="U-37"
ITEM_NAME="crontab 설정 파일 권한 설정 미흡"
SEVERITY="상"

# 가이드라인 정보
GUIDELINE_PURPOSE="관리자 외에는 서비스를 사용할 수 없도록 설정하고 있는지 점검하기 위함"
GUIDELINE_THREAT="일반 사용자가 crontab 및 at 서비스를 사용할 수 있을 경우, 고의 또는 실수로 불법적인 예약 파일 실행으로 시스템 피해를 일으킬 수 있는 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="crontab 및 at 명령어에 일반 사용자 실행 권한이 제거되어 있으며,cron 및 at 관련 파일 권한이 640 이하인 경우"
GUIDELINE_CRITERIA_BAD="crontab 및 at 명령어에 일반 사용자 실행 권한이 부여되어 있으며,cron 및 at 관련 파일 권한이 640 이상인 경우"
GUIDELINE_REMEDIATION="crontab 및 at 명령어 파일 권한 750 이하,cron 및 at 관련 파일 소유자 및 파일 권한 640 이하 설정"

# ============================================================================
# 진단 함수
# ============================================================================

# 파일 권한을 4자리 8진수로 조회 (HP-UX: perl stat 사용, perl 미가용 시 ls 심볼릭 변환)
# 출력: "<4자리 권한> <소유자> <SUID(0/1)> <ls -ld 원본 행>"
get_file_perm() {
    local target="$1"
    local ls_line=""
    ls_line=$(ls -ld "$target" 2>/dev/null) || return 1
    if [ -z "$ls_line" ]; then
        return 1
    fi

    local owner
    owner=$(printf '%s\n' "$ls_line" | awk '{print $3}')

    local perm4=""
    if command -v perl >/dev/null 2>&1; then
        perm4=$(perl -e 'printf "%04o", (stat($ARGV[0]))[2] & 07777' "$target" 2>/dev/null) || perm4=""
    fi
    if [ -z "$perm4" ]; then
        local perm_str bits digits="" special=0 i d c
        perm_str=$(printf '%s\n' "$ls_line" | awk '{print $1}')
        bits="${perm_str:1:9}"
        if [ "${#bits}" -ne 9 ]; then
            return 1
        fi
        for i in 0 3 6; do
            d=0
            c="${bits:${i}:1}"
            if [ "$c" = "r" ]; then d=$((d + 4)); fi
            c="${bits:$((i + 1)):1}"
            if [ "$c" = "w" ]; then d=$((d + 2)); fi
            c="${bits:$((i + 2)):1}"
            case "$c" in
                x|s|t) d=$((d + 1)) ;;
            esac
            case "$c" in
                s|S)
                    if [ "$i" -eq 0 ]; then special=$((special + 4)); fi
                    if [ "$i" -eq 3 ]; then special=$((special + 2)); fi
                    ;;
                t|T)
                    if [ "$i" -eq 6 ]; then special=$((special + 1)); fi
                    ;;
            esac
            digits="${digits}${d}"
        done
        perm4="${special}${digits}"
    fi

    case "$perm4" in
        [0-7][0-7][0-7][0-7]) : ;;
        *) return 1 ;;
    esac

    local suid=0
    case "${perm4:0:1}" in
        4|5|6|7) suid=1 ;;
    esac

    printf '%s %s %s %s\n' "$perm4" "$owner" "$suid" "$ls_line"
    return 0
}

# 4자리 권한에 640(rw-r-----) 초과 비트가 있는지 비트 단위 검사 (10진 비교 아님)
perm_exceeds_640() {
    local p="$1"
    local o="${p:1:1}" g="${p:2:1}" t="${p:3:1}"
    case "$o" in 1|3|5|7) return 0 ;; esac
    case "$g" in 1|2|3|5|6|7) return 0 ;; esac
    if [ "$t" != "0" ]; then
        return 0
    fi
    return 1
}

# 4자리 권한에 750(rwxr-x---) 초과 비트가 있는지 비트 단위 검사 (crontab/at 명령어용)
perm_exceeds_750() {
    local p="$1"
    local g="${p:2:1}" t="${p:3:1}"
    case "$g" in 2|3|6|7) return 0 ;; esac
    if [ "$t" != "0" ]; then
        return 0
    fi
    return 1
}

# 진단 수행
diagnose() {


    diagnosis_result="unknown"
    local status="미진단"
    local inspection_summary=""
    local command_result=""
    local command_executed=""
    local newline=$'\n'

    # HP-UX 실제 경로 (가이드 'AIX, HP-UX' 절):
    #  - 명령어: /usr/bin/crontab, /usr/bin/at (소유자 root, 권한 750 이하)
    #  - 접근 제어 파일: /var/adm/cron/{cron.allow,cron.deny,at.allow,at.deny}
    #    (HP-UX는 /usr/lib/cron 변형 경로도 사용되므로 함께 점검) (root, 640 이하)
    #  - 작업 등록 파일: /var/spool/cron/crontabs, /var/spool/cron/atjobs (root, 640 이하)
    local binaries="/usr/bin/crontab /usr/bin/at"
    local spool_dirs="/var/spool/cron/crontabs /var/spool/cron/atjobs"

    local violations=""
    local manual_reason=""
    local evidence=""
    local acl_found=0
    local perm_info="" perms="" owner="" suid="" ls_raw="" f="" dir="" base="" acl_dir=""

    # 1) crontab 및 at 명령어: 일반 사용자 실행 권한 제거(750 이하), 소유자 root
    for f in $binaries; do
        if [ -e "$f" ]; then
            if perm_info=$(get_file_perm "$f"); then
                read -r perms owner suid ls_raw <<< "$perm_info"
                evidence="${evidence}${ls_raw}${newline}"
                if perm_exceeds_750 "$perms"; then
                    violations="${violations}${f} 권한=${perms} (명령어 750 이하 필요: 일반 사용자 실행 권한 제거); "
                fi
                if [ "$owner" != "root" ]; then
                    violations="${violations}${f} 소유자=${owner} (root 필요); "
                fi
                if [ "$suid" = "1" ]; then
                    evidence="${evidence}※ ${f}: SUID 설정됨 (가이드: SUID 제거 검토 필요)${newline}"
                fi
            else
                manual_reason="${manual_reason}${f} 권한 확인 불가; "
            fi
        else
            evidence="${evidence}${f}: 파일 없음${newline}"
        fi
    done

    # 2) cron/at 접근 제어 파일: 권한 640 이하, 소유자 root
    #    /var/adm/cron 우선, 없으면 /usr/lib/cron 변형 경로 확인
    for base in cron.allow cron.deny at.allow at.deny; do
        f=""
        for acl_dir in /var/adm/cron /usr/lib/cron; do
            if [ -e "${acl_dir}/${base}" ]; then
                f="${acl_dir}/${base}"
                break
            fi
        done
        if [ -n "$f" ]; then
            if perm_info=$(get_file_perm "$f"); then
                read -r perms owner suid ls_raw <<< "$perm_info"
                acl_found=$((acl_found + 1))
                evidence="${evidence}${ls_raw}${newline}"
                if perm_exceeds_640 "$perms"; then
                    violations="${violations}${f} 권한=${perms} (640 이하 필요); "
                fi
                if [ "$owner" != "root" ]; then
                    violations="${violations}${f} 소유자=${owner} (root 필요); "
                fi
            else
                manual_reason="${manual_reason}${f} 권한 확인 불가; "
            fi
        else
            evidence="${evidence}/var/adm/cron/${base} (및 /usr/lib/cron/${base}): 파일 없음${newline}"
        fi
    done

    # 3) cron/at 작업 등록 파일: 권한 640 이하, 소유자 root
    for dir in $spool_dirs; do
        if [ -d "$dir" ]; then
            while IFS= read -r f; do
                if [ ! -f "$f" ]; then
                    continue
                fi
                if perm_info=$(get_file_perm "$f"); then
                    read -r perms owner suid ls_raw <<< "$perm_info"
                    evidence="${evidence}${ls_raw}${newline}"
                    if perm_exceeds_640 "$perms"; then
                        violations="${violations}${f} 권한=${perms} (640 이하 필요); "
                    fi
                    if [ "$owner" != "root" ]; then
                        violations="${violations}${f} 소유자=${owner} (root 필요); "
                    fi
                else
                    manual_reason="${manual_reason}${f} 권한 확인 불가; "
                fi
            done < <(find "$dir" -type f 2>/dev/null | head -200) || true
        else
            evidence="${evidence}${dir}: 디렉터리 없음${newline}"
        fi
    done

    command_executed="ls -ld /usr/bin/crontab /usr/bin/at /var/adm/cron/cron.allow /var/adm/cron/cron.deny /var/adm/cron/at.allow /var/adm/cron/at.deny /usr/lib/cron/cron.allow /usr/lib/cron/cron.deny /usr/lib/cron/at.allow /usr/lib/cron/at.deny 2>/dev/null; perl -e 'printf q{%04o}, (stat(\$ARGV[0]))[2] & 07777' <대상파일>; find /var/spool/cron/crontabs /var/spool/cron/atjobs -type f 2>/dev/null | xargs ls -ld 2>/dev/null"

    # 최종 판정 (판단기준 양호: crontab 및 at 명령어에 일반 사용자 실행 권한이
    # 제거되어 있으며, cron 및 at 관련 파일 권한이 640 이하인 경우)
    if [ -n "$violations" ]; then
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="cron/at 관련 파일 권한 미흡: ${violations}"
        command_result="${evidence}"
    elif [ -n "$manual_reason" ]; then
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="cron/at 관련 파일 권한을 확인할 수 없어 수동 진단 필요: ${manual_reason}"
        command_result="${evidence}확인 불가: ${manual_reason}"
    elif [ "$acl_found" -eq 0 ]; then
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="cron/at 접근 제어 파일(/var/adm/cron 또는 /usr/lib/cron의 cron.allow·cron.deny·at.allow·at.deny)이 존재하지 않음 - 명령어 및 작업 등록 파일 권한 위반은 없으나, HP-UX는 cron.allow·cron.deny가 모두 없으면 root만 cron/at 사용이 허용되는 보안 기본값이므로 접근 제어 정책을 수동으로 확인 필요"
        command_result="${evidence}"
    else
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="crontab/at 명령어(750 이하, root 소유) 및 cron/at 관련 파일(640 이하, root 소유) 권한 기준 충족"
        command_result="${evidence}"
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
