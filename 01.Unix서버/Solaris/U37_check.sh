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
# @Platform    : Solaris
# @Severity    : 상
# @Title       : crontab 설정 파일 권한 설정 미흡
# @Description : /etc/crontab 권한 600 확인
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

# 진단 수행
diagnose() {


    diagnosis_result="unknown"
    local status="미진단"
    local inspection_summary=""
    local command_result=""
    local command_executed=""
    local newline=$'\n'

    # crontab 파일 권한 확인 (Solaris: /var/spool/cron/crontabs 사용)
    local crontab_files=(
        "/etc/cron.deny"
        "/etc/cron.allow"
        "/etc/at.deny"
        "/etc/at.allow"
    )

    local is_secure=true
    local issues=()
    local file_info=""
    local checked_any=false

    for file in "${crontab_files[@]}"; do
        if [ -f "$file" ]; then
            checked_any=true
            local perms=$(perl -e 'if (-f $ARGV[0]) { printf "%04o\n", (stat($ARGV[0]))[2] & 07777; }' "$file" 2>/dev/null || echo "000")
            local owner=$(perl -e 'if (-f $ARGV[0]) { $uid = (stat($ARGV[0]))[4]; print getpwuid($uid); }' "$file" 2>/dev/null || echo "unknown")

            file_info="${file_info}${file}: 권한=${perms}, 소유자=${owner}\\n"

            # cron.deny, at.deny는 600 이하 권장 (Solaris: /etc/crontab 없음)
            if [[ "$file" =~ (cron.deny|at.deny)$ ]]; then
                if [ $(( 8#$perms & ~8#640 & 8#7777 )) -ne 0 ]; then
                    is_secure=false
                    issues+=("${file} 권한=${perms} (640 이하 권장)")
                fi
                # root 소유여부 확인
                if [ "$owner" != "root" ]; then
                    is_secure=false
                    issues+=("${file} 소유자=${owner} (root여야 함)")
                fi
            fi

            # cron.allow, at.allow는 600 권장
            if [[ "$file" =~ (cron.allow|at.allow)$ ]]; then
                if [ $(( 8#$perms & ~8#640 & 8#7777 )) -ne 0 ]; then
                    is_secure=false
                    issues+=("${file} 권한=${perms} (640 이하 권장)")
                fi
                if [ "$owner" != "root" ]; then
                    is_secure=false
                    issues+=("${file} 소유자=${owner} (root여야 함)")
                fi
            fi
        fi
    done || true

    # /etc/cron.d 디렉토리 내 파일 권한 확인 (Solaris: /var/spool/cron/crontabs 사용)
    if [ -d /etc/cron.d ]; then
        file_info="${file_info}\\n/etc/cron.d 디렉토리 파일:\\n"
        while IFS= read -r -d '' file; do
            local perms=$(perl -e 'if (-f $ARGV[0]) { printf "%04o\n", (stat($ARGV[0]))[2] & 07777; }' "$file" 2>/dev/null || echo "000")
            local owner=$(perl -e 'if (-f $ARGV[0]) { $uid = (stat($ARGV[0]))[4]; print getpwuid($uid); }' "$file" 2>/dev/null || echo "unknown")
            file_info="${file_info}  $(basename "$file"): ${perms}, ${owner}\\n"
            checked_any=true

            if [ $(( 8#$perms & ~8#640 & 8#7777 )) -ne 0 ]; then
                is_secure=false
                issues+=("cron.d/$(basename "$file") 권한=${perms} (640 이하 권장)")
            fi
        done < <(find /etc/cron.d -type f -print0 2>/dev/null) || true
    fi

    # Solaris: /var/spool/cron/crontabs 확인
    if [ -d /var/spool/cron/crontabs ]; then
        file_info="${file_info}\\n/var/spool/cron/crontabs 디렉토리 파일:\\n"
        while IFS= read -r -d '' file; do
            local perms=$(perl -e 'if (-f $ARGV[0]) { printf "%04o\n", (stat($ARGV[0]))[2] & 07777; }' "$file" 2>/dev/null || echo "000")
            local owner=$(perl -e 'if (-f $ARGV[0]) { $uid = (stat($ARGV[0]))[4]; print getpwuid($uid); }' "$file" 2>/dev/null || echo "unknown")
            file_info="${file_info}  $(basename "$file"): ${perms}, ${owner}\\n"
            checked_any=true

            if [ $(( 8#$perms & ~8#640 & 8#7777 )) -ne 0 ]; then
                is_secure=false
                issues+=("crontabs/$(basename "$file") 권한=${perms} (640 이하 권장)")
            fi
        done < <(find /var/spool/cron/crontabs -type f -print0 2>/dev/null) || true
    fi

    # Solaris: /var/spool/cron/atjobs (at 작업 파일) 확인
    if [ -d /var/spool/cron/atjobs ]; then
        file_info="${file_info}\\n/var/spool/cron/atjobs 디렉토리 파일:\\n"
        while IFS= read -r -d '' file; do
            local perms=$(perl -e 'if (-f $ARGV[0]) { printf "%04o\n", (stat($ARGV[0]))[2] & 07777; }' "$file" 2>/dev/null || echo "000")
            local owner=$(perl -e 'if (-f $ARGV[0]) { $uid = (stat($ARGV[0]))[4]; print getpwuid($uid); }' "$file" 2>/dev/null || echo "unknown")
            file_info="${file_info}  $(basename "$file"): ${perms}, ${owner}\\n"
            checked_any=true

            if [ $(( 8#$perms & ~8#640 & 8#7777 )) -ne 0 ]; then
                is_secure=false
                issues+=("atjobs/$(basename "$file") 권한=${perms} (640 이하 권장)")
            fi
        done < <(find /var/spool/cron/atjobs -type f -print0 2>/dev/null) || true
    fi

    # crontab/at 명령어 일반 사용자 실행 권한 확인 (가이드: 750 이하)
    local cmd_path
    for cmd_path in /usr/bin/crontab /usr/bin/at; do
        if [ -f "$cmd_path" ]; then
            checked_any=true
            local perms=$(perl -e 'if (-f $ARGV[0]) { printf "%04o\n", (stat($ARGV[0]))[2] & 07777; }' "$cmd_path" 2>/dev/null || echo "000")
            local owner=$(perl -e 'if (-f $ARGV[0]) { $uid = (stat($ARGV[0]))[4]; print getpwuid($uid); }' "$cmd_path" 2>/dev/null || echo "unknown")
            file_info="${file_info}${cmd_path}: 권한=${perms}, 소유자=${owner}\\n"

            if [ $(( 8#$perms & ~8#750 & 8#7777 )) -ne 0 ]; then
                is_secure=false
                issues+=("${cmd_path} 권한=${perms} (일반 사용자 실행 권한 제거, 750 이하 필요)")
            fi
        fi
    done || true

    # 최종 판정
    if [ "$checked_any" = false ]; then
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="cron/at 관련 파일 및 명령어를 확인하지 못함 - 수동 점검 필요"
        command_result="${file_info:-점검 대상 파일/명령어 없음}"
        command_executed="ls -l /etc/cron.deny /etc/cron.allow /etc/at.deny /etc/at.allow /usr/bin/crontab /usr/bin/at 2>/dev/null"
    elif [ "$is_secure" = true ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="crontab 관련 파일 권한 적절함"
        command_result="${file_info}"
        command_executed="perl -e 'for $f (@ARGV) { if (-f $f) { printf \"%04o %s\\n\", (stat($f))[2] & 07777, (getpwuid((stat($f))[4]))[0]; } }' /etc/cron.deny /etc/cron.allow /etc/at.deny /etc/at.allow 2>/dev/null"
    else
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="crontab 파일 권한 미흡: ${issues[*]}"
        command_result="${file_info}"
        command_executed="perl -e 'for $f (@ARGV) { if (-f $f) { printf \"%04o %s\\n\", (stat($f))[2] & 07777, (getpwuid((stat($f))[4]))[0]; } }' /etc/cron.deny /etc/cron.allow /etc/at.deny /etc/at.allow 2>/dev/null; find /var/spool/cron/crontabs -type f 2>/dev/null"
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
