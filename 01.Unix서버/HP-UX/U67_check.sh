#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : U-67
# @Category    : Unix Server
# @Platform    : HP-UX
# @Severity    : 중
# @Title       : 로그 디렉터리 소유자 및 권한 설정
# @Description : /var/log 권한 700 또는 750 확인
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


ITEM_ID="U-67"
ITEM_NAME="로그 디렉터리 소유자 및 권한 설정"
SEVERITY="중"

# 가이드라인 정보
GUIDELINE_PURPOSE="로그 파일을 관리자만 제어할 수 있게하여 비인가자의 임의적인 파일 훼손 및 변조를 방지하기 위함"
GUIDELINE_THREAT="로그에 대한 접근 통제가 미흡할 경우, 비인가자가 로그에서 정보를 획득하거나 로그 자체를 변조할 수 있는 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="디렉터리 내 로그 파일의 소유자가 root이고, 권한이 644 이하인 경우"
GUIDELINE_CRITERIA_BAD="디렉터리 내 로그 파일의 소유자가 root가 아니거나, 권한이 644를 초과하는 경우"
GUIDELINE_REMEDIATION="디렉터리 내 로그 파일 소유자 및 권한 변경 설정"

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
    # /var/log 디렉터리 소유자 및 권한 설정 확인

    local log_dir="/var/log"
    local is_secure=false
    local details=""
    local raw_output=""

    # 디렉터리 존재 확인
    if [ ! -d "$log_dir" ]; then
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="/var/log 디렉터리가 존재하지 않습니다"
        local log_dir_check=$(ls -ld /var/log 2>/dev/null || echo "Directory not found: /var/log")
        command_result="${log_dir_check}"
        command_executed="ls -ld /var/log"

        echo ""
      #  echo "진단 결과: ${status}"
      # echo "판정: ${diagnosis_result}"
      # echo "설명: ${inspection_summary}"
        echo ""

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
    fi

    # Capture raw output for /var/log directory and files (HP-UX uses perl for stat)
    raw_output=$(echo "=== /var/log Directory Info ===" && ls -ld /var/log 2>/dev/null && echo -e "\n=== Critical Log Files (HP-UX) ===" && ls -l /var/adm/syslog/syslog.log /var/adm/sulog /var/adm/wtmp 2>/dev/null; echo -e "\n=== Group/World-Writable Files ===" && find /var/log -type f \( -perm -g+w -o -perm -o+w \) 2>/dev/null | head -5; echo -e "\n=== Non-root Owned Files ===" && find /var/log -type f ! -user root ! -user syslog 2>/dev/null | head -5 || echo "None found")

    # 권한 및 소유자 확인
    local perms=$(perl -e 'printf "%04o\n", (stat(shift))[2] & 07777' "$log_dir" 2>/dev/null || echo "0000")
    local owner=$(perl -e 'print getpwuid((stat(shift))[4])' "$log_dir" 2>/dev/null || echo "unknown")
    local group=$(perl -e 'print getgrgid((stat(shift))[5])' "$log_dir" 2>/dev/null || echo "unknown")

    details="권한: ${perms}, 소유자: ${owner}:${group}"

    # 권한/소유자 확인 불가(perl stat 실패) → 증거 미확보로 수동진단
    if [[ ! "$perms" =~ ^[0-7]{3,4}$ ]] || [ "$owner" = "unknown" ]; then
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="/var/log 권한/소유자 정보를 확인하지 못함 (perl stat 실패) - 수동 점검 필요 (${details})"
        command_result="${raw_output}"
        save_dual_result \
            "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" \
            "${inspection_summary}" "${command_result}" "${command_executed}" \
            "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" \
            "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
        verify_result_saved "${ITEM_ID}"
        return 0
    fi

    # 보안 판정 (권한 700 또는 750 (디렉토리), 소유자 root)
    # 디렉토리 자체에 group/other 쓰기 비트가 있으면 즉시 취약 (770 등 group-write 차단)
    # 디렉토리 자체에 group/other 쓰기 비트가 없으면(700/750/751/755 등) 통과하여 하위 점검 진행.
    # group/other 쓰기 비트 보유(770/775/757 등) → 즉시 취약. others 읽기/실행만 있는 경우는 허용.
    if [ "$owner" = "root" ] && [ "$(( 8#$perms & 022 ))" -eq 0 ]; then
           # 개별 로그 파일 소유자 및 권한 재귀 점검 (RedHat 형제와 동일한 비트마스크 기준)
           # 소유자가 root(또는 정당한 로그 데몬 syslog)가 아니거나, 권한이 644 초과(644 외 비트 보유)이면 취약.
           # 644 초과 여부는 십진 비교가 아닌 비트 마스크(~644 = 7133)로 판정 → 755/744/751 등 비쓰기 초과 모드와
           # SUID/SGID(4755/2644)도 취약으로 판정 (쓰기 비트만 보는 기존 find 프리필터의 false_good 차단).
           # HP-UX find 에는 -printf 가 없으므로 파일 목록을 받아 perl stat 으로 권한/소유자를 확인한다.
           local insecure_files=""
           local file_list=$(find "$log_dir" /var/adm -type f 2>/dev/null) || true
           local f_path="" f_perm="" f_owner=""
           while IFS= read -r f_path; do
                [ -n "${f_path:-}" ] || continue
                f_perm=$(perl -e 'printf "%04o\n", (stat(shift))[2] & 07777' "$f_path" 2>/dev/null || echo "0000")
                f_owner=$(perl -e 'print getpwuid((stat(shift))[4])' "$f_path" 2>/dev/null || echo "unknown")
                if [ "$f_owner" != "root" ] && [ "$f_owner" != "syslog" ]; then
                     insecure_files="${insecure_files}${f_path}(owner:${f_owner}) "
                elif [ "$(( (8#$f_perm) & (8#7133) ))" -ne 0 ]; then
                     insecure_files="${insecure_files}${f_path}(perm:${f_perm}) "
                fi
           done <<< "$file_list"

           if [ -n "$insecure_files" ]; then
                is_secure=false
                details="${details}, 취약 파일 발견: ${insecure_files}..."
           else
                # Check specific critical logs (HP-UX 실제 로그 경로: /var/adm 하위)
                local critical_logs=("/var/adm/syslog/syslog.log" "/var/adm/syslog/mail.log" "/var/adm/sulog" "/var/adm/wtmp" "/var/adm/btmp")
                local crit_issue=false
                local crit_found=false

                for log in "${critical_logs[@]}"; do
                    if [ -f "$log" ]; then
                        crit_found=true
                        local l_perm=$(perl -e 'printf "%04o\n", (stat(shift))[2] & 07777' "$log" 2>/dev/null || echo "0000")
                        local l_owner=$(perl -e 'print getpwuid((stat(shift))[4])' "$log" 2>/dev/null || echo "unknown")

                        # Expected: 600 or 640. 644 is arguably OK if info leakage is not critical, but guideline says <= 644.
                        # If > 644 (e.g. 666), bad.

                        if [ "$l_owner" != "root" ] && [ "$l_owner" != "syslog" ]; then
                            # Allow syslog user owner
                            crit_issue=true
                            details="${details}, ${log} owner invalid ($l_owner)"
                        fi

                        # 권한 644 초과 여부(644 외 비트: group/other write, 추가 exec, SUID/SGID)를 비트 마스크(~644 = 7133)로 판정
                        # (RedHat/Solaris 형제와 동일 기준 — 0755/0744/4755/2644 등 비쓰기 초과 모드도 취약으로 판정)
                        if [[ "$l_perm" =~ ^[0-7]{3,4}$ ]] && [ $(( (8#${l_perm}) & (8#7133) )) -ne 0 ]; then
                             crit_issue=true
                             details="${details}, ${log} 권한 644 초과 ($l_perm)"
                        fi
                    fi
                done || true

                if [ "$crit_issue" = true ]; then
                    is_secure=false
                elif [ "$crit_found" = false ]; then
                    # 주요 로그 파일이 하나도 존재하지 않음 → 증거 미확보로 GOOD 단정 불가
                    is_secure=false
                    diagnosis_result="MANUAL"
                    details="${details}, 주요 로그 파일을 찾을 수 없어 확인 불가 (수동 점검 필요)"
                else
                    is_secure=true
                fi
           fi
    else
        is_secure=false
        details="${details} (디렉토리 소유자/권한 취약)"
    fi

    command_executed="perl -e 'printf \"%04o %s\\n\", (stat(\"/var/log\"))[2] & 07777, getpwuid((stat(\"/var/log\"))[4])' 2>/dev/null; find /var/log -type f \\( -perm -g+w -o -perm -o+w \\); find /var/log -type f ! -user root ! -user syslog; ls -l /var/adm/syslog/syslog.log /var/adm/sulog /var/adm/wtmp"

    # 최종 판정
    if [ "$diagnosis_result" = "MANUAL" ]; then
        # 증거 미확보(주요 로그 파일 부재 등) → 수동진단 유지, GOOD 단정 금지
        status="수동진단"
        inspection_summary="/var/log 로그 설정을 확정하지 못함 (${details})"
        command_result="${raw_output}"
    elif [ "$is_secure" = true ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="/var/log 디렉터리 및 주요 로그 파일 설정이 양호합니다 (${details})"
        command_result="${raw_output}"
    else
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="/var/log 설정 미흡 (${details})"
        command_result="${raw_output}"
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
