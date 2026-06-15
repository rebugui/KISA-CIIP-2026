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
# @Platform    : Solaris
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
        local log_check=$(ls -ld /var/log 2>/dev/null || echo "Directory not found")
        command_result="[Command: ls -ld /var/log]${newline}${log_check}"
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

    # Capture raw output for /var/log and /var/adm (Solaris uses perl for stat)
    raw_output=$(
        echo "=== /var/log Directory Info ==="
        ls -ld /var/log /var/adm 2>/dev/null
        echo ""
        echo "=== Critical Log Files ==="
        ls -la /var/log/syslog /var/log/authlog /var/adm/messages /var/adm/sulog /var/adm/loginlog /var/adm/authlog 2>/dev/null
        echo ""
        echo "=== Group/World-Writable Log Files ==="
        find /var/log /var/adm -type f \( -perm -g+w -o -perm -o+w \) 2>/dev/null | head -5 || echo "None found"
    )

    # 권한 및 소유자 확인
    local perms=$(perl -e 'printf "%04o\n", (stat)[2] & 07777' "$log_dir" 2>/dev/null || echo "000")
    local owner=$(perl -e 'print getpwuid((stat)[4])' "$log_dir" 2>/dev/null || echo "unknown")
    local group=$(perl -e 'print getgrgid((stat)[5])' "$log_dir" 2>/dev/null || echo "unknown")

    details="권한: ${perms}, 소유자: ${owner}:${group}"

    # 보안 판정 (권한 700 또는 750 (디렉토리), 소유자 root)
    if [ "$owner" = "root" ]; then
        # 디렉터리 권한에서 그룹/기타 자릿수를 추출 (4자리 sticky 모드도 정규화)
        # 마지막 3자리만 사용 (owner/group/other), 그룹·기타에 쓰기 비트(2,3,6,7) 없을 것
        # → group-write 가능 디렉토리(760/770 등)를 GOOD으로 오판하던 미탐(false-good) 차단
        local perms_norm="${perms: -3}"        # 마지막 3자리 (owner/group/other)
        local dir_group_digit="${perms_norm:1:1}"
        local dir_other_digit="${perms_norm:2:1}"
        # 권한 형식이 비정상(숫자 아님)이면 보수적으로 취약 처리
        if [[ "$perms" =~ ^[0-7]{3,4}$ ]] \
           && [[ ! "$dir_group_digit" =~ [2367] ]] \
           && [[ ! "$dir_other_digit" =~ [2367] ]]; then  # 그룹/기타 쓰기 권한 없음 (700/750 허용)
        # Guideline says 644 for files. For Dir, it implies access control.

           # 권한이 644를 초과하는 파일(644 외 비트 보유: 추가 exec/SUID/SGID/group·other write 등) 탐지
           # → 쓰기 비트만이 아닌 십진 644 초과를 비트 마스크(~644 = 7133)로 판정 (RedHat/AIX 형제 스크립트와 동일, 예: 755/4755/2644/666 모두 취약)
           local insecure_files=""
           while IFS= read -r f_path; do
               [ -n "${f_path:-}" ] || continue
               local f_perms=$(perl -e 'printf "%04o\n", (stat)[2] & 07777' "$f_path" 2>/dev/null || echo "0000")
               if [[ "$f_perms" =~ ^[0-7]{3,4}$ ]] && [ $(( (8#${f_perms}) & (8#7133) )) -ne 0 ]; then
                   insecure_files="${insecure_files}${f_path}(perm:${f_perms}) "
               fi
           done <<< "$(find "$log_dir" /var/adm -type f 2>/dev/null | head -50)"

           if [ -n "$insecure_files" ]; then
                is_secure=false
                details="${details}, 권한 644 초과 파일: ${insecure_files}..."
           else
                # Check specific critical logs (Solaris-native /var/adm 로그 포함)
                local critical_logs=("/var/log/syslog" "/var/log/authlog" "/var/adm/messages" "/var/adm/sulog" "/var/adm/loginlog" "/var/adm/authlog")
                local crit_issue=false

                for log in "${critical_logs[@]}"; do
                    if [ -f "$log" ]; then
                        local l_perm=$(perl -e 'printf "%04o\n", (stat)[2] & 07777' "$log" 2>/dev/null || echo "")
                        local l_owner=$(perl -e 'print getpwuid((stat)[4])' "$log" 2>/dev/null || echo "")

                        # Expected: 600 or 640. 644 is arguably OK if info leakage is not critical, but guideline says <= 644.
                        # If > 644 (e.g. 666), bad.

                        if [ "$l_owner" != "root" ] && [ "$l_owner" != "syslog" ] && [ "$l_owner" != "adm" ] && [ "$l_owner" != "sys" ]; then
                            # Allow syslog/adm/sys system owners
                            crit_issue=true
                            details="${details}, ${log} owner invalid ($l_owner)"
                        fi

                        # 권한 644 초과 여부(644 외 비트: group/other write, 추가 exec, SUID/SGID)를 비트 마스크(~644 = 7133)로 판정
                        if [[ "$l_perm" =~ ^[0-7]{3,4}$ ]] && [ $(( (8#${l_perm}) & (8#7133) )) -ne 0 ]; then
                             crit_issue=true
                             details="${details}, ${log} 권한 644 초과 ($l_perm)"
                        fi
                    fi
                done || true

                # critical 목록 외 파일 포함 비표준 소유자 로그 파일 검사
                local bad_owner_files=$(find "$log_dir" /var/adm -type f ! -user root ! -user adm ! -user sys ! -user syslog 2>/dev/null | head -5 || true)
                if [ -n "$bad_owner_files" ]; then
                    crit_issue=true
                    details="${details}, 비표준 소유자 로그 파일: ${bad_owner_files//$'\n'/ }"
                fi

                if [ "$crit_issue" = true ]; then
                    is_secure=false
                else
                    is_secure=true
                fi
           fi
        else
            is_secure=false
            details="${details} (디렉토리 권한 취약)"
        fi
    else
        is_secure=false
        details="${details} (디렉토리 소유자 취약)"
    fi

    command_executed="perl -e 'printf \"%04o %s %s\", (stat)[2] & 07777, getpwuid((stat)[4]), getgrgid((stat)[5])' /var/log; find /var/log /var/adm -type f ( -perm -g+w -o -perm -o+w )"

    # 최종 판정
    if [ "$is_secure" = true ]; then
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
