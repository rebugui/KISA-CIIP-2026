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
# @Platform    : RedHat
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
        command_result="[Command: ls -ld /var/log]${newline}Directory not found"
        command_executed="ls -ld /var/log"

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

        verify_result_saved "${ITEM_ID}"
        return 0
    fi

    # Capture raw output for /var/log directory and files (RedHat uses stat)
    raw_output=$(echo "=== /var/log Directory Info ===" && ls -ld /var/log 2>/dev/null && echo -e "\n=== Critical Log Files ===" && ls -la /var/log/messages /var/log/secure 2>/dev/null; echo -e "\n=== Group/World-Writable Files ===" && find /var/log -xdev -type f \( -perm -g+w -o -perm -o+w \) 2>/dev/null | head -5 || echo "None found")

    # 권한 및 소유자 확인 (RedHat: stat -c 지원)
    local dir_perms=$(stat -c "%a" "$log_dir" 2>/dev/null || echo "0000")
    local dir_owner=$(stat -c "%U" "$log_dir" 2>/dev/null || echo "unknown")
    local dir_group=$(stat -c "%G" "$log_dir" 2>/dev/null || echo "unknown")

    details="디렉토리 권한: ${dir_perms}, 소유자: ${dir_owner}:${dir_group}"

    # 디렉토리 소유자 확인
    if [ "$dir_owner" != "root" ]; then
        is_secure=false
        details="${details} (디렉토리 소유자가 root가 아님)"
    else
        # 개별 로그 파일 소유자 및 권한 확인 (/var/log 하위 디렉터리 포함 재귀 점검)
        local vulnerable_files=""
        local vuln_count=0
        local file_scan=""
        local evidence_found=false
        file_scan=$(find "$log_dir" -type f -printf '%m %u %p\n' 2>/dev/null) || true
        local f_perms="" f_owner="" f_path=""
        while IFS=' ' read -r f_perms f_owner f_path; do
            [ -n "${f_path:-}" ] || continue
            evidence_found=true
            # 소유자가 root(또는 정당한 로그 데몬 시스템 계정)가 아니거나 권한이 644 초과(644 비트 외
            # 권한 보유)인 경우 취약. systemd 호스트의 /var/log/journal/* 는 systemd-journal 소유,
            # 일부 배포판 로그는 syslog 소유가 표준이므로 이들 데몬 계정은 허용한다(그 외 비-root는 취약).
            # 644 초과 여부는 십진 비교가 아닌 비트 마스크(~644 = 7133)로 판정 (예: 622, 755 모두 취약)
            if [ "$f_owner" != "root" ] && [ "$f_owner" != "systemd-journal" ] && [ "$f_owner" != "syslog" ]; then
                vuln_count=$((vuln_count + 1))
                if [ "$vuln_count" -le 10 ]; then
                    vulnerable_files="${vulnerable_files}${f_path}(owner:${f_owner}) "
                fi
            elif [ $(( (8#${f_perms}) & (8#7133) )) -ne 0 ]; then
                vuln_count=$((vuln_count + 1))
                if [ "$vuln_count" -le 10 ]; then
                    vulnerable_files="${vulnerable_files}${f_path}(perm:${f_perms}) "
                fi
            fi
        done <<< "$file_scan"

        if [ "$vuln_count" -eq 0 ]; then
            if [ "$evidence_found" = true ]; then
                is_secure=true
            else
                diagnosis_result="MANUAL"
                status="수동진단"
                inspection_summary="/var/log 디렉터리 내 점검 가능한 로그 파일이 존재하지 않습니다"
                command_result="${raw_output}"
                command_executed="stat -c '%a %U %G' /var/log && find /var/log -type f -printf '%m %u %p\n' 2>/dev/null"
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
                verify_result_saved "${ITEM_ID}"
                return 0
            fi
        else
            is_secure=false
            details="${details}, 취약 파일 ${vuln_count}건(최대 10건 표시): ${vulnerable_files}"
        fi
    fi

    command_executed="stat -c '%a %U %G' /var/log && find /var/log -xdev -type f -printf '%m %u %p\n' 2>/dev/null"

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

    # root 권한 확인
    [ "$EUID" -ne 0 ] && { echo "root 권한이 필요합니다."; exit 1; }

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
