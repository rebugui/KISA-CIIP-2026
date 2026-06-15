#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : U-27
# @Category    : Unix Server
# @Platform    : Debian
# @Severity    : 상
# @Title       : \$HOME/.rhosts, hosts.equiv 사용 금지
# @Description : .rhosts, hosts.equiv 파일 확인
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


ITEM_ID="U-27"
ITEM_NAME="\$HOME/.rhosts, hosts.equiv 사용 금지"
SEVERITY="상"

# 가이드라인 정보
GUIDELINE_PURPOSE="r-command를 통한 별도의 인증 없는 관리자 권한 원격 접속을 차단하기 위함"
GUIDELINE_THREAT="r-command(rlogin, rsh 등)에 보안 설정이 적용되지 않을 경우, 원격지의 공격자가 관리자 권한으로 목표 시스템상 임의의 명령을 수행시킬 수 있으며, 명령어 원격 실행을 통해 중요 정보 유출 및 시스템 장애를 유발 또는 공격자의 백 도어 등으로도 활용될 수 있는 위험이 존재함 해당 파일은 r-command 서비스의 접근 통제에 관련된 파일이며, 권한 설정이 부적절한 경우 r-command 서비스 사용 권한을 임의로 등록하여 무단 사용 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="rlogin,rsh,rexec 서비스를 사용하지 않거나, 사용 시 아래와 같은 설정이 적용된 경우 1. /etc/hosts.equiv 및 \$HOME/.rhosts 파일 소유자가 root 또는 해당 계정인 경우 2. /etc/hosts.equiv 및 \$HOME/.rhosts 파일 권한이 600 이하인 경우 3. /etc/hosts.equiv 및 \$HOME/.rhosts 파일 설정에'+'설정이 없는 경우"
GUIDELINE_CRITERIA_BAD="rlogin,rsh,rexec 서비스를 사용하며 아래와 같은 설정이 적용되지 않은 경우 1. /etc/hosts.equiv 및 \$HOME/.rhosts 파일 소유자가 root 또는 해당 계정이 아닌 경우"
GUIDELINE_REMEDIATION="/etc/hosts.equiv, \$HOME/.rhosts 파일 소유자 및 권한 변경, 허용 호스트 및 계정 등록 설정"

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
    # .rhosts, hosts.equiv 파일 사용 금지 확인

    local rhosts_files=""
    local rhosts_count=0
    local hosts_equiv_exists=0
    local hosts_equiv_details=""
    local details=""
    # 보안 위반 카운트(소유자 불일치/권한 초과/'+' 설정). 0 이면 양호.
    local insecure_count=0

    # Capture raw find output for .rhosts files
    local rhosts_find=$(find /home -name '.rhosts' 2>/dev/null)
    # Capture ls output for hosts.equiv
    local hosts_equiv_ls=$(ls -l /etc/hosts.equiv 2>&1)
    # Build command_result
    command_result="[Command: find /home -name '.rhosts']${newline}${rhosts_find}${newline}${newline}[Command: ls -l /etc/hosts.equiv]${newline}${hosts_equiv_ls}"

    # /etc/hosts.equiv 파일 확인
    if [ -f "/etc/hosts.equiv" ]; then
        ((hosts_equiv_exists++)) || true
        local perms=$(stat -c "%a" "/etc/hosts.equiv" 2>/dev/null)
        local owner=$(stat -c "%U:%G" "/etc/hosts.equiv" 2>/dev/null)
        local owner_user=$(stat -c "%U" "/etc/hosts.equiv" 2>/dev/null)
        local size=$(stat -c "%s" "/etc/hosts.equiv" 2>/dev/null)
        # 주석(#)을 제외한 라인에서 '+' 단독 설정(++/+ 사용자/호스트+ 등) 존재 여부
        local has_plus=$(grep -vE '^[[:space:]]*#' "/etc/hosts.equiv" 2>/dev/null | grep -E '(^|[[:space:]])\+' || true)
        local equiv_issue=""

        # 소유자가 root가 아닌 경우
        if [ "$owner_user" != "root" ]; then
            ((insecure_count++)) || true
            equiv_issue="${equiv_issue} [소유자 불일치]"
        fi
        # 권한이 600 초과인 경우 (600을 넘는 비트가 있으면 취약)
        if ! [[ "$perms" =~ ^[0-7]{3,4}$ ]] || [ "$(( 8#$perms & ~8#600 & 07777 ))" -ne 0 ] 2>/dev/null; then
            ((insecure_count++)) || true
            equiv_issue="${equiv_issue} [권한 초과]"
        fi
        # '+' 설정이 있는 경우
        if [ -n "$has_plus" ]; then
            ((insecure_count++)) || true
            equiv_issue="${equiv_issue} [+설정 존재]"
        fi

        hosts_equiv_details="/etc/hosts.equiv 파일 존재 (권한: ${perms}, 소유자: ${owner}, 크기: ${size}bytes)${equiv_issue}"
    fi

    # 사용자 홈 디렉터리에서 .rhosts 파일 검색
    while IFS= read -r user_line; do
        local username=$(echo "$user_line" | cut -d: -f1)
        local uid=$(echo "$user_line" | cut -d: -f3)
        local home_dir=$(echo "$user_line" | cut -d: -f6)

        # 홈 디렉터리가 존재하는 모든 계정 점검 (UID 1-999 서비스 계정 홈의
        # .rhosts도 r-command 신뢰 설정에 악용될 수 있으므로 점검 대상)
        if [ -d "$home_dir" ] && [ "$uid" -ge 0 ] 2>/dev/null; then
            local rhosts_path="${home_dir}/.rhosts"

            if [ -f "$rhosts_path" ]; then
                ((rhosts_count++)) || true
                local perms=$(stat -c "%a" "$rhosts_path" 2>/dev/null)
                local owner=$(stat -c "%U" "$rhosts_path" 2>/dev/null)
                local size=$(stat -c "%s" "$rhosts_path" 2>/dev/null)
                # 주석(#)을 제외한 라인에서 '+' 설정 존재 여부
                local has_plus=$(grep -vE '^[[:space:]]*#' "$rhosts_path" 2>/dev/null | grep -E '(^|[[:space:]])\+' || true)
                local rhosts_issue=""

                # 소유자가 해당 계정 또는 root가 아닌 경우
                if [ "$owner" != "root" ] && [ "$owner" != "$username" ]; then
                    ((insecure_count++)) || true
                    rhosts_issue="${rhosts_issue} [소유자 불일치]"
                fi
                # 권한이 600 초과인 경우 (600을 넘는 비트가 있으면 취약)
                if ! [[ "$perms" =~ ^[0-7]{3,4}$ ]] || [ "$(( 8#$perms & ~8#600 & 07777 ))" -ne 0 ] 2>/dev/null; then
                    ((insecure_count++)) || true
                    rhosts_issue="${rhosts_issue} [권한 초과]"
                fi
                # '+' 설정이 있는 경우
                if [ -n "$has_plus" ]; then
                    ((insecure_count++)) || true
                    rhosts_issue="${rhosts_issue} [+설정 존재]"
                fi

                rhosts_files="${rhosts_files}${rhosts_path} (권한: ${perms}, 소유자: ${owner}, 크기: ${size}bytes)${rhosts_issue}, "
            fi
        fi
    done < /etc/passwd || true

    # 결과 판정
    # 파일이 없거나(첫 분기), 존재하더라도 소유자 root/계정 + 권한<=600 + '+' 없음을
    # 모두 만족하면(insecure_count==0) 가이드라인상 양호. 하나라도 위반 시에만 취약.
    if [ "$hosts_equiv_exists" -eq 0 ] && [ "$rhosts_count" -eq 0 ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary=".rhosts 및 hosts.equiv 파일 없음 (r 계정 사용 제어 양호)"
        # 실제 수집 증거(command_result, L73 구성)를 그대로 유지
        command_executed="find /home -name '.rhosts' 2>/dev/null; ls -l /etc/hosts.equiv 2>/dev/null"
    elif [ "$insecure_count" -eq 0 ]; then
        diagnosis_result="GOOD"
        status="양호"
        details=""

        if [ "$hosts_equiv_exists" -gt 0 ]; then
            details="${details}${hosts_equiv_details}. "
        fi

        if [ "$rhosts_count" -gt 0 ]; then
            details="${details}.rhosts 파일 ${rhosts_count}개 발견: ${rhosts_files%, }. "
        fi

        inspection_summary="양호: 파일이 존재하나 소유자/권한(600 이하)/'+' 미설정 기준을 모두 만족함. ${details}"
        # 실제 수집 증거(command_result, L73 구성)를 그대로 유지
        command_executed="find /home -name '.rhosts' 2>/dev/null; ls -l /etc/hosts.equiv 2>/dev/null"
    else
        diagnosis_result="VULNERABLE"
        status="취약"
        details=""

        if [ "$hosts_equiv_exists" -gt 0 ]; then
            details="${details}${hosts_equiv_details}. "
        fi

        if [ "$rhosts_count" -gt 0 ]; then
            details="${details}.rhosts 파일 ${rhosts_count}개 발견: ${rhosts_files%, }. "
        fi

        inspection_summary="취약: ${details}"
        command_result="hosts.equiv: ${hosts_equiv_exists} found, .rhosts: ${rhosts_count} found"
        command_executed="find /home -name '.rhosts' 2>/dev/null; ls -l /etc/hosts.equiv 2>/dev/null"
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
