#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-04-20
# ============================================================================
# [점검 항목 상세]
# @ID          : U-27
# @Category    : UNIX > 3. 서비스 관리
# @Platform    : RedHat
# @Severity    : 상
# @Title       : \$HOME/.rhosts, hosts.equiv 사용 금지
# @Description : 원격 접속 시 인증 없이 접근 가능한 설정 파일 존재 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/metadata_parser.sh"

ITEM_ID="U-27"
ITEM_NAME="\$HOME/.rhosts, hosts.equiv 사용 금지"
SEVERITY="상"

GUIDELINE_PURPOSE="r-command를 통한 별도의 인증 없는 관리자 권한 원격 접속을 차단하기 위함"
GUIDELINE_THREAT="r-command(rlogin, rsh 등)에 보안 설정이 적용되지 않을 경우, 원격지의 공격자가 관리자 권한으로 목표 시스템상 임의의 명령을 수행시킬 수 있으며, 명령어 원격 실행을 통해 중요 정보 유출 및 시스템 장애를 유발 또는 공격자의 백 도어 등으로도 활용될 수 있는 위험이 존재함 해당 파일은 r-command 서비스의 접근 통제에 관련된 파일이며, 권한 설정이 부적절한 경우 r-command 서비스 사용 권한을 임의로 등록하여 무단 사용 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="rlogin,rsh,rexec 서비스를 사용하지 않거나, 사용 시 아래와 같은 설정이 적용된 경우 1. /etc/hosts.equiv 및 \$HOME/.rhosts 파일 소유자가 root 또는 해당 계정인 경우 2. /etc/hosts.equiv 및 \$HOME/.rhosts 파일 권한이 600 이하인 경우 3. /etc/hosts.equiv 및 \$HOME/.rhosts 파일 설정에'+'설정이 없는 경우"
GUIDELINE_CRITERIA_BAD="rlogin,rsh,rexec 서비스를 사용하며 아래와 같은 설정이 적용되지 않은 경우 1. /etc/hosts.equiv 및 \$HOME/.rhosts 파일 소유자가 root 또는 해당 계정이 아닌 경우"
GUIDELINE_REMEDIATION="/etc/hosts.equiv, \$HOME/.rhosts 파일 소유자 및 권한 변경, 허용 호스트 및 계정 등록 설정"

diagnose() {
    local status="양호"
    diagnosis_result="GOOD"
    local inspection_summary=""
    local command_result=""
    local command_executed="ls -la /etc/hosts.equiv; find /home -name .rhosts -exec ls -la {} \\;"
    local evidence=""

    # ==========================================================================
    # 1. /etc/hosts.equiv 확인
    # ==========================================================================
    local equiv="/etc/hosts.equiv"
    if [ -f "$equiv" ]; then
        local equiv_owner=$(stat -c "%U" "$equiv" 2>/dev/null || echo "unknown")
        local equiv_perm=$(stat -c "%a" "$equiv" 2>/dev/null || echo "000")
        local equiv_has_plus=$(grep -vE '^[[:space:]]*#' "$equiv" 2>/dev/null | grep -E '(^|[[:space:]])\+([[:space:]]|$)' || true)

        evidence="${evidence}/etc/hosts.equiv (Owner:${equiv_owner}, Perm:${equiv_perm})"

        # 소유자가 root가 아닌 경우
        if [ "$equiv_owner" != "root" ]; then
            status="취약"
            diagnosis_result="VULNERABLE"
            evidence="${evidence} [소유자 불일치]"
        fi

        # 권한이 600 초과인 경우 (600을 넘는 비트가 있으면 취약)
        if ! [[ "$equiv_perm" =~ ^[0-7]{3,4}$ ]] || [ "$(( 8#$equiv_perm & ~8#600 & 07777 ))" -ne 0 ] 2>/dev/null; then
            status="취약"
            diagnosis_result="VULNERABLE"
            evidence="${evidence} [권한 초과]"
        fi

        # '+' 설정이 있는 경우
        if [ -n "$equiv_has_plus" ]; then
            status="취약"
            diagnosis_result="VULNERABLE"
            evidence="${evidence} [+] 설정 존재"
        fi

        evidence="${evidence}. "
    fi

    # ==========================================================================
    # 2. 모든 사용자의 $HOME/.rhosts 확인
    # ==========================================================================
    while IFS=: read -r username _ uid _ _ homedir shell; do
        # 시스템 계정 (UID < 1000, root 제외) 및 로그인 불가 쉘은 건너뜀
        [ "$uid" -ne 0 ] 2>/dev/null && [ "$uid" -lt 1000 ] 2>/dev/null && continue
        [ -z "$homedir" ] || [ "$homedir" = "/" ] && continue

        local rhosts_file="${homedir}/.rhosts"
        if [ -f "$rhosts_file" ]; then
            local rhosts_owner=$(stat -c "%U" "$rhosts_file" 2>/dev/null || echo "unknown")
            local rhosts_perm=$(stat -c "%a" "$rhosts_file" 2>/dev/null || echo "000")
            local rhosts_has_plus=$(grep -vE '^[[:space:]]*#' "$rhosts_file" 2>/dev/null | grep -E '(^|[[:space:]])\+([[:space:]]|$)' || true)

            evidence="${evidence}${rhosts_file} (Owner:${rhosts_owner}, Perm:${rhosts_perm})"

            # 소유자가 해당 계정 또는 root가 아닌 경우
            if [ "$rhosts_owner" != "root" ] && [ "$rhosts_owner" != "$username" ]; then
                status="취약"
                diagnosis_result="VULNERABLE"
                evidence="${evidence} [소유자 불일치]"
            fi

            # 권한이 600 초과인 경우 (600을 넘는 비트가 있으면 취약)
            if ! [[ "$rhosts_perm" =~ ^[0-7]{3,4}$ ]] || [ "$(( 8#$rhosts_perm & ~8#600 & 07777 ))" -ne 0 ] 2>/dev/null; then
                status="취약"
                diagnosis_result="VULNERABLE"
                evidence="${evidence} [권한 초과]"
            fi

            # '+' 설정이 있는 경우
            if [ -n "$rhosts_has_plus" ]; then
                status="취약"
                diagnosis_result="VULNERABLE"
                evidence="${evidence} [+] 설정 존재"
            fi

            evidence="${evidence}. "
        fi
    done < /etc/passwd

    # ==========================================================================
    # 3. 판정
    # ==========================================================================
    if [ "$diagnosis_result" = "GOOD" ]; then
        inspection_summary="hosts.equiv 및 .rhosts 파일 설정이 적절합니다."
    else
        inspection_summary="hosts.equiv 또는 .rhosts 파일에 보안 설정 문제가 있습니다."
    fi

    command_result="${evidence:-검사 대상 파일 없음}"
    command_result=$(echo "$command_result" | tr -d '\n\r')

    save_dual_result \
        "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" \
        "${inspection_summary}" "${command_result}" "${command_executed}" \
        "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" \
        "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"

    verify_result_saved "${ITEM_ID}"
    return 0
}

main() {
    show_diagnosis_start "${ITEM_ID}" "${ITEM_NAME}"
    [ "$EUID" -ne 0 ] && { echo "root 권한이 필요합니다."; exit 1; }
    diagnose
    show_diagnosis_complete "${ITEM_ID}" "${diagnosis_result}"
    exit 0
}

main "$@"
