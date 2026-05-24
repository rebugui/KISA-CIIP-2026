#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-04-20
# ============================================================================
# [점검 항목 상세]
# @ID          : U-55
# @Category    : UNIX > 4. 웹 서비스 관리
# @Platform    : RedHat
# @Severity    : 중
# @Title       : FTP 계정 shell 제한
# @Description : FTP 계정에 부여된 쉘이 시스템 접근을 차단하는 쉘인지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/metadata_parser.sh"

ITEM_ID="U-55"
ITEM_NAME="FTP 계정 shell 제한"
SEVERITY="중"

# 가이드라인 정보
GUIDELINE_PURPOSE="FTP 계정의 쉘을 통한 시스템 접근을 차단하기 위함"
GUIDELINE_THREAT="FTP 기본 계정에 쉘이 부여될 경우, 비인가자가 해당 기본 계정으로 시스템에 접근할 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="FTP 계정에 /bin/false(/sbin/nologin)쉘이 부여된 경우"
GUIDELINE_CRITERIA_BAD="FTP 계정에 /bin/false(/sbin/nologin)쉘이 부여되어 있지 않은 경우"
GUIDELINE_REMEDIATION="FTP 서비스를 사용하지 않는 경우 서비스 중지 및 비활성화 설정 FTP 서비스 사용 시 FTP 계정에 /bin/false 쉘부여 설정"

diagnose() {
    local status="양호"
    diagnosis_result="GOOD"
    local inspection_summary="FTP 계정에 제한 쉘이 부여되어 있거나 FTP 계정이 존재하지 않습니다."
    local command_result=""
    local command_executed="grep -iE '(ftp|anonymous)' /etc/passwd"

    local restricted_shells="/bin/false /sbin/nologin /usr/sbin/nologin"
    local ftp_accounts=""
    local vulnerable_accounts=""

    # 1. /etc/passwd에서 FTP 관련 계정 추출
    if [ -f "/etc/passwd" ]; then
        while IFS=: read -r user _ uid _ _ home shell; do
            # FTP 관련 계정 확인 (ftp, anonymous 등)
            if echo "$user" | grep -qiE '^(ftp|anonymous)'; then
                ftp_accounts+="${user}:${shell}, "

                # 쉘이 제한 쉘인지 확인
                local is_restricted=false
                for rshell in $restricted_shells; do
                    if [ "$shell" = "$rshell" ]; then
                        is_restricted=true
                        break
                    fi
                done

                if [ "$is_restricted" = false ]; then
                    vulnerable_accounts+="${user}(쉘: ${shell}), "
                fi
            fi
        done < /etc/passwd
    fi

    # 2. 판정 로직
    if [ -z "$ftp_accounts" ]; then
        # FTP 계정이 아예 없는 경우
        command_result="FTP 관련 계정이 존재하지 않습니다."
    elif [ -n "$vulnerable_accounts" ]; then
        # 제한 쉘이 아닌 FTP 계정이 존재하는 경우
        status="취약"
        diagnosis_result="VULNERABLE"
        inspection_summary="FTP 계정에 실제 쉘이 부여되어 있습니다."
        command_result="실제 쉘 부여 계정: [ ${vulnerable_accounts} ]"
    else
        command_result="모든 FTP 계정에 제한 쉘이 부여되어 있습니다. [ ${ftp_accounts} ]"
    fi

    # [보정] JSON 파싱 에러 방지
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
