#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : U-55
# @Category    : Unix Server
# @Platform    : AIX
# @Severity    : 중
# @Title       : FTP 계정 shell 제한
# @Description : FTP 계정의 Shell 제한 설정 여부 확인
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


ITEM_ID="U-55"
ITEM_NAME="FTP 계정 shell 제한"
SEVERITY="중"

# 가이드라인 정보
GUIDELINE_PURPOSE="FTP 계정의 쉘을 통한 시스템 접근을 차단하기 위함"
GUIDELINE_THREAT="FTP 기본 계정에 쉘이 부여될 경우, 비인가자가 해당 기본 계정으로 시스템에 접근할 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="FTP 계정에 /bin/false(/sbin/nologin)쉘이 부여된 경우"
GUIDELINE_CRITERIA_BAD="FTP 계정에 /bin/false(/sbin/nologin)쉘이 부여되어 있지 않은 경우"
GUIDELINE_REMEDIATION="FTP 서비스를 사용하지 않는 경우 서비스 중지 및 비활성화 설정 FTP 서비스 사용 시 FTP 계정에 /bin/false 쉘부여 설정"

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
    # FTP 계정의 Shell 제한 설정 확인

    local ftp_users=()
    local vulnerable_users=()
    local secure_users=()
    local all_users_info=""

    # /etc/passwd에서 FTP 관련 사용자 찾기
    # 일반적인 FTP 사용자: ftp, anonymous, ftpuser
    while IFS=: read -r username x uid x gecos home shell; do
        # FTP 관련 사용자 확인 (사용자명에 ftp 포함 또는 UID가 FTP 전용)
        if [[ "$username" =~ [Ff][Tt][Pp] ]] || [[ "$username" =~ [Aa]nonymous ]]; then
            ftp_users+=("$username:$shell")

            # Shell 검사: /bin/false, /usr/sbin/nologin, /sbin/nologin은 안전함
            if [ "$shell" = "/bin/false" ] || [ "$shell" = "/usr/sbin/nologin" ] || [ "$shell" = "/sbin/nologin" ]; then
                secure_users+=("$username:${shell}")
            else
                # /bin/bash, /bin/sh 등 일반 Shell을 사용하는 경우 취약
                vulnerable_users+=("$username:${shell}")
            fi

            all_users_info="${all_users_info}${username}: ${shell}, HOME: ${home}\\n"
        fi
    done < /etc/passwd || true

    command_executed="grep -E 'ftp|anonymous' /etc/passwd"

    # 최종 판정
    if [ ${#ftp_users[@]} -eq 0 ]; then
        diagnosis_result="N/A"
        status="N/A"
        inspection_summary="FTP 계정이 존재하지 않습니다."
        command_result="FTP related users not found in /etc/passwd"
    elif [ ${#vulnerable_users[@]} -eq 0 ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="모든 FTP 계정의 Shell이 적절하게 제한되어 있습니다. (${#secure_users[@]}개 계정 확인)"
        command_result="${all_users_info}"
    else
        diagnosis_result="VULNERABLE"
        status="취약"
        local vuln_list=""
        for user in "${vulnerable_users[@]}"; do
            vuln_list="${vuln_list}${user}, "
        done || true
        inspection_summary="FTP 계정이 제한되지 않은 Shell을 사용하고 있습니다 (${vuln_list%, }). usermod 명령어로 Shell을 /bin/false로 변경하세요."
        local awk_out=$(awk -F: '$3 >= 200 {print $1, $3, $7}' /etc/passwd 2>/dev/null | head -30)
        command_result="[Command: awk -F: '\$3 >= 200' /etc/passwd]${newline}${awk_out}"
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
