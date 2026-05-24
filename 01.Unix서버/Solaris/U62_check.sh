#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : U-62
# @Category    : Unix Server
# @Platform    : Solaris
# @Severity    : 하
# @Title       : 로그인 시 경고 메시지 설정
# @Description : /etc/issue, /etc/issue.net 설정 확인
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


ITEM_ID="U-62"
ITEM_NAME="로그인 시 경고 메시지 설정"
SEVERITY="하"

# 가이드라인 정보
GUIDELINE_PURPOSE="비인가자들에게 서버에 대한 불필요한 정보를 제공하지 않고, 서버 접속 시 관계자만 접속해야한다는 경각심을 심어 주기 위함"
GUIDELINE_THREAT="로그온 시 경고 메시지가 설정되어 있지 않을 경우, 기본 설정 값엔 서버 OS 버전 및 서비스 버전이 비인가자에게 노출되어 해당 정보를 통해 서비스의 취약점을 이용하여 공격을 시도할 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="서버 및 Telnet,FTP,SMTP,DNS 서비스에 로그온 시 경고 메시지가 설정된 경우"
GUIDELINE_CRITERIA_BAD="서버 및 Telnet,FTP,SMTP,DNS 서비스에 로그 온 시 경고 메시지가 설정되어 있지 않은 경우"
GUIDELINE_REMEDIATION="Telnet,FTP,SMTP,DNS 서비스를 사용하는 경우 설정 파일을 통해 로그온 시 경고 메시지 설정"

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
    # 로그인 시 경고 메시지 설정 확인

    local issue_file=""
    local issue_net_file=""
    local has_warning=false
    local warning_details=""
    local raw_output=""

    # 1) /etc/issue 파일 확인 (로컬 로그인 시 경고 메시지)
    if [ -f /etc/issue ]; then
        local issue_content=$(cat /etc/issue 2>/dev/null)
        if [ -n "$issue_content" ]; then
            # 경고 메시지 키워드 확인
            if echo "$issue_content" | grep -qiE "warning|unauthorized|access|prohibited|경고|무단|접속금지"; then
                has_warning=true
                issue_file="존재함 (경고 메시지 포함)"
            else
                issue_file="존재함 (경고 메시지 없음)"
            fi
        else
            issue_file="비어있음"
        fi
    else
        issue_file="없음"
    fi

    # 2) /etc/issue.net 파일 확인 (원격 SSH 로그인 시 경고 메시지)
    if [ -f /etc/issue.net ]; then
        local issue_net_content=$(cat /etc/issue.net 2>/dev/null)
        if [ -n "$issue_net_content" ]; then
            # 경고 메시지 키워드 확인
            if echo "$issue_net_content" | grep -qiE "warning|unauthorized|access|prohibited|경고|무단|접속금지"; then
                has_warning=true
                issue_net_file="존재함 (경고 메시지 포함)"
            else
                issue_net_file="존재함 (경고 메시지 없음)"
            fi
        else
            issue_net_file="비어있음"
        fi
    else
        issue_net_file="없음"
    fi

    # 3) SSH Banner 설정 확인 (SSH를 통한 로그인 시)
    local ssh_banner=""
    if [ -f /etc/ssh/sshd_config ]; then
        ssh_banner=$(grep -E "^[\s]*Banner" /etc/ssh/sshd_config 2>/dev/null | grep -v "^#" | awk '{print $2}')
        if [ -n "$ssh_banner" ]; then
            if [ -f "$ssh_banner" ]; then
                has_warning=true
                ssh_banner="설정됨 (${ssh_banner})"
            else
                ssh_banner="설정됨 (파일 없음: ${ssh_banner})"
            fi
        else
            ssh_banner="설정 안됨"
        fi
    fi

    # Capture raw command output
    raw_output=$(echo "=== /etc/issue ===" && cat /etc/issue 2>/dev/null && echo -e "\n=== /etc/issue.net ===" && cat /etc/issue.net 2>/dev/null && echo -e "\n=== SSH Banner ===" && grep -E "^[\s]*Banner" /etc/ssh/sshd_config 2>/dev/null | grep -v "^#" || echo "No banner configured")

    # 최종 판정
    if [ "$has_warning" = true ]; then
        diagnosis_result="GOOD"
        status="양호"
        warning_details="/etc/issue: ${issue_file}, /etc/issue.net: ${issue_net_file}"
        [ -n "$ssh_banner" ] && warning_details="${warning_details}, SSH Banner: ${ssh_banner}"
        inspection_summary="로그인 경고 메시지가 설정됨: ${warning_details}"
        command_result="${raw_output}"
        command_executed="cat /etc/issue /etc/issue.net 2>/dev/null; grep '^Banner' /etc/ssh/sshd_config 2>/dev/null"
    else
        diagnosis_result="VULNERABLE"
        status="취약"
        warning_details="/etc/issue: ${issue_file}, /etc/issue.net: ${issue_net_file}"
        [ -n "$ssh_banner" ] && warning_details="${warning_details}, SSH Banner: ${ssh_banner}"
        inspection_summary="로그인 경고 메시지가 설정되지 않음: ${warning_details}"
        command_result="${raw_output}"
        command_executed="cat /etc/issue /etc/issue.net 2>/dev/null; grep '^Banner' /etc/ssh/sshd_config 2>/dev/null"
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
