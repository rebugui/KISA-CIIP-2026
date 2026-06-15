#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : U-46
# @Category    : Unix Server
# @Platform    : AIX
# @Severity    : 상
# @Title       : 일반 사용자의 메일 서비스 실행 방지
# @Description : mail 실행 제한 확인
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


ITEM_ID="U-46"
ITEM_NAME="일반 사용자의 메일 서비스 실행 방지"
SEVERITY="상"

# 가이드라인 정보
GUIDELINE_PURPOSE="일반 사용자의 q 옵션을 제한하여 메일 서비스 설정 및 메일 큐를 강제적으로 drop시킬 수 없게하여 비인가자에 의한 SMTP 서비스 오류 방지하기 위함"
GUIDELINE_THREAT="일반 사용자가 q 옵션을 이용해서 메일 큐, 메일 서비스 설정을 보거나 메일 큐를 강제적으로 drop시킬 수 있어 악의적으로 SMTP 서버의 오류를 발생시킬 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="일반 사용자의 메일 서비스 실행 방지가 설정된 경우"
GUIDELINE_CRITERIA_BAD="일반 사용자의 메일 서비스 실행 방지가 설정되어 있지 않은 경우"
GUIDELINE_REMEDIATION="메일 서비스를 사용하지 않는 경우 서비스 중지 및 비활성화 설정 메일 서비스 사용 시 메일 서비스의 q 옵션 제한 설정"

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

    # 일반 사용자의 메일 서비스 실행 방지 확인
    local mail_restricted=false
    local restriction_info=""

    # 1) Sendmail: smrsh 확인
    if [ -f /etc/mail/smrsh ]; then
        restriction_info="${restriction_info}Sendmail smrsh 설치됨\\n"
        if command -v smrsh &>/dev/null; then
            mail_restricted=true
            restriction_info="${restriction_info}smrsh: 사용 가능한 명령어 제한됨\\n"
        fi
    fi

    # Sendmail 설정에서 restrict-mailrun 확인
    if [ -f /etc/mail/sendmail.cf ] || [ -f /etc/sendmail.cf ]; then
        local conf_file="/etc/mail/sendmail.cf"
        [ ! -f "$conf_file" ] && conf_file="/etc/sendmail.cf"

        local privacy_options=$(grep -i "PrivacyOptions" "$conf_file" | grep -v "^#" | head -1)
        restriction_info="${restriction_info}Sendmail PrivacyOptions: ${privacy_options}\\n"

        if echo "$privacy_options" | grep -q "restrict-mailrun"; then
            mail_restricted=true
            restriction_info="${restriction_info}restrict-mailrun 설정됨\\n"
        fi
    fi

    # 2) Postfix: 제출 제한 확인
    if command -v postconf &>/dev/null; then
        # mail_owner는 Postfix 데몬의 표준 소유자(기본값 postfix)일 뿐
        # 일반 사용자의 메일 큐/제출 제한 여부를 증명하지 못하므로 참고 정보로만 표시
        local mail_owner=$(postconf mail_owner 2>/dev/null | grep "mail_owner" | awk '{print $3}')
        restriction_info="${restriction_info}Postfix mail_owner: ${mail_owner} (데몬 소유자 - 제한 근거 아님)\\n"

        # authorized_mail_users 확인
        local auth_users=$(postconf authorized_mail_users 2>/dev/null | grep "authorized_mail_users" | awk '{print $3}')
        if [ -n "$auth_users" ]; then
            restriction_info="${restriction_info}authorized_mail_users: ${auth_users}\\n"
        fi

        # authorized_submit_users 확인
        # 기본값은 비어있음(= 모든 사용자 제출 허용)이며, static:anyone/static:all/all 도 전체 허용을 의미함.
        # 위 전체 허용 값이 아닌 실제 제한 값이 설정된 경우에만 제출 제한으로 인정함.
        local submit_users=$(postconf authorized_submit_users 2>/dev/null | grep "authorized_submit_users" | awk '{print $3}')
        if [ -n "$submit_users" ]; then
            restriction_info="${restriction_info}authorized_submit_users: ${submit_users}\\n"
            case "$submit_users" in
                static:anyone|static:all|all)
                    restriction_info="${restriction_info}authorized_submit_users가 전체 허용(${submit_users}) - 제출 제한 아님\\n"
                    ;;
                *)
                    mail_restricted=true
                    restriction_info="${restriction_info}authorized_submit_users로 제출 사용자 제한됨\\n"
                    ;;
            esac
        fi
    fi

    # 3) 메일 큐 디렉토리 권한 확인 (AIX: stat -c 미지원, perl 사용)
    local mailq_dirs=("/var/spool/mqueue" "/var/spool/postfix" "/var/mail")
    for dir in "${mailq_dirs[@]}"; do
        if [ -d "$dir" ]; then
            local perms=$(perl -le 'printf "%04o\n", (stat shift)[2] & 07777' "$dir" 2>/dev/null || echo "000")
            local owner=$(perl -le 'print +(getpwuid((stat shift)[4]))[0]' "$dir" 2>/dev/null || echo "unknown")
            restriction_info="${restriction_info}${dir}: ${perms}, ${owner}\\n"
        fi
    done || true

    # 최종 판정
    if [ "$mail_restricted" = true ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="일반 사용자의 메일 서비스 실행 제한됨"
        command_result="${restriction_info}"
        command_executed="postconf mail_owner authorized_submit_users; grep -i 'PrivacyOptions' /etc/mail/sendmail.cf 2>/dev/null"
    else
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="메일 서비스 접근 제한 설정 수동 확인 필요"
        command_result="${restriction_info}"
        command_executed="postconf mail_owner; grep -i 'PrivacyOptions' /etc/mail/sendmail.cf"
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
