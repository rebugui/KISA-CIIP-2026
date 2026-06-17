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
# @Platform    : Solaris
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
    local mail_vulnerable=false
    local restriction_info=""

    # 1) Sendmail: smrsh 확인
    if [ -f /etc/mail/smrsh ]; then
        restriction_info="${restriction_info}Sendmail smrsh 설치됨\\n"
        if command -v smrsh &>/dev/null; then
            mail_restricted=true
            restriction_info="${restriction_info}smrsh: 사용 가능한 명령어 제한됨\\n"
        fi
    fi

    # Sendmail 설정에서 restrictqrun 확인
    if [ -f /etc/mail/sendmail.cf ] || [ -f /etc/sendmail.cf ]; then
        mail_restricted=true
        local conf_file="/etc/mail/sendmail.cf"
        [ ! -f "$conf_file" ] && conf_file="/etc/sendmail.cf"

        local privacy_options=$(grep -i "PrivacyOptions" "$conf_file" | grep -v "^#" | head -1)
        restriction_info="${restriction_info}Sendmail PrivacyOptions: ${privacy_options}\\n"

        if echo "$privacy_options" | grep -q "restrictqrun"; then
            restriction_info="${restriction_info}restrictqrun 설정됨\\n"
        else
            mail_vulnerable=true
            restriction_info="${restriction_info}restrictqrun 미설정 - 일반 사용자 q 옵션 허용됨\\n"
        fi
    fi

    # 2) Postfix: /usr/sbin/postsuper 일반 사용자 실행 권한 확인
    local ps_bin=""
    for cand in /usr/sbin/postsuper /usr/lib/postfix/sbin/postsuper; do
        [ -f "$cand" ] && ps_bin="$cand" && break
    done
    if [ -n "$ps_bin" ]; then
        mail_restricted=true
        local ps_perms
        # Solaris: perl을 사용하여 권한 확인
        ps_perms=$(perl -e 'printf "%04o", (stat shift)[2] & 07777' "$ps_bin" 2>/dev/null || echo "0000")
        restriction_info="${restriction_info}[Postfix] ${ps_bin} 권한: ${ps_perms}\\n"
        # others(기타 사용자) 실행 비트(1) 여부 판단
        local other_digit="${ps_perms: -1}"
        case "$other_digit" in
            1|3|5|7)
                mail_vulnerable=true
                restriction_info="${restriction_info}[Postfix] 일반 사용자 실행 권한 존재 -> 취약\\n"
                ;;
            *)
                restriction_info="${restriction_info}[Postfix] 일반 사용자 실행 권한 제거됨 -> 제한\\n"
                ;;
        esac
    fi

    # 3) 메일 큐 디렉토리 권한 확인
    local mailq_dirs=("/var/spool/mqueue" "/var/spool/postfix" "/var/mail")
    for dir in "${mailq_dirs[@]}"; do
        if [ -d "$dir" ]; then
            # Solaris: perl을 사용하여 권한 및 소유자 확인
            local perms=$(perl -e 'printf "%04o", (stat shift)[2] & 0777' "$dir" 2>/dev/null || echo "000")
            local owner=$(perl -e 'print (stat shift)[4]' "$dir" 2>/dev/null || echo "unknown")
            # UID를 사용자 이름으로 변환
            if [ "$owner" != "unknown" ] && [ -n "$owner" ]; then
                local owner_name=$(getent passwd "$owner" 2>/dev/null | cut -d: -f1 || echo "$owner")
                restriction_info="${restriction_info}${dir}: ${perms}, ${owner_name}\\n"
            else
                restriction_info="${restriction_info}${dir}: ${perms}, unknown\\n"
            fi
        fi
    done || true

    # 최종 판정
    if [ "$mail_restricted" != true ]; then
        # SMTP(메일) 서비스가 설치되어 있지 않으면 점검 대상 아님
        diagnosis_result="N/A"
        status="N/A"
        inspection_summary="메일(SMTP) 서비스가 설치되어 있지 않아 점검 대상이 아님"
        command_result="Sendmail/Postfix 메일 서비스 미설치"
        command_executed="ls -l /usr/sbin/postsuper 2>/dev/null; grep -i 'PrivacyOptions' /etc/mail/sendmail.cf 2>/dev/null"
    elif [ "$mail_vulnerable" = true ]; then
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="일반 사용자의 메일 서비스 실행 방지가 설정되어 있지 않음"
        command_result="${restriction_info}"
        command_executed="ls -l /usr/sbin/postsuper 2>/dev/null; grep -i 'PrivacyOptions' /etc/mail/sendmail.cf 2>/dev/null"
    else
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="일반 사용자의 메일 서비스 실행 제한됨"
        command_result="${restriction_info}"
        command_executed="ls -l /usr/sbin/postsuper 2>/dev/null; grep -i 'PrivacyOptions' /etc/mail/sendmail.cf 2>/dev/null"
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
