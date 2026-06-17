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
    # KISA 판단기준: 일반 사용자의 q 옵션(메일 큐 강제 실행/drop) 제한 여부
    #  - Sendmail : /etc/mail/sendmail.cf 의 PrivacyOptions 에 restrictqrun 설정 시 양호
    #  - Postfix  : /usr/sbin/postsuper 에 일반 사용자(others) 실행 권한이 없으면 양호
    #               (조치: chmod o-x /usr/sbin/postsuper)
    local mail_service_present=false
    local mail_vulnerable=false
    local restriction_info=""

    # 1) Sendmail: PrivacyOptions 의 restrictqrun 확인
    local sm_conf=""
    [ -f /etc/mail/sendmail.cf ] && sm_conf="/etc/mail/sendmail.cf"
    [ -z "$sm_conf" ] && [ -f /etc/sendmail.cf ] && sm_conf="/etc/sendmail.cf"
    if [ -n "$sm_conf" ]; then
        mail_service_present=true
        local privacy_options
        privacy_options=$(grep -i "PrivacyOptions" "$sm_conf" 2>/dev/null | grep -v "^#" | head -1 || true)
        restriction_info="${restriction_info}[Sendmail] ${sm_conf} PrivacyOptions: ${privacy_options}\\n"
        command_executed="${command_executed}grep -i 'PrivacyOptions' ${sm_conf}; "
        # restrictqrun 이 설정되어 있고 norestrictqrun 으로 무력화되지 않은 경우만 양호
        if echo "$privacy_options" | grep -qiw "restrictqrun" && ! echo "$privacy_options" | grep -qiw "norestrictqrun"; then
            restriction_info="${restriction_info}[Sendmail] restrictqrun 설정됨 -> 제한\\n"
        else
            mail_vulnerable=true
            restriction_info="${restriction_info}[Sendmail] restrictqrun 미설정 -> 일반 사용자 q 옵션 허용\\n"
        fi
    fi

    # 2) Postfix: /usr/sbin/postsuper 의 일반 사용자 실행 권한 확인
    local ps_bin=""
    for cand in /usr/sbin/postsuper /usr/lib/postfix/sbin/postsuper; do
        [ -f "$cand" ] && ps_bin="$cand" && break
    done
    if [ -n "$ps_bin" ]; then
        mail_service_present=true
        # stat -c 미지원 AIX: perl 사용
        local ps_perms
        ps_perms=$(perl -le 'printf "%04o\n", (stat shift)[2] & 07777' "$ps_bin" 2>/dev/null || echo "000")
        restriction_info="${restriction_info}[Postfix] ${ps_bin} 권한: ${ps_perms}\\n"
        command_executed="${command_executed}ls -l ${ps_bin}; "
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
    if [ "$mail_service_present" != true ]; then
        # SMTP(메일) 서비스가 설치되어 있지 않으면 점검 대상 아님
        diagnosis_result="N/A"
        status="N/A"
        inspection_summary="메일(SMTP) 서비스가 설치되어 있지 않아 점검 대상이 아님"
        command_result="Sendmail/Postfix 메일 서비스 미설치"
        command_executed="ls -l /usr/sbin/postsuper; grep -i 'PrivacyOptions' /etc/mail/sendmail.cf"
    elif [ "$mail_vulnerable" = true ]; then
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="일반 사용자의 메일 서비스 실행 방지가 설정되어 있지 않음"
        command_result="${restriction_info}"
    else
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="일반 사용자의 메일 서비스 실행 방지가 설정됨"
        command_result="${restriction_info}"
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
