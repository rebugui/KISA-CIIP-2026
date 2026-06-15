#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : U-47
# @Category    : Unix Server
# @Platform    : Solaris
# @Severity    : 상
# @Title       : 스팸메일 릴레이 제한
# @Description : 메일 릴레이 제한 설정 확인
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


ITEM_ID="U-47"
ITEM_NAME="스팸메일 릴레이 제한"
SEVERITY="상"

# 가이드라인 정보
GUIDELINE_PURPOSE="스팸메일 서버로의 악용 방지 및 서버 과부하를 방지하기 위함"
GUIDELINE_THREAT="SMTP 서버의 릴레이 기능을 제한하지 않을 경우, 악의적인 사용 목적을 가진 사용자들이 스팸 메일 서버로 사용하거나 DoS 공격의 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="릴레이 제한이 설정된 경우"
GUIDELINE_CRITERIA_BAD="릴레이 제한이 설정되어 있지 않은 경우"
GUIDELINE_REMEDIATION="메일 서비스를 사용하지 않는 경우 서비스 중지 및 비활성화 설정 메일 서비스 사용 시 릴레이 방지 설정 또는 릴레이 대상 접근 제어 설정"

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

    # 스팸 메일 릴레이 제한 확인
    local relay_restricted=false
    local relay_vulnerable=false
    local relay_manual=false
    local relay_info=""

    # 0) 메일서비스(MTA) 사용 여부 확인 (sendmail 설정 / postfix / SMTP 데몬)
    local sendmail_conf=""
    if [ -f /etc/mail/sendmail.cf ]; then
        sendmail_conf="/etc/mail/sendmail.cf"
    elif [ -f /etc/sendmail.cf ]; then
        sendmail_conf="/etc/sendmail.cf"
    fi

    local postfix_present=false
    if command -v postconf >/dev/null 2>&1 || [ -f /etc/postfix/main.cf ]; then
        postfix_present=true
    fi

    local smtp_daemon=""
    smtp_daemon=$(ps -ef 2>/dev/null | grep -E '[s]endmail|[p]ostfix/master|[e]xim|[s]mtpd' || true)

    if [ -z "$sendmail_conf" ] && [ "$postfix_present" = false ] && [ -z "$smtp_daemon" ]; then
        # 가이드 참고: "메일서비스를 사용하지 않는 경우 양호 또는 N/A"
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="메일서비스 미사용 (sendmail/postfix 설정 및 SMTP 데몬 없음)"
        command_result="sendmail.cf: 없음${newline}postconf/main.cf: 없음${newline}SMTP 데몬: 미실행"
        command_executed="ls /etc/mail/sendmail.cf /etc/sendmail.cf /etc/postfix/main.cf; command -v postconf; ps -ef"
    else
        # 1) Sendmail 릴레이 제한 확인
        if [ -n "$sendmail_conf" ]; then
            relay_info="${relay_info}[Sendmail: ${sendmail_conf}]${newline}"

            # 릴레이 전면 허용(FEATURE promiscuous_relay) 여부 확인 - 조치방법: 해당 설정 제거
            local promiscuous=""
            promiscuous=$(grep -h "promiscuous_relay" "$sendmail_conf" /etc/mail/sendmail.mc 2>/dev/null | grep -v "^[[:space:]]*#" || true)

            # 릴레이 거부 룰 확인 - 조치방법: cat sendmail.cf | grep 'R$*' | grep 'Relaying denied'
            local relay_denied=""
            relay_denied=$(grep 'R\$\*' "$sendmail_conf" 2>/dev/null | grep -i 'Relaying denied' | grep -v "^[[:space:]]*#" || true)

            if [ -n "$promiscuous" ]; then
                relay_vulnerable=true
                relay_info="${relay_info}promiscuous_relay 설정 발견(릴레이 전면 허용): ${promiscuous}${newline}"
            elif [ -n "$relay_denied" ]; then
                relay_restricted=true
                relay_info="${relay_info}릴레이 거부 룰(R\$* ... Relaying denied) 확인됨: ${relay_denied}${newline}"
            else
                # 릴레이 제한 여부를 설정 파일에서 판별할 수 없으면 수동진단 (양호 아님)
                relay_manual=true
                relay_info="${relay_info}sendmail.cf에서 릴레이 제한 설정을 자동 판별할 수 없음 - 수동 확인 필요${newline}"
            fi

            # access DB는 증적으로만 기록 (파일 존재 자체는 릴레이 제한의 근거가 아님)
            if [ -f /etc/mail/access.db ] || [ -f /etc/mail/access ]; then
                relay_info="${relay_info}/etc/mail/access(.db) 존재 (참고 증적)${newline}"
            fi
        fi

        # 2) Postfix 릴레이 제한 확인
        if [ "$postfix_present" = true ]; then
            local relay_restrictions=""
            local recipient_restrictions=""
            local mynetworks=""
            local mynetworks_open=false

            if command -v postconf >/dev/null 2>&1; then
                relay_restrictions=$(postconf -h smtpd_relay_restrictions 2>/dev/null || true)
                recipient_restrictions=$(postconf -h smtpd_recipient_restrictions 2>/dev/null || true)
                mynetworks=$(postconf -h mynetworks 2>/dev/null || true)
                # 유효값 기준: mynetworks가 비어 있으면 신뢰 범위를 판별할 수 없어 취약 처리
                if [ -z "$mynetworks" ]; then
                    mynetworks_open=true
                fi
            elif [ -f /etc/postfix/main.cf ]; then
                relay_restrictions=$(grep -E '^[[:space:]]*smtpd_relay_restrictions[[:space:]]*=' /etc/postfix/main.cf 2>/dev/null | tail -1 | cut -d= -f2- || true)
                recipient_restrictions=$(grep -E '^[[:space:]]*smtpd_recipient_restrictions[[:space:]]*=' /etc/postfix/main.cf 2>/dev/null | tail -1 | cut -d= -f2- || true)
                mynetworks=$(grep -E '^[[:space:]]*mynetworks[[:space:]]*=' /etc/postfix/main.cf 2>/dev/null | tail -1 | cut -d= -f2- || true)
            fi

            if echo "$mynetworks" | grep -q "0\.0\.0\.0/0"; then
                mynetworks_open=true
            fi

            relay_info="${relay_info}[Postfix]${newline}smtpd_relay_restrictions: ${relay_restrictions}${newline}smtpd_recipient_restrictions: ${recipient_restrictions}${newline}mynetworks: ${mynetworks}${newline}"

            if [ "$mynetworks_open" = true ]; then
                # mynetworks 전체 허용(0.0.0.0/0)이면 permit_mynetworks가 open relay가 됨 - 판단기준 "취약: 릴레이 제한이 설정되어 있지 않은 경우"
                relay_vulnerable=true
                relay_info="${relay_info}mynetworks 무제한(0.0.0.0/0 또는 빈 값) - 전체 네트워크 릴레이 허용${newline}"
            elif echo "${relay_restrictions} ${recipient_restrictions}" | grep -Eq "reject_unauth_destination|defer_unauth_destination"; then
                # 판단기준 "양호: 릴레이 제한이 설정된 경우" - 유효 릴레이 정책에 비인가 목적지 거부가 존재하고 mynetworks가 제한됨
                relay_restricted=true
                relay_info="${relay_info}reject/defer_unauth_destination 적용 + mynetworks 제한 - 비인가 릴레이 차단됨${newline}"
            else
                # 판단기준 "취약: 릴레이 제한이 설정되어 있지 않은 경우" - 비인가 목적지 릴레이 거부 설정 부재
                relay_vulnerable=true
                relay_info="${relay_info}비인가 목적지 릴레이 거부(reject/defer_unauth_destination) 설정 없음${newline}"
            fi
        fi

        # 3) 설정 파일 없이 SMTP 데몬만 탐지된 경우 수동진단
        if [ -z "$sendmail_conf" ] && [ "$postfix_present" = false ]; then
            relay_manual=true
            relay_info="${relay_info}[SMTP 데몬]${newline}${smtp_daemon}${newline}설정 파일을 찾지 못해 릴레이 제한 여부 수동 확인 필요${newline}"
        fi

        command_executed="grep promiscuous_relay /etc/mail/sendmail.cf /etc/mail/sendmail.mc; grep 'R\$*' sendmail.cf | grep 'Relaying denied'; postconf -h smtpd_relay_restrictions smtpd_recipient_restrictions mynetworks"

        # 최종 판정 (판단기준 - 양호: 릴레이 제한이 설정된 경우 / 취약: 릴레이 제한이 설정되어 있지 않은 경우)
        if [ "$relay_vulnerable" = true ]; then
            diagnosis_result="VULNERABLE"
            status="취약"
            inspection_summary="메일 릴레이 제한이 설정되어 있지 않음 - open relay 가능성"
            command_result="${relay_info}"
        elif [ "$relay_manual" = true ]; then
            diagnosis_result="MANUAL"
            status="수동진단"
            inspection_summary="메일서비스 사용 중이나 릴레이 제한 설정을 자동 판별할 수 없어 수동 진단 필요"
            command_result="${relay_info}"
        else
            diagnosis_result="GOOD"
            status="양호"
            inspection_summary="메일 릴레이 제한 설정됨"
            command_result="${relay_info}"
        fi
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
