#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-28
# ============================================================================
# [점검 항목 상세]
# @ID          : U-46
# @Category    : UNIX > 3. 서비스 관리
# @Platform    : RedHat
# @Severity    : 상
# @Title       : 일반 사용자의 메일 서비스 실행 방지
# @Description : 일반 사용자가 메일 서비스를 임의로 실행하거나 제어하는 것을 방지하는 설정 점검
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

ITEM_ID="U-46"
ITEM_NAME="일반 사용자의 메일 서비스 실행 방지"
SEVERITY="상"

# 가이드라인 정보
GUIDELINE_PURPOSE="일반 사용자의 q 옵션을 제한하여 메일 서비스 설정 및 메일 큐를 강제적으로 drop시킬 수 없게하여 비인가자에 의한 SMTP 서비스 오류 방지하기 위함"
GUIDELINE_THREAT="일반 사용자가 q 옵션을 이용해서 메일 큐, 메일 서비스 설정을 보거나 메일 큐를 강제적으로 drop시킬 수 있어 악의적으로 SMTP 서버의 오류를 발생시킬 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="일반 사용자의 메일 서비스 실행 방지가 설정된 경우"
GUIDELINE_CRITERIA_BAD="일반 사용자의 메일 서비스 실행 방지가 설정되어 있지 않은 경우"
GUIDELINE_REMEDIATION="메일 서비스를 사용하지 않는 경우 서비스 중지 및 비활성화 설정 메일 서비스 사용 시 메일 서비스의 q 옵션 제한 설정"

diagnose() {
    # [중요] 파싱 에러 방지를 위한 기존 변수 초기값 유지
    local status="양호"
    diagnosis_result="GOOD"
    local inspection_summary="일반 사용자의 메일 서비스 실행 방지 설정이 적절합니다."
    local command_result=""
    local command_executed="grep '^O PrivacyOptions' /etc/mail/sendmail.cf; ls -l /usr/sbin/postsuper; systemctl is-active postfix; ls -l /usr/sbin/exiqgrep"

    local mta_checked=false
    local is_vulnerable=false
    local needs_manual=false
    local findings=""

    # 1. Sendmail 점검 (PrivacyOptions에 restrictqrun 설정 여부, 주석 라인 제외)
    local cf_file="/etc/mail/sendmail.cf"
    if [ -f "$cf_file" ]; then
        mta_checked=true
        local privacy_opts=$(grep -E '^[[:space:]]*O[[:space:]]*PrivacyOptions' "$cf_file" 2>/dev/null | cut -d= -f2- || echo "")
        if echo "$privacy_opts" | grep -q "restrictqrun"; then
            findings="${findings}[Sendmail] PrivacyOptions에 restrictqrun 설정됨: ${privacy_opts} / "
        else
            is_vulnerable=true
            findings="${findings}[Sendmail] PrivacyOptions에 restrictqrun 미설정: ${privacy_opts:-설정 없음} / "
        fi
    fi

    # 2. Postfix 점검 (postsuper 일반 사용자 실행 권한 o-x 여부)
    local postfix_present=false
    local postfix_running=false
    if [ -f /etc/postfix/main.cf ] || command -v postconf >/dev/null 2>&1; then
        postfix_present=true
    fi
    if { command -v systemctl >/dev/null 2>&1 && systemctl is-active postfix >/dev/null 2>&1; } || \
       { command -v pgrep >/dev/null 2>&1 && pgrep -x master >/dev/null 2>&1; }; then
        postfix_running=true
        postfix_present=true
    fi
    if [ "$postfix_present" = true ]; then
        mta_checked=true
        local postsuper_path=""
        if [ -e /usr/sbin/postsuper ]; then
            postsuper_path="/usr/sbin/postsuper"
        else
            postsuper_path=$(command -v postsuper 2>/dev/null || echo "")
        fi
        if [ -n "$postsuper_path" ]; then
            local postsuper_perms=$(stat -c '%a' "$postsuper_path" 2>/dev/null || echo "")
            if [ -n "$postsuper_perms" ]; then
                local other_perm="${postsuper_perms: -1}"
                if [ $(( other_perm & 1 )) -ne 0 ]; then
                    is_vulnerable=true
                    findings="${findings}[Postfix] postsuper(${postsuper_path}) 일반 사용자 실행 권한(o+x) 존재: ${postsuper_perms} / "
                else
                    findings="${findings}[Postfix] postsuper(${postsuper_path}) 일반 사용자 실행 권한 제거됨(o-x): ${postsuper_perms} / "
                fi
            else
                # postfix 운용 중이나 권한 판독 불가 → 기본 GOOD 금지, 수동 점검
                needs_manual=true
                findings="${findings}[Postfix] postsuper 권한 확인 불가(실행 중: ${postfix_running}) — 수동 점검 필요 / "
            fi
        else
            needs_manual=true
            findings="${findings}[Postfix] postfix 사용 중(실행 중: ${postfix_running})이나 postsuper 경로 확인 불가 — 수동 점검 필요 / "
        fi
    fi

    # 3. Exim 점검 (exiqgrep 일반 사용자 실행 권한 o-x 여부)
    local exim_path="/usr/sbin/exiqgrep"
    if [ -f "$exim_path" ]; then
        mta_checked=true
        local exim_perms
        exim_perms=$(stat -c '%a' "$exim_path" 2>/dev/null || echo "")
        if [ -n "$exim_perms" ]; then
            local other_perm="${exim_perms: -1}"
            if [ $(( other_perm & 1 )) -ne 0 ]; then
                is_vulnerable=true
                findings="${findings}[Exim] exiqgrep(${exim_path}) 일반 사용자 실행 권한(o+x) 존재: ${exim_perms} / "
            else
                findings="${findings}[Exim] exiqgrep(${exim_path}) 일반 사용자 실행 권한 제거됨(o-x): ${exim_perms} / "
            fi
        else
            needs_manual=true
            findings="${findings}[Exim] exiqgrep(${exim_path}) 권한 확인 불가 — 수동 점검 필요 / "
        fi
    fi

    # 4. 최종 판정 (취약 > 수동 > 양호 / 메일 서비스 미사용 → 양호)
    if [ "$is_vulnerable" = true ]; then
        status="취약"
        diagnosis_result="VULNERABLE"
        inspection_summary="일반 사용자의 메일 서비스 실행 방지 설정이 미흡합니다."
    elif [ "$needs_manual" = true ]; then
        status="수동진단"
        diagnosis_result="MANUAL"
        inspection_summary="메일 서비스(Postfix) 사용 중이나 일반 사용자 실행 제한 여부를 자동 판정할 수 없어 수동 점검이 필요합니다."
    elif [ "$mta_checked" = true ]; then
        status="양호"
        diagnosis_result="GOOD"
        inspection_summary="일반 사용자의 메일 서비스 실행 방지 설정이 적절합니다."
    else
        status="양호"
        diagnosis_result="GOOD"
        inspection_summary="메일 서비스(Sendmail/Postfix/Exim)가 사용되지 않습니다."
    fi
    command_result="${findings:-메일 서비스 미검출: sendmail.cf 부재, postfix 미설치/미실행}"

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
