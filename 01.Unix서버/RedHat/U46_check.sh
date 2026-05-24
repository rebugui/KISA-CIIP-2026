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
# @Platform    : SOLARIS, LINUX, AIX, HP-UX 등
# @Severity    : (상)
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
    local command_executed="grep -i 'PrivacyOptions' /etc/mail/sendmail.cf"

    # 1. 실제 데이터 추출 (Sendmail 기준)
    local cf_file="/etc/mail/sendmail.cf"
    if [ -f "$cf_file" ]; then
        local privacy_opts=$(grep -i "O PrivacyOptions" "$cf_file" | cut -d= -f2 || echo "")
        
        # 2. 판정 로직 (restrictmailq, restrictqrun 포함 여부 확인)
        if [[ ! "$privacy_opts" =~ "restrictmailq" ]] || [[ ! "$privacy_opts" =~ "restrictqrun" ]]; then
            status="취약"
            diagnosis_result="VULNERABLE"
            inspection_summary="PrivacyOptions 설정에 일반 사용자 제한 옵션이 누락되어 있습니다."
        fi
        command_result="설정된 PrivacyOptions: [ ${privacy_opts:-설정 없음} ]"
    else
        command_result="Sendmail 설정 파일이 존재하지 않습니다."
    fi

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
