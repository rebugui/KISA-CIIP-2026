#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-04-20
# ============================================================================
# [점검 항목 상세]
# @ID          : U-21
# @Category    : UNIX > 2. 파일 및 디렉토리 관리
# @Platform    : RedHat
# @Severity    : 상
# @Title       : /etc/(r)syslog.conf 파일 소유자 및 권한 설정
# @Description : 로그 설정 파일(/etc/syslog.conf 또는 /etc/rsyslog.conf)의 소유자 및 권한 설정 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/metadata_parser.sh"

ITEM_ID="U-21"
ITEM_NAME="/etc/(r)syslog.conf 파일 소유자 및 권한 설정"
SEVERITY="상"

# 가이드라인 정보 (PDF 가이드 내용 반영)
GUIDELINE_PURPOSE="/etc/(r)syslog.conf 파일의 권한 적절성을 점검하여, 비인가자의 임의적인 /etc/(r)syslog.conf 파일 변조를 방지하기 위함"
GUIDELINE_THREAT="/etc/(r)syslog.conf 파일의 설정 내용을 참조하여 로그의 저장 위치가 노출되며 로그를 기록하지 않도록 설정하거나 대량의 로그를 기록하게하여 시스템과 부하를 유도할 수 있는 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="/etc/(r)syslog.conf 파일의 소유자가 root(또는 bin, sys)이고, 권한이 640 이하인 경우"
GUIDELINE_CRITERIA_BAD="/etc/(r)syslog.conf 파일의 소유자가 root(또는 bin, sys)가 아니거나, 권한이 640 이하가 아닌 경우"
GUIDELINE_REMEDIATION="/etc/(r)syslog.conf 파일 소유자 및 권한 변경 설정"

diagnose() {
    local status="양호"
    diagnosis_result="GOOD"
    local inspection_summary="로그 설정 파일의 소유자 및 권한 설정이 적절합니다."
    local command_result=""
    local command_executed="ls -l /etc/syslog.conf /etc/rsyslog.conf"

    # 1. 실제 데이터 추출 (OS에 따라 syslog.conf 또는 rsyslog.conf 사용)
    local target="/etc/rsyslog.conf"
    [ ! -f "$target" ] && target="/etc/syslog.conf"

    if [ -f "$target" ]; then
        local owner=$(stat -c "%U" "$target")
        local perm=$(stat -c "%a" "$target")
        local ls_out=$(ls -l "$target")

        # 2. 판정 로직: 소유자 root/bin/sys 및 권한 640 이하
        if [[ ! "$owner" =~ ^(root|bin|sys)$ ]] || ! [[ "$perm" =~ ^[0-7]{3,4}$ ]] || [ "$(( 8#$perm & ~8#640 & 07777 ))" -ne 0 ]; then
            status="취약"
            diagnosis_result="VULNERABLE"
            inspection_summary="로그 설정 파일의 소유자 또는 권한 설정이 부적절합니다."
        fi
        command_result="설정 현황: [ ${ls_out} ]"
    else
        status="N/A"
        diagnosis_result="N/A"
        inspection_summary="로그 설정 파일(/etc/rsyslog.conf, /etc/syslog.conf)이 존재하지 않습니다 (journald 단독 운용 등 (r)syslog 미사용 환경)."
        command_result="로그 설정 파일(/etc/syslog.conf 또는 rsyslog.conf)이 존재하지 않습니다."
    fi

    save_dual_result \
        "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" \
        "${inspection_summary}" "${command_result}" "${command_executed}" \
        "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" \
        "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
    
    return 0
}

main() {
    show_diagnosis_start "${ITEM_ID}" "${ITEM_NAME}"
    [ "$EUID" -ne 0 ] && exit 1
    diagnose
    show_diagnosis_complete "${ITEM_ID}" "${diagnosis_result}"
}

main "$@"
