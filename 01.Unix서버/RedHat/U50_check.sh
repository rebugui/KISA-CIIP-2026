#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-28
# ============================================================================
# [점검 항목 상세]
# @ID          : U-50
# @Category    : UNIX > 3. 서비스 관리
# @Platform    : RedHat
# @Severity    : 상
# @Title       : DNS ZoneTransfer 설정
# @Description : DNS 존 전송(Zone Transfer)을 제한하여 불필요한 영역 정보 노출을 방지하는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/metadata_parser.sh"

ITEM_ID="U-50"
ITEM_NAME="DNS ZoneTransfer 설정"
SEVERITY="상"

GUIDELINE_PURPOSE="DNSZoneTransfer 설정을 통해 비인가자에 대한 무단 접근을 방지하기 위함"
GUIDELINE_THREAT="ZoneTransfer를 모든 사용자에게 허용할 경우, 비인가자에게 호스트 정보, 시스템 정보 등 중요 정보가 유출될 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="ZoneTransfer를 허가된 사용자에게만 허용한 경우"
GUIDELINE_CRITERIA_BAD="Zone Transfer를 모든 사용자에게 허용한 경우"
GUIDELINE_REMEDIATION="DNS 서비스를 사용하지 않는 경우 서비스 중지 및 비활성화 설정 DNS 서비스 사용 시 DNSZoneTransfer를 허가된 사용자에게만 전송 허용하도록 설정"

diagnose() {
    local status="양호"
    diagnosis_result="GOOD"
    local inspection_summary="DNS 존 전송 설정이 적절하게 제한되어 있습니다."
    local command_result=""
    local command_executed="grep -v '^//' /etc/named.conf | tr -s '[:space:]' ' ' | grep -oiE 'allow-transfer[^{};]*\{[^}]*'"

    # 설정 파일 탐색: 표준 경로 + chroot 운용 경로
    local named_conf=""
    local cand
    for cand in /etc/named.conf /var/named/chroot/etc/named.conf; do
        if [ -f "$cand" ]; then
            named_conf="$cand"
            break
        fi
    done

    if [ -n "$named_conf" ]; then
        # include 지시자 1단계 추적 (zone 별 allow-transfer가 include 파일에 있을 수 있음)
        # 미해결 include(절대 경로/conf_dir 상대 경로/글롭 등)는 GOOD으로 묻히지 않도록 별도 플래그로 표시
        local conf_dir=$(dirname "$named_conf")
        local conf_files="$named_conf"
        local include_unresolved=false
        local unresolved_list=""
        local inc
        for inc in $(grep -v "^[[:space:]]*//" "$named_conf" 2>/dev/null | grep -v "^[[:space:]]*#" | grep -oE 'include[[:space:]]+"[^"]+"' | sed -E 's/include[[:space:]]+"([^"]+)"/\1/' || true); do
            if [ -f "$inc" ]; then
                conf_files="$conf_files $inc"
            elif [ -f "${conf_dir}/${inc}" ]; then
                conf_files="$conf_files ${conf_dir}/${inc}"
            else
                include_unresolved=true
                unresolved_list="${unresolved_list}${unresolved_list:+ }${inc}"
            fi
        done

        # 멀티라인 블록 대응: 주석 제거 후 평탄화하여 allow-transfer 블록 전체 추출
        local transfer_opt
        transfer_opt=$(cat $conf_files 2>/dev/null | grep -v "^[[:space:]]*//" | grep -v "^[[:space:]]*#" | tr -s '[:space:]' ' ' | grep -oiE 'allow-transfer[^{};]*\{[^}]*' || echo "not-set")
        if [[ "$transfer_opt" == "not-set" ]] || echo "$transfer_opt" | grep -qiE '(^|[{; ])any *;'; then
            status="취약"
            diagnosis_result="VULNERABLE"
            inspection_summary="DNS 존 전송이 제한되지 않았거나 모든 호스트(any)에 허용되어 있습니다."
        elif [ "$include_unresolved" = true ]; then
            # 기본 설정의 allow-transfer는 안전하나, 미확인 include(예: chroot/글롭 패턴) 내 per-zone override 가능성 존재
            status="수동진단"
            diagnosis_result="MANUAL"
            inspection_summary="기본 설정의 allow-transfer는 제한되어 있으나, 확인할 수 없는 include 지시자가 존재합니다. include 파일 내 per-zone allow-transfer 설정을 수동으로 확인하십시오."
        fi
        command_result="점검 파일: [ ${conf_files} ] / allow-transfer 설정 현황: [ ${transfer_opt} ]"
        if [ "$include_unresolved" = true ]; then
            command_result="${command_result} / 미해결 include: [ ${unresolved_list} ]"
        fi
    else
        if pgrep -x named >/dev/null 2>&1; then
            status="수동진단"
            diagnosis_result="MANUAL"
            inspection_summary="named 프로세스는 실행 중이나 표준 경로에서 설정 파일을 찾을 수 없습니다. 비표준/chroot 경로의 allow-transfer 설정을 수동으로 확인하십시오."
        else
            status="양호"
            diagnosis_result="GOOD"
            inspection_summary="DNS(BIND) 서비스 미사용 (설정 파일 없음 및 named 미실행)"
        fi
        command_result="DNS 설정 파일(/etc/named.conf, /var/named/chroot/etc/named.conf)이 존재하지 않습니다."
    fi

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
