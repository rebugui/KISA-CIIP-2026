#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-28
# ============================================================================
# [점검 항목 상세]
# @ID          : U-51
# @Category    : UNIX > 3. 서비스 관리
# @Platform    : RedHat
# @Severity    : 중
# @Title       : DNS 서비스의 취약한 동적 업데이트 설정 금지
# @Description : 인가되지 않은 사용자의 DNS 동적 업데이트(Dynamic Update) 허용 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/metadata_parser.sh"

ITEM_ID="U-51"
ITEM_NAME="DNS 서비스의 취약한 동적 업데이트 설정 금지"
SEVERITY="중"

GUIDELINE_PURPOSE="DNS 서비스의 동적 업데이트를 비활성화함으로써 신뢰할 수 없는 원본으로부터 업데이트를 받아들이는 위험을 차단하기 위함"
GUIDELINE_THREAT="DNS 서버에서 동적 업데이트를 사용할 경우, 악의적인 사용자에 의해 신뢰할 수 없는 데이터가 받아들여질 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="DNS 서비스의 동적 업데이트 기능이 비활성화되었거나, 활성화 시 적절한 접근 통제를 수행하고 있는 경우"
GUIDELINE_CRITERIA_BAD="DNS 서비스의 동적 업데이트 기능이 활성화 중이며 적절한 접근 통제를 수행하고 있지 않은 경우"
GUIDELINE_REMEDIATION="DNS 서비스를 사용하지 않는 경우 서비스 중지 및 비활성화 설정 DNS 서비스 사용 시 일반적으로 동적 업데이트 기능이 필요 없으나 확인 필요함"

diagnose() {
    local status="양호"
    diagnosis_result="GOOD"
    local inspection_summary="DNS 동적 업데이트 설정이 적절하게 제한되어 있습니다."
    local command_result=""
    local command_executed="cat /etc/named.conf /etc/named.rfc1912.zones <include된 zone 파일> | grep -oiE 'allow-update[^{};]*\\{[^}]*'"

    local conf_found=false
    local evidence=""
    local conf_file=""

    # 점검 대상 파일: 표준 경로 + named.conf의 include 지시자 1단계 추적
    # (zone 별 allow-update가 custom include 파일에 있을 수 있음)
    local scan_files="/etc/named.conf /etc/named.rfc1912.zones"
    if [ -f /etc/named.conf ]; then
        local inc
        for inc in $(grep -v "^[[:space:]]*//" /etc/named.conf 2>/dev/null | grep -v "^[[:space:]]*#" | grep -oE 'include[[:space:]]+"[^"]+"' | sed -E 's/include[[:space:]]+"([^"]+)"/\1/' || true); do
            case " $scan_files " in
                *" $inc "*) ;;
                *)
                    if [ -f "$inc" ]; then
                        scan_files="$scan_files $inc"
                    elif [ -f "/etc/${inc}" ]; then
                        scan_files="$scan_files /etc/${inc}"
                    fi
                    ;;
            esac
        done
    fi

    for conf_file in $scan_files; do
        if [ -f "$conf_file" ]; then
            conf_found=true
            # 주석 제거 후 다중행 allow-update 블록을 한 줄로 평탄화하여 점검
            # sed 범위(/allow-update/,/;/)는 첫 ';' 줄에서 끊겨 멀티라인 블록 내 any를 놓치므로 사용 금지
            local au_flat=$(sed -e 's://.*$::' -e 's:#.*$::' "$conf_file" 2>/dev/null | tr -s '[:space:]' ' ' || echo "")
            local au_blocks=$(echo "$au_flat" | grep -oiE 'allow-update[^{};]*\{[^}]*' || echo "")
            if [ -n "$au_blocks" ]; then
                evidence="${evidence}${conf_file}: [ $(echo "$au_blocks" | tr '\n' ' ') ]. "
                # none·키·특정 IP 제한은 양호(가이드 조치방법 부합), any만 취약
                if echo "$au_blocks" | grep -qiw "any"; then
                    status="취약"
                    diagnosis_result="VULNERABLE"
                    inspection_summary="DNS 동적 업데이트가 모든 호스트(any)에 대해 허용되어 있습니다. (${conf_file})"
                fi
            else
                evidence="${evidence}${conf_file}: allow-update 미설정(기본값 none). "
            fi
        fi
    done

    if [ "$conf_found" = true ]; then
        command_result="allow-update 설정 현황: ${evidence}"
    else
        command_result="DNS 설정 파일(/etc/named.conf, /etc/named.rfc1912.zones)이 존재하지 않습니다."
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
