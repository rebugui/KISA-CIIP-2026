#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : U-51
# @Category    : Unix Server
# @Platform    : Solaris
# @Severity    : 중
# @Title       : DNS 서비스의 취약한 동적 업데이트 설정 금지
# @Description : allow-update 설정 확인
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


ITEM_ID="U-51"
ITEM_NAME="DNS 서비스의 취약한 동적 업데이트 설정 금지"
SEVERITY="중"

# 가이드라인 정보
GUIDELINE_PURPOSE="DNS 서비스의 동적 업데이트를 비활성화함으로써 신뢰할 수 없는 원본으로부터 업데이트를 받아들이는 위험을 차단하기 위함"
GUIDELINE_THREAT="DNS 서버에서 동적 업데이트를 사용할 경우, 악의적인 사용자에 의해 신뢰할 수 없는 데이터가 받아들여질 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="DNS 서비스의 동적 업데이트 기능이 비활성화되었거나, 활성화 시 적절한 접근 통제를 수행하고 있는 경우"
GUIDELINE_CRITERIA_BAD="DNS 서비스의 동적 업데이트 기능이 활성화 중이며 적절한 접근 통제를 수행하고 있지 않은 경우"
GUIDELINE_REMEDIATION="DNS 서비스를 사용하지 않는 경우 서비스 중지 및 비활성화 설정 DNS 서비스 사용 시 일반적으로 동적 업데이트 기능이 필요 없으나 확인 필요함"

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

    # DNS 동적 업데이트 설정 제한 확인
    local dns_configured=false
    local is_secure=true
    local dns_info=""
    local issues=()

    # BIND 설정 파일 경로 확인
    local bind_conf="/etc/bind/named.conf"
    local bind_conf_local="/etc/bind/named.conf.local"
    local bind_conf_opts="/etc/bind/named.conf.options"

    for conf_file in "$bind_conf" "$bind_conf_local" "$bind_conf_opts"; do
        if [ -f "$conf_file" ]; then
            dns_configured=true
            dns_info="${dns_info}${conf_file} 확인:${newline}"

            # allow-update 설정 확인
            local allow_update=$(grep -i "allow-update" "$conf_file" | grep -v "^//" | grep -v "^#" || echo "")
            if [ -n "$allow_update" ]; then
                dns_info="${dns_info}${allow_update}\${newline}"

                # "any" 확인
                if echo "$allow_update" | grep -qi "allow-update.*{.*any.*;"; then
                    is_secure=false
                    issues+=("allow-update가 'any'로 설정됨 (취약)")
                elif echo "$allow_update" | grep -qi "allow-update.*{.*none.*;"; then
                    dns_info="${dns_info}allow-update가 'none'으로 설정됨 (안전)${newline}"
                else
                    # 키 기반 업데이트인 경우 확인
                    if echo "$allow_update" | grep -qi "key"; then
                        dns_info="${dns_info}allow-update가 키로 제한됨${newline}"
                    else
                        is_secure=false
                        issues+=("allow-update가 IP로 제한됨 (키 기반 권장)")
                    fi
                fi
            else
                # 기본값은 none이므로 안전함
                dns_info="${dns_info}allow-update 설정 없음 (기본값 none, 안전)${newline}"
            fi

            # update-policy 확인 (더 안전한 대안)
            local update_policy=$(grep -i "update-policy" "$conf_file" | grep -v "^//" | grep -v "^#" || echo "")
            if [ -n "$update_policy" ]; then
                dns_info="${dns_info}${update_policy}${newline}"
                dns_info="${dns_info}update-policy 사용됨 (안전)${newline}"
            fi
        fi
    done || true

    # DNS 서비스 실행 확인 (Solaris SMF)
    if svcs named 2>/dev/null | grep -q "online" || \
       svcs server/dns 2>/dev/null | grep -q "online" || \
       svcs bind9 2>/dev/null | grep -q "online"; then
        dns_configured=true
        dns_info="${dns_info}\${newline}DNS 서비스 실행 중\${newline}"
    fi

    # 최종 판정
    if [ "$dns_configured" = false ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="DNS 서비스 미설치됨"
        command_result="DNS not used"
        command_executed="svcs named server/dns bind9 2>/dev/null"
    elif [ "$is_secure" = true ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="DNS 동적 업데이트 제한 적절히 설정됨"
        command_result="${dns_info}"
        command_executed="grep -i 'allow-update|update-policy' /etc/bind/named.conf*"
    else
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="DNS 동적 업데이트 제한 미흡: ${issues[*]}"
        command_result="${dns_info}${newline}[Issues:] ${issues[*]}"
        command_executed="grep -i 'allow-update|update-policy' /etc/bind/named.conf*"
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
