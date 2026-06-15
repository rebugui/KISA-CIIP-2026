#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : U-50
# @Category    : Unix Server
# @Platform    : Solaris
# @Severity    : 상
# @Title       : DNS ZoneTransfer 설정
# @Description : allow-transfer 설정 확인
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


ITEM_ID="U-50"
ITEM_NAME="DNS ZoneTransfer 설정"
SEVERITY="상"

# 가이드라인 정보
GUIDELINE_PURPOSE="DNSZoneTransfer 설정을 통해 비인가자에 대한 무단 접근을 방지하기 위함"
GUIDELINE_THREAT="ZoneTransfer를 모든 사용자에게 허용할 경우, 비인가자에게 호스트 정보, 시스템 정보 등 중요 정보가 유출될 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="ZoneTransfer를 허가된 사용자에게만 허용한 경우"
GUIDELINE_CRITERIA_BAD="Zone Transfer를 모든 사용자에게 허용한 경우"
GUIDELINE_REMEDIATION="DNS 서비스를 사용하지 않는 경우 서비스 중지 및 비활성화 설정 DNS 서비스 사용 시 DNSZoneTransfer를 허가된 사용자에게만 전송 허용하도록 설정"

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

    # DNS Zone Transfer 설정 확인
    local dns_configured=false
    local is_secure=false
    local dns_info=""
    local issues=()

    # BIND 설정 파일 경로 확인 (Debian/RedHat 호환)
    local bind_conf_files=()

    # Debian/Ubuntu 계열
    if [ -f "/etc/bind/named.conf" ]; then
        bind_conf_files+=("/etc/bind/named.conf")
    fi
    if [ -f "/etc/bind/named.conf.local" ]; then
        bind_conf_files+=("/etc/bind/named.conf.local")
    fi
    if [ -f "/etc/bind/named.conf.options" ]; then
        bind_conf_files+=("/etc/bind/named.conf.options")
    fi

    # RedHat/CentOS/Rocky/AlmaLinux 계열
    if [ -f "/etc/named.conf" ]; then
        bind_conf_files+=("/etc/named.conf")
    fi

    # 설정 파일이 하나도 없으면 기본 경로들 추가 (존재 여부 확인 후 진행)
    if [ ${#bind_conf_files[@]} -eq 0 ]; then
        bind_conf_files=("/etc/bind/named.conf" "/etc/bind/named.conf.local" "/etc/bind/named.conf.options" "/etc/named.conf")
    fi

    for conf_file in "${bind_conf_files[@]}"; do
        if [ -f "$conf_file" ]; then
            dns_configured=true
            dns_info="${dns_info}${conf_file} 확인:${newline}"

            # allow-transfer 설정 확인 (멀티라인 블록 평탄화 후 판정)
            local allow_transfer=$(grep -v '^[[:space:]]*//' "$conf_file" 2>/dev/null | grep -v '^[[:space:]]*#' | tr -s '[:space:]' ' ' | grep -oiE 'allow-transfer[^{};]*\{[^}]*' || echo "")
            if [ -n "$allow_transfer" ]; then
                dns_info="${dns_info}${allow_transfer}${newline}"

                # "any" 또는 "none" 확인
                if echo "$allow_transfer" | grep -qiE '(^|[{; ])any *;?'; then
                    issues+=("allow-transfer가 'any'로 설정됨 (취약)")
                elif echo "$allow_transfer" | grep -qiE '(^|[{; ])none *;?'; then
                    is_secure=true
                    dns_info="${dns_info}allow-transfer가 'none'으로 설정됨 (안전)${newline}"
                else
                    # 특정 IP/키로 제한된 경우
                    is_secure=true
                    dns_info="${dns_info}allow-transfer가 특정 호스트로 제한됨${newline}"
                fi
            else
                # 기본값은 any이므로 명시적 제한이 필요함
                issues+=("allow-transfer 설정 미존재 (기본값 any, 취약)")
            fi

            # also-notify 확인 (안전한 설정)
            local also_notify=$(grep -i "also-notify" "$conf_file" | grep -v "^//" | grep -v "^#" || echo "")
            if [ -n "$also_notify" ]; then
                dns_info="${dns_info}${also_notify}${newline}"
            fi
        fi
    done || true

    # DNS 서비스 실행 확인 (Solaris SMF 정식 FMRI + ps 폴백)
    if svcs -H -o state svc:/network/dns/server 2>/dev/null | grep -q "online" || \
       ps -ef 2>/dev/null | grep -w "named" | grep -v "grep" | grep -q "."; then
        dns_configured=true
        dns_info="${dns_info}${newline}DNS 서비스 실행 중${newline}"
    fi

    # 최종 판정
    if [ "$dns_configured" = false ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="DNS 서비스 미설치됨"
        command_result="DNS not used"
        command_executed="svcs -H -o state svc:/network/dns/server; ps -ef | grep -w named"
    elif [ "$is_secure" = true ] && [ ${#issues[@]} -eq 0 ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="DNS Zone Transfer 제한 적절히 설정됨"
        command_result="${dns_info}"
        command_executed="grep -i 'allow-transfer' /etc/bind/named.conf* /etc/named.conf 2>/dev/null || true"
    else
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="DNS Zone Transfer 제한 미흡: ${issues[*]}"
        command_result="${dns_info}${newline}[Issues:] ${issues[*]}"
        command_executed="grep -i 'allow-transfer' /etc/bind/named.conf* /etc/named.conf 2>/dev/null || true"
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
