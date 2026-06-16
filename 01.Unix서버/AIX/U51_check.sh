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
# @Platform    : AIX
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
    local newline=$'\n'

    # DNS 동적 업데이트 설정 제한 확인
    local dns_configured=false
    local is_secure=""
    local dns_info=""
    local issues=()
    local service_running=false
    local service_probe=""

    # BIND 설정 파일 경로 확인 (AIX 실제 경로 + Debian 계열 추가 경로)
    local bind_conf_files=(
        "/etc/named.conf"
        "/etc/named.boot"
        "/var/named/named.conf"
        "/etc/bind/named.conf"
        "/etc/bind/named.conf.local"
        "/etc/bind/named.conf.options"
    )

    # include 구문으로 참조되는 설정 파일도 점검 대상에 추가 (zone별 allow-update 누락 방지)
    # U50과 동일하게 include된 zone 파일까지 스캔하여 included 파일 내 allow-update {any;} 누락을 방지함
    local include_files=()
    local inc_path=""
    local include_unresolved=false
    for conf_file in "${bind_conf_files[@]}"; do
        [ -f "$conf_file" ] || continue
        while IFS= read -r inc_path; do
            [ -n "$inc_path" ] || continue
            if [ -f "$inc_path" ]; then
                include_files+=("$inc_path")
            else
                # include 경로를 확인할 수 없음: 자동 판정 불가 (수동 점검 대상)
                include_unresolved=true
            fi
        done < <(sed -e 's://.*$::' -e 's:#.*$::' "$conf_file" 2>/dev/null | grep -oE 'include[[:space:]]+"[^"]+"' | sed 's/include[[:space:]]*"//; s/"$//' | head -20 || true)
    done
    if [ ${#include_files[@]} -gt 0 ]; then
        bind_conf_files+=("${include_files[@]}")
    fi

    for conf_file in "${bind_conf_files[@]}"; do
        if [ -f "$conf_file" ]; then
            dns_configured=true
            dns_info="${dns_info}${conf_file} 확인:${newline}"

            # allow-update 설정 확인 (주석 제거 → 평탄화 → 블록 전체('}'까지) 추출)
            # sed 범위(/allow-update/,/;/)는 첫 ';' 줄에서 끊겨 멀티라인 블록 내 any를 놓치므로 사용 금지
            local allow_update_block=""
            allow_update_block=$(sed -e 's://.*$::' -e 's:#.*$::' "$conf_file" 2>/dev/null | tr -s '[:space:]' ' ' | grep -oiE 'allow-update[^{};]*\{[^}]*' || true)

            if echo "$allow_update_block" | grep -qi "allow-update"; then
                dns_info="${dns_info}allow-update 설정: ${allow_update_block}${newline}"

                if echo "$allow_update_block" | grep -qiE '(^|[^[:alnum:]_-])any([^[:alnum:]_-]|$)'; then
                    # any 허용: 비인가 동적 업데이트 가능 (취약)
                    is_secure="false"
                    issues+=("${conf_file}: allow-update가 'any'로 설정됨 (취약)")
                elif echo "$allow_update_block" | grep -qiE '(^|[^[:alnum:]_-])none([^[:alnum:]_-]|$)'; then
                    # none: 동적 업데이트 비활성화 (양호)
                    if [ -z "$is_secure" ]; then is_secure="true"; fi
                    dns_info="${dns_info}allow-update가 'none'으로 설정됨 (동적 업데이트 비활성화, 양호)${newline}"
                elif echo "$allow_update_block" | grep -qi "key"; then
                    # 키 기반 접근 통제 (양호)
                    if [ -z "$is_secure" ]; then is_secure="true"; fi
                    dns_info="${dns_info}allow-update가 키 기반으로 제한됨 (접근 통제 수행, 양호)${newline}"
                else
                    # 특정 IP 제한: 가이드 조치방법(allow-update { <허용 IP>; };)에 따른 접근 통제 (양호)
                    if [ -z "$is_secure" ]; then is_secure="true"; fi
                    dns_info="${dns_info}allow-update가 특정 IP로 제한됨 (접근 통제 수행, 양호)${newline}"
                fi
            else
                # allow-update 미설정: BIND 기본값은 동적 업데이트 거부이므로 비활성화 상태 (양호)
                if [ -z "$is_secure" ]; then is_secure="true"; fi
                dns_info="${dns_info}allow-update 설정 없음 (BIND 기본값 거부, 동적 업데이트 비활성화)${newline}"
            fi

            # update-policy 확인 (키 기반 접근 통제 대안)
            local update_policy=""
            update_policy=$(grep -i "update-policy" "$conf_file" 2>/dev/null | grep -v "^[[:space:]]*//" | grep -v "^[[:space:]]*#" || true)
            if [ -n "$update_policy" ]; then
                dns_info="${dns_info}${update_policy}${newline}update-policy 사용됨 (접근 통제 수행)${newline}"
            fi
        fi
    done

    # DNS 서비스 실행 확인 (AIX SRC + ps 폴백)
    service_probe=$( { lssrc -s named 2>/dev/null; ps -ef 2>/dev/null | grep -w "named" | grep -v "grep"; } | tr -d '\r' || true)
    if lssrc -s named 2>/dev/null | grep -q "active"; then
        service_running=true
    elif ps -ef 2>/dev/null | grep -w "named" | grep -v "grep" | grep -q "."; then
        service_running=true
    fi
    if [ "$service_running" = true ]; then
        dns_configured=true
        dns_info="${dns_info}DNS 서비스(named) 실행 중${newline}"
    fi

    # 최종 판정 (증거 기반: is_secure는 설정 근거가 있을 때만 결정됨)
    if [ "$dns_configured" = false ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="DNS 서비스 미사용 (BIND 미실행 및 설정 파일 없음)"
        command_result="[Command: lssrc -s named; ps -ef | grep -w named]${newline}${service_probe:-DNS service not found}${newline}[Config] /etc/named.conf, /etc/named.boot, /var/named/named.conf, /etc/bind/named.conf* 없음"
        command_executed="lssrc -s named; ps -ef | grep -w named; ls /etc/named.conf /etc/named.boot /var/named/named.conf /etc/bind/named.conf*"
    elif [ "$is_secure" = "false" ]; then
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="DNS 동적 업데이트 제한 미흡: ${issues[*]}"
        command_result="${dns_info}${newline}[Issues] ${issues[*]}"
        command_executed="sed -n '/allow-update/,/;/p' /etc/named.conf /etc/named.boot /var/named/named.conf /etc/bind/named.conf*"
    elif [ "$is_secure" = "true" ] && [ "$include_unresolved" = true ]; then
        # 읽을 수 있는 설정 파일은 양호하나 include 경로를 확인하지 못함:
        # included zone 파일에 allow-update {any;}가 있을 수 있어 자동 판정 불가 (수동 점검)
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="DNS 동적 업데이트 설정은 확인된 설정 파일 기준 양호하나, include 참조 경로를 확인하지 못해 included zone 파일의 allow-update 설정 수동 점검 필요"
        command_result="${dns_info}${newline}[Unresolved include] 참조된 설정 파일을 확인하지 못함"
        command_executed="sed -n '/allow-update/,/;/p' /etc/named.conf /etc/named.boot /var/named/named.conf /etc/bind/named.conf* <included zone files>"
    elif [ "$is_secure" = "true" ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="DNS 동적 업데이트가 비활성화되었거나 적절한 접근 통제가 설정됨"
        command_result="${dns_info}"
        command_executed="sed -n '/allow-update/,/;/p' /etc/named.conf /etc/named.boot /var/named/named.conf /etc/bind/named.conf*"
    else
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="DNS 서비스 실행 중이나 BIND 설정 파일을 확인하지 못해 동적 업데이트 설정 수동 점검 필요"
        command_result="${dns_info}${newline}[Service probe]${newline}${service_probe:-N/A}"
        command_executed="lssrc -s named; ps -ef | grep -w named; sed -n '/allow-update/,/;/p' <named.conf>"
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
