#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : U-60
# @Category    : Unix Server
# @Platform    : Solaris
# @Severity    : 중
# @Title       : SNMP Community String 복잡성 설정
# @Description : public, private 이외 community 사용
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


ITEM_ID="U-60"
ITEM_NAME="SNMP Community String 복잡성 설정"
SEVERITY="중"

# 가이드라인 정보
GUIDELINE_PURPOSE="SNMP 서비스의 Community String의 복잡성 설정을 통해 비인가자의 비밀번호 추측 공격에 대비하기 위함"
GUIDELINE_THREAT="Community String에 복잡성 설정이 되어 있지 않을 경우, 비인가자가 비밀번호 추측 공격을 통해 계정 탈취 시 환경 설정 파일 열람 및 수정, 각종 정보 수집, 관리자 권한 획득 등 다양한 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="SNMP Community String 기본값인 'public', 'private'이 아닌 영문자, 숫자 포함 10 자리 이상 또는 영문자, 숫자, 특수 문자 포함 8 자리 이상인 경우 ※ SNMPv3의 경우 별도 인증 기능을 사용하고, 해당 비밀번호가 복잡 도를 만족하는 경우 양호"
GUIDELINE_CRITERIA_BAD="아래의 내용 중 하나라도 해당되는 경우 1. SNMP Community String 기본값인'public', 'private'일 경우 2. 영문자, 숫자 포함 10 자리 미만인 경우 3. 영문자, 숫자, 특수 문자 포함 8 자리 미만인 경우"
GUIDELINE_REMEDIATION="SNMP 서비스를 사용하지 않는 경우 서비스 중지 및 비활성화 설정 SNMP 서비스 사용 시 SNMP Community String 기본값인 'public', 'private'이 아닌 영문자, 숫자 포함 10 자리 이상 또는 영문자, 숫자, 특수 문자 포함 8 자리 이상으로 설정"

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

    # 진단 로직 구현
    # SNMP Community String 복잡성 확인

    local snmpd_installed=false
    local weak_community=false
    local community_details=""
    local snmp_conf="/etc/snmp/snmpd.conf"

    # 1) SNMP 설치 여부 확인
    if [ -f "$snmp_conf" ] || command -v snmpd >/dev/null 2>&1; then
        snmpd_installed=true
    fi

    if [ "$snmpd_installed" = false ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="SNMP 서비스가 설치되지 않음"
        local snmp_check=$(ls "${snmp_conf}" 2>/dev/null || echo "SNMP not installed")
        command_result="[Command: ls ${snmp_conf}]\${newline}${snmp_check}"
        command_executed="ls ${snmp_conf} 2>/dev/null"
    elif [ ! -f "$snmp_conf" ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="SNMP 설정 파일이 존재하지 않음"
        local snmp_check=$(ls /etc/snmp/*.conf 2>/dev/null || echo "No SNMP config found")
        command_result="[Command: ls /etc/snmp/*.conf]\${newline}${snmp_check}"
        command_executed="ls /etc/snmp/*.conf 2>/dev/null"
    else
        # 2) Community String 확인 (기본 취약한 community: public, private, cisco 등)
        local default_communities=("public" "private" "cisco" "admin" "monitor" "write" "read" "secret")

        for default_comm in "${default_communities[@]}"; do
            # 대소문자 구분 없이 기본 community string 검색
            if grep -qiE "com2sec.*${default_comm}|rocommunity.*${default_comm}|rwcommunity.*${default_comm}" "$snmp_conf" 2>/dev/null; then
                weak_community=true
                # 해당 라인 추출
                local matching_lines=$(grep -iE "com2sec.*${default_comm}|rocommunity.*${default_comm}|rwcommunity.*${default_comm}" "$snmp_conf" 2>/dev/null | grep -v "^#" | head -3)
                community_details="${community_details}기본 Community '${default_comm}' 사용: ${matching_lines}, "
            fi
        done || true

        # 3) Community string 복잡성 확인 (길이, 문자열 구성)
        # 사용자 정의 community string 확인
        local custom_communities=$(grep -iE "com2sec|rocommunity|rwcommunity" "$snmp_conf" 2>/dev/null | grep -v "^#" | awk '{for(i=2;i<=NF;i++)print $i}' | head -10)

        if [ -n "$custom_communities" ]; then
            while IFS= read -r comm; do
                if [ -n "$comm" ] && [ ${#comm} -lt 8 ]; then
                    weak_community=true
                    community_details="${community_details}약한 Community '${comm}' (길이 ${#comm}), "
                fi
            done <<< "$custom_communities" || true
        fi

        if [ "$weak_community" = true ]; then
            diagnosis_result="VULNERABLE"
            status="취약"
            inspection_summary="약한 SNMP Community String 사용: ${community_details%, }"
            command_result="${community_details%, }"
            command_executed="grep -iE 'com2sec|rocommunity|rwcommunity' ${snmp_conf} | grep -v '^#'"
        else
            diagnosis_result="GOOD"
            status="양호"
            if [ -n "$custom_communities" ]; then
                inspection_summary="SNMP Community String이 안전하게 설정됨 (기본값 미사용, 복잡성 충분)"
                command_result="Community: secure configuration"
            else
                inspection_summary="SNMP Community String이 설정되지 않았거나 v3만 사용 중"
                command_result="Community: not set or v3"
            fi
            command_executed="grep -iE 'com2sec|rocommunity|rwcommunity' ${snmp_conf}"
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
