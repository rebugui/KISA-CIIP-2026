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

# Community String 복잡성 판정 (판단기준)
#  1. 기본값 'public', 'private'인 경우 취약
#  2. 영문자, 숫자 포함 10자리 미만인 경우 취약
#  3. 영문자, 숫자, 특수 문자 포함 8자리 미만인 경우 취약
# 반환: 0=양호, 1=취약 (사유는 COMPLEXITY_REASON 변수에 기록)
COMPLEXITY_REASON=""

check_community_complexity() {
    local comm="$1"
    local lower
    lower=$(printf '%s' "$comm" | tr '[:upper:]' '[:lower:]')
    COMPLEXITY_REASON=""

    # 1) 기본값 'public', 'private' 여부
    if [ "$lower" = "public" ] || [ "$lower" = "private" ]; then
        COMPLEXITY_REASON="기본값 '${comm}' 사용"
        return 1
    fi

    local len=${#comm}
    local has_alpha=false
    local has_digit=false
    local has_special=false
    case "$comm" in *[A-Za-z]*) has_alpha=true ;; esac
    case "$comm" in *[0-9]*) has_digit=true ;; esac
    case "$comm" in *[!A-Za-z0-9]*) has_special=true ;; esac

    # 영문자, 숫자, 특수 문자 포함 8자리 이상인 경우 양호
    if [ "$has_alpha" = true ] && [ "$has_digit" = true ] && [ "$has_special" = true ] && [ "$len" -ge 8 ]; then
        return 0
    fi
    # 영문자, 숫자 포함 10자리 이상인 경우 양호
    if [ "$has_alpha" = true ] && [ "$has_digit" = true ] && [ "$len" -ge 10 ]; then
        return 0
    fi

    COMPLEXITY_REASON="복잡성 미충족 (길이 ${len}자, 영문자=${has_alpha}, 숫자=${has_digit}, 특수문자=${has_special})"
    return 1
}

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
    # Solaris 가이드 점검 대상:
    #  - /etc/snmp/conf/snmpd.conf  (Solaris 9 이하: read/write-community)
    #  - /etc/snmp/conf/snmpdx.acl  (snmpdx ACL: communities = ...)
    #  - /etc/sma/snmp/snmpd.conf   (Solaris 10 SMA: net-snmp 형식)
    #  - /etc/net-snmp/snmp/snmpd.conf (Solaris 11: net-snmp 형식)
    #  - /etc/snmp/snmpd.conf       (net-snmp 기본 경로)
    local conf_candidates=("/etc/snmp/conf/snmpd.conf" "/etc/snmp/conf/snmpdx.acl" "/etc/sma/snmp/snmpd.conf" "/etc/net-snmp/snmp/snmpd.conf" "/etc/snmp/snmpd.conf")
    local existing_confs=()
    local unreadable_confs=()
    local conf=""

    for conf in "${conf_candidates[@]}"; do
        if [ -f "$conf" ]; then
            existing_confs+=("$conf")
        fi
    done

    # 1) SNMP 설치 여부 확인
    if [ ${#existing_confs[@]} -gt 0 ] || command -v snmpd >/dev/null 2>&1; then
        snmpd_installed=true
    fi

    if [ "$snmpd_installed" = false ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="SNMP 서비스가 설치되지 않음"
        local snmp_check=$(ls /etc/snmp/conf/snmpd.conf /etc/sma/snmp/snmpd.conf /etc/net-snmp/snmp/snmpd.conf /etc/snmp/snmpd.conf 2>/dev/null || echo "SNMP not installed")
        command_result="[Command: ls snmpd.conf candidates]${newline}${snmp_check}"
        command_executed="ls /etc/snmp/conf/snmpd.conf /etc/sma/snmp/snmpd.conf /etc/net-snmp/snmp/snmpd.conf /etc/snmp/snmpd.conf 2>/dev/null"
    elif [ ${#existing_confs[@]} -eq 0 ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="SNMP 설정 파일이 존재하지 않음"
        local snmp_check=$(ls /etc/snmp/conf/*.conf /etc/sma/snmp/*.conf /etc/net-snmp/snmp/*.conf /etc/snmp/*.conf 2>/dev/null || echo "No SNMP config found")
        command_result="[Command: ls SNMP config candidates]${newline}${snmp_check}"
        command_executed="ls /etc/snmp/conf/*.conf /etc/sma/snmp/*.conf /etc/net-snmp/snmp/*.conf /etc/snmp/*.conf 2>/dev/null"
    else
        # 2) 설정 파일별 Community String 값 추출 후 복잡성 판정
        #    - read/write-community (2번째 필드), system-group-read/write-community (2번째 필드)
        #    - ro/rwcommunity (2번째 필드), com2sec (4번째 필드)
        #    - snmpdx.acl : communities = <목록>
        local community_values=""
        local file_values=""
        local file_lines=""
        local raw_output=""
        local comm=""

        for conf in "${existing_confs[@]}"; do
            if [ ! -r "$conf" ]; then
                unreadable_confs+=("$conf")
                raw_output="${raw_output}[${conf}] unreadable${newline}"
                continue
            fi

            file_lines=$(grep -iE "communit|com2sec" "$conf" 2>/dev/null | grep -v "^[[:space:]]*#" | head -15 || true)
            raw_output="${raw_output}[${conf}]${newline}${file_lines:-No community entries}${newline}"

            file_values=$(awk '
                {
                    l = tolower($0)
                    if (l ~ /^[[:space:]]*#/) next
                    if (FILENAME ~ /snmpdx\.acl$/) {
                        if (l ~ /communities[[:space:]]*=/) {
                            line = $0
                            sub(/^[^=]*=[[:space:]]*/, "", line)
                            gsub(/[,{}]/, " ", line)
                            n = split(line, parts, /[[:space:]]+/)
                            for (i = 1; i <= n; i++) if (parts[i] != "") print parts[i]
                        }
                        next
                    }
                    key = tolower($1)
                    if (key ~ /^(ro|rw)community6?$/ && $2 != "") print $2
                    else if ((key == "com2sec" || key == "com2sec6") && $4 != "") print $4
                    else if (key ~ /^(read|write)-community$/ && $2 != "") print $2
                    else if (key ~ /^system-group-(read|write)-community$/ && $2 != "") print $2
                }
            ' "$conf" 2>/dev/null || true)

            [ -z "$file_values" ] && continue
            while IFS= read -r comm; do
                [ -z "$comm" ] && continue
                comm="${comm%\"}"
                comm="${comm#\"}"
                community_values="${community_values}${comm}${newline}"
                if ! check_community_complexity "$comm"; then
                    weak_community=true
                    community_details="${community_details}${conf}: Community '${comm}' - ${COMPLEXITY_REASON}, "
                fi
            done <<< "$file_values" || true
        done

        if [ "$weak_community" = true ]; then
            diagnosis_result="VULNERABLE"
            status="취약"
            inspection_summary="약한 SNMP Community String 사용: ${community_details%, }"
            command_result="${raw_output}"
            command_executed="grep -iE 'communit|com2sec' ${existing_confs[*]}"
        elif [ ${#unreadable_confs[@]} -gt 0 ]; then
            diagnosis_result="MANUAL"
            status="수동진단"
            inspection_summary="SNMP 설정 파일(${unreadable_confs[*]})을 읽을 수 없어 Community String 복잡성 수동 확인 필요"
            command_result="${raw_output}"
            command_executed="grep -iE 'communit|com2sec' ${existing_confs[*]}"
        else
            diagnosis_result="GOOD"
            status="양호"
            if [ -n "$community_values" ]; then
                inspection_summary="SNMP Community String이 안전하게 설정됨 (기본값 미사용, 복잡성 충족)"
            else
                inspection_summary="SNMP Community String이 설정되지 않았거나 v3만 사용 중"
            fi
            command_result="${raw_output}"
            command_executed="grep -iE 'communit|com2sec' ${existing_confs[*]}"
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
