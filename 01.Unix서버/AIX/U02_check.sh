#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : U-02
# @Category    : Unix Server
# @Platform    : AIX
# @Severity    : 상
# @Title       : 비밀번호 관리 정책 설정
# @Description : 비밀번호 복잡성 설정 및 최소/최대 사용 기간 확인
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


ITEM_ID="U-02"
ITEM_NAME="비밀번호 관리 정책 설정"
SEVERITY="상"

# 가이드라인 정보
GUIDELINE_PURPOSE="사용자의 비밀번호 복잡성과 주기적 변경을 통해 시스템 보안을 강화하기 위함"
GUIDELINE_THREAT="비밀번호 관련 정책이 설정되지 않을 경우, 비인가자의 각종 공격(무차별 대입 공격, 사전 대입 공격 등)에 의해 비밀번호가 노출될 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="비밀번호 관리 정책이 설정된 경우"
GUIDELINE_CRITERIA_BAD="비밀번호 관리 정책이 설정되지 않은 경우"
GUIDELINE_REMEDIATION="root 계정을 포함한 사용자 계정의 비밀번호를 영문, 숫자, 특수 문자를 포함하여 최소 8 자리 이상 및 최소 사용 기간 1일, 최대 사용 기간 90일, 최근 비밀번호 기억 4회 이상으로 설정"

# ============================================================================
# 진단 함수
# ============================================================================

# /etc/security/user 의 default: 스탠자에서 속성 값 추출 (마지막 정의 우선)
u02_get_default_attr() {
    awk -v key="$1" '
        /^\*/ { next }
        /^default:/ { in_def=1; next }
        /^[^ \t]/ { in_def=0 }
        in_def && $0 ~ ("^[ \t]*" key "[ \t]*=") {
            line=$0
            sub(/^[ \t]*[A-Za-z_]+[ \t]*=[ \t]*/, "", line)
            sub(/[ \t]*$/, "", line)
            val=line
        }
        END { if (val != "") print val }
    ' "$2" 2>/dev/null || true
}

# /etc/security/user 에서 지정한 스탠자 전체 추출 (증적용)
u02_get_stanza() {
    awk -v stanza="$1" '
        $0 == stanza ":" { f=1; print; next }
        /^[^ \t]/ { f=0 }
        f { print }
    ' "$2" 2>/dev/null || true
}

# 양의 정수(0 포함) 여부 확인
u02_is_number() {
    case "$1" in
        ''|*[!0-9]*) return 1 ;;
        *) return 0 ;;
    esac
}

# 진단 수행
diagnose() {

    diagnosis_result="unknown"
    local status="미진단"
    local inspection_summary=""
    local command_result=""
    local command_executed=""

    # 진단 로직 구현 (KISA 가이드 AIX 기준: /etc/security/user 의 default: 스탠자)
    #  - maxage 1~12 (주 단위 최대 사용 기간, 90일 ≈ 12주, 0/미설정은 만료 없음으로 취약)
    #  - minage >= 1 (주 단위 최소 사용 기간)
    #  - minlen >= 8 (비밀번호 최소 길이)
    #  - histsize >= 4 (최근 비밀번호 기억 횟수)
    #  - minalpha >= 1 (영문자 최소 개수, 복잡성)
    #  - minother >= 1 (영문자 외 문자(숫자/특수문자) 최소 개수, 복잡성)
    # root: 스탠자는 참고 증적으로만 기록

    local security_user_file="/etc/security/user"
    local newline=$'\n'
    local default_stanza_output=""
    local root_stanza_output=""
    local config_details=""

    if [ -f "$security_user_file" ] && [ -r "$security_user_file" ]; then
        # 증적용 raw output (default: 스탠자 = 판정 기준, root: 스탠자 = 참고)
        default_stanza_output=$(u02_get_stanza "default" "$security_user_file")
        root_stanza_output=$(u02_get_stanza "root" "$security_user_file")

        local maxage=""
        local minage=""
        local minlen=""
        local histsize=""
        local minalpha=""
        local minother=""
        maxage=$(u02_get_default_attr "maxage" "$security_user_file")
        minage=$(u02_get_default_attr "minage" "$security_user_file")
        minlen=$(u02_get_default_attr "minlen" "$security_user_file")
        histsize=$(u02_get_default_attr "histsize" "$security_user_file")
        minalpha=$(u02_get_default_attr "minalpha" "$security_user_file")
        minother=$(u02_get_default_attr "minother" "$security_user_file")

        config_details="default 스탠자: maxage=${maxage:-미설정}(주), minage=${minage:-미설정}(주), minlen=${minlen:-미설정}, histsize=${histsize:-미설정}, minalpha=${minalpha:-미설정}, minother=${minother:-미설정}"

        local maxage_ok=false
        local minage_ok=false
        local minlen_ok=false
        local histsize_ok=false
        local minalpha_ok=false
        local minother_ok=false

        # maxage: 주(week) 단위. 1~12주 (90일 ≈ 12주). 0 또는 미설정은 만료 없음 → 취약
        if u02_is_number "$maxage" && [ "$maxage" -ge 1 ] && [ "$maxage" -le 12 ]; then
            maxage_ok=true
        fi

        # minage: 주(week) 단위. 1주 이상
        if u02_is_number "$minage" && [ "$minage" -ge 1 ]; then
            minage_ok=true
        fi

        # minlen >= 8
        if u02_is_number "$minlen" && [ "$minlen" -ge 8 ]; then
            minlen_ok=true
        fi

        # histsize >= 4
        if u02_is_number "$histsize" && [ "$histsize" -ge 4 ]; then
            histsize_ok=true
        fi

        # minalpha >= 1 (영문자 포함 - 복잡성. 0/미설정은 문자 구성 요구 없음 → 취약)
        if u02_is_number "$minalpha" && [ "$minalpha" -ge 1 ]; then
            minalpha_ok=true
        fi

        # minother >= 1 (영문자 외 문자(숫자/특수문자) 포함 - 복잡성. 0/미설정은 취약)
        if u02_is_number "$minother" && [ "$minother" -ge 1 ]; then
            minother_ok=true
        fi

        if [ "$maxage_ok" = true ] && [ "$minage_ok" = true ] && \
           [ "$minlen_ok" = true ] && [ "$histsize_ok" = true ] && \
           [ "$minalpha_ok" = true ] && [ "$minother_ok" = true ]; then
            diagnosis_result="GOOD"
            status="양호"
            inspection_summary="비밀번호 관리 정책이 적절하게 설정됨 (${config_details})"
        else
            diagnosis_result="VULNERABLE"
            status="취약"
            inspection_summary="비밀번호 관리 정책 미흡: ${config_details} (기준: maxage 1~12주, minage>=1주, minlen>=8, histsize>=4, minalpha>=1, minother>=1)"
        fi
    else
        # 파일이 없거나 읽을 수 없는 경우 → 수동 점검
        default_stanza_output=$(ls -l "$security_user_file" 2>/dev/null || echo "File not found: ${security_user_file}")
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="/etc/security/user 파일이 없거나 읽을 수 없어 비밀번호 관리 정책을 확인하지 못함 - 수동 점검 필요"
    fi

    # 명령어 실행 결과 결합 (raw output)
    command_result="[/etc/security/user default: 스탠자]${newline}${default_stanza_output:-default 스탠자 없음}${newline}${newline}"
    command_result="${command_result}[/etc/security/user root: 스탠자 (참고)]${newline}${root_stanza_output:-root 스탠자 없음}"

    command_executed="awk(/etc/security/user default: 스탠자 maxage/minage/minlen/histsize/minalpha/minother); awk(/etc/security/user root: 스탠자)"

    #echo ""
    #echo "진단 결과: ${status}"
    #echo "판정: ${diagnosis_result}"
    #echo "설명: ${inspection_summary}"
    #echo ""

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
