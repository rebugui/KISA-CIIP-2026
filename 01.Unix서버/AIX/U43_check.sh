#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.2
# @Last Updated: 2026-04-23
# ============================================================================
# [점검 항목 상세]
# @ID          : U-43
# @Category    : Unix Server
# @Platform    : AIX
# @Severity    : 상
# @Title       : NIS, NIS +점검
# @Description : 계정 정보를 네트워크로 공유하는 NIS 서비스의 활성화 여부 점검
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


ITEM_ID="U-43"
ITEM_NAME="NIS, NIS +점검"
SEVERITY="상"

# 가이드라인 정보
GUIDELINE_PURPOSE="안전하지 않은 NIS 서비스를 비활성화하고 안전한 NIS + 서비스를 활성화하여 시스템의 보안성을 높이기 위함"
GUIDELINE_THREAT="NIS 서비스가 활성화된 경우, 비인가자가 타 시스템의 root 권한까지 탈취할 수 있는 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="NIS 서비스가 비활성화되어 있거나, 불가피하게 사용 시 NIS +서비스를 사용하는 경우"
GUIDELINE_CRITERIA_BAD="NIS 서비스가 활성화된 경우"
GUIDELINE_REMEDIATION="NIS 관련 서비스 비활성화 설정"

# ============================================================================
# 진단 함수
# ============================================================================

diagnose() {

    diagnosis_result="unknown"
    local status="미진단"
    local inspection_summary=""
    local command_result=""
    local command_executed=""
    local newline=$'\n'

    local is_secure=true
    local nis_details=""
    local active_items=()

    # 1) NIS 프로세스 확인
    local nis_procs=$(ps -ef 2>/dev/null | grep -Ei "ypserv|ypbind|yppasswdd|ypxfrd|rpc\.yppasswdd" | grep -v grep || echo "")
    if [ -n "$nis_procs" ]; then
        is_secure=false
        local proc_names=$(echo "$nis_procs" | awk '{print $8}' | sort -u | xargs)
        active_items+=("NIS 프로세스 실행 중: ${proc_names}")
    fi

    # 2) AIX lssrc로 NIS 서비스 상태 확인
    if command -v lssrc >/dev/null 2>&1; then
        local yp_lssrc=$(lssrc -s yp 2>/dev/null || echo "")
        if echo "$yp_lssrc" | grep -q "active"; then
            is_secure=false
            active_items+=("lssrc yp active")
        fi

        local ypserv_lssrc=$(lssrc -s ypserv 2>/dev/null || echo "")
        if echo "$ypserv_lssrc" | grep -q "active"; then
            is_secure=false
            active_items+=("lssrc ypserv active")
        fi
    fi

    # 3) NIS 도메인 확인
    local nis_domain=""
    if command -v domainname >/dev/null 2>&1; then
        nis_domain=$(domainname 2>/dev/null || echo "")
    fi
    if [ -n "$nis_domain" ] && [ "$nis_domain" != "(none)" ]; then
        nis_details="NIS 도메인: ${nis_domain}"
    fi

    # 4) /etc/defaultdomain 확인
    local default_domain=""
    if [ -f /etc/defaultdomain ]; then
        default_domain=$(cat /etc/defaultdomain 2>/dev/null || echo "")
    fi

    # 명령어 결과 수집
    local ps_raw=$(ps -ef 2>/dev/null | grep -Ei "ypserv|ypbind|yppasswdd" | grep -v grep || echo "No NIS processes found")
    local lssrc_raw=""
    if command -v lssrc >/dev/null 2>&1; then
        lssrc_raw="$(lssrc -s yp 2>/dev/null || echo "yp: service not found")"
    fi

    # 최종 판정
    if [ "$is_secure" = true ]; then
        diagnosis_result="GOOD"
        status="양호"
        if [ -n "$nis_details" ]; then
            inspection_summary="NIS 관련 서비스가 비활성화되어 있습니다. (${nis_details})"
        else
            inspection_summary="NIS 관련 서비스가 비활성화되어 있습니다."
        fi
        command_result="[Command: ps -ef | grep yp]${newline}${ps_raw}${newline}${newline}[Command: lssrc -s yp]${newline}${lssrc_raw}"
        command_executed="ps -ef | grep -Ei 'ypserv|ypbind'; lssrc -s yp; domainname"
    else
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="계정 정보 유출 위험이 있는 NIS 서비스가 활성화되어 있습니다: ${active_items[*]}"
        command_result="[Command: ps -ef | grep yp]${newline}${ps_raw}${newline}${newline}[Command: lssrc -s yp]${newline}${lssrc_raw}"
        command_executed="ps -ef | grep -Ei 'ypserv|ypbind'; lssrc -s yp; domainname"
    fi

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

    verify_result_saved "${ITEM_ID}"

    return 0
}

# ============================================================================
# 메인 실행
# ============================================================================

main() {
    show_diagnosis_start "${ITEM_ID}" "${ITEM_NAME}"

    check_disk_space

    diagnose

    show_diagnosis_complete "${ITEM_ID}" "${diagnosis_result:-UNKNOWN}"

    return 0
}

# 스크립트 직접 실행 시에만 진단 수행
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi
