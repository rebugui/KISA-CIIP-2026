#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.2
# @Last Updated: 2026-06-11
# ============================================================================
# [점검 항목 상세]
# @ID          : U-43
# @Category    : Unix Server
# @Platform    : HP-UX
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

# 진단 수행
diagnose() {

    diagnosis_result="unknown"
    local status="미진단"
    local inspection_summary=""
    local command_result=""
    local command_executed=""
    local newline=$'\n'

    # NIS(yp) 데몬 활성화 여부 점검
    local is_secure=true
    local probe_available=false
    local service_status=""
    local active_items=()

    # 확인 대상 NIS 데몬: ypserv, ypbind, ypxfrd, rpc.yppasswdd, rpc.ypupdated
    local nis_pattern='ypserv|ypbind|ypxfrd|yppasswdd|ypupdated'

    # 1) NIS 프로세스 확인 (주 판단 기준)
    local nis_procs=""
    if command -v ps >/dev/null 2>&1; then
        probe_available=true
        nis_procs=$(ps -ef 2>/dev/null | grep -E "${nis_pattern}" | grep -v grep || echo "")
        if [ -n "$nis_procs" ]; then
            is_secure=false
            active_items+=("NIS 프로세스 실행 중")
            service_status="${service_status}[ps -ef NIS 프로세스]${newline}${nis_procs}${newline}"
        else
            service_status="${service_status}[ps -ef NIS 프로세스] 실행 중인 NIS 데몬 없음${newline}"
        fi
    fi

    # 2) /etc/rc.config.d/namesvrs 의 NIS_* 설정 플래그 확인 (증적)
    if [ -f /etc/rc.config.d/namesvrs ]; then
        local namesvrs_flags=""
        namesvrs_flags=$(grep -E "^[[:space:]]*NIS_" /etc/rc.config.d/namesvrs 2>/dev/null || echo "")
        if [ -n "$namesvrs_flags" ]; then
            service_status="${service_status}[/etc/rc.config.d/namesvrs NIS_* 설정]${newline}${namesvrs_flags}${newline}"
        else
            service_status="${service_status}[/etc/rc.config.d/namesvrs] NIS_* 설정 항목 없음${newline}"
        fi
    else
        service_status="${service_status}[/etc/rc.config.d/namesvrs] 파일이 존재하지 않습니다.${newline}"
    fi

    # 최종 판정
    if [ "$probe_available" = false ]; then
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="ps 명령을 사용할 수 없어 NIS 서비스 활성화 여부를 자동 확인할 수 없습니다. 수동 점검이 필요합니다."
        command_result="NIS 프로세스 확인 명령(ps)을 사용할 수 없습니다.${newline}${service_status}"
        command_executed="command -v ps; grep -E '^NIS_' /etc/rc.config.d/namesvrs"
    elif [ "$is_secure" = true ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="NIS 관련 서비스(ypserv, ypbind 등)가 비활성화되어 있습니다."
        command_result="${service_status}"
        command_executed="ps -ef | grep -E '${nis_pattern}' | grep -v grep; grep -E '^NIS_' /etc/rc.config.d/namesvrs"
    else
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="계정 정보 유출 위험이 있는 NIS 서비스가 활성화되어 있습니다: ${active_items[*]}"
        command_result="${service_status}"
        command_executed="ps -ef | grep -E '${nis_pattern}' | grep -v grep; grep -E '^NIS_' /etc/rc.config.d/namesvrs"
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
