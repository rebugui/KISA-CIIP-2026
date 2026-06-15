#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : U-34
# @Category    : Unix Server
# @Platform    : Solaris
# @Severity    : 상
# @Title       : Finger 서비스 비활성화
# @Description : Finger 서비스 활성화 여부 점검 (svcs/inetadm/inetd.conf)
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


ITEM_ID="U-34"
ITEM_NAME="Finger 서비스 비활성화"
SEVERITY="상"

# 가이드라인 정보
GUIDELINE_PURPOSE="Finger 서비스를 통해 네트워크 외부에서 해당 시스템에 등록된 사용자 정보를 확인할 수 있어 비인가자에게 사용자 정보가 조회되는 것을 방지하기 위함"
GUIDELINE_THREAT="Finger 서비스가 활성화되어 있을 경우, 비인가자가 Finger 서비스를 사용하여 사용자 정보를 조회한 후 비밀번호 공격을 통해 계정을 탈취할 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="Finger 서비스가 비활성화된 경우"
GUIDELINE_CRITERIA_BAD="Finger 서비스가 활성화된 경우"
GUIDELINE_REMEDIATION="Finger 서비스 비활성화 설정"

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
    # Solaris: SMF(svcs/inetadm) 및 레거시 inetd.conf에서 Finger 서비스 활성화 여부 확인

    local probe_available=false
    local finger_active=false
    local active_details=""
    local evidence=""

    # 1) Solaris 10 이상: svcs로 finger 서비스 상태 확인
    if command -v svcs >/dev/null 2>&1; then
        probe_available=true
        local svcs_out=""
        svcs_out=$(svcs -H -o state,fmri 2>/dev/null | grep finger || true)
        if [ -n "$svcs_out" ]; then
            evidence="${evidence}[Command: svcs -H -o state,fmri | grep finger]${newline}${svcs_out}${newline}"
            if printf '%s\n' "$svcs_out" | awk '{print $1}' | grep -q "^online$"; then
                finger_active=true
                active_details="${active_details}svcs: finger 서비스 online 상태. "
            fi
        else
            evidence="${evidence}[Command: svcs -H -o state,fmri | grep finger]${newline}finger 서비스 미등록${newline}"
        fi
    fi

    # 2) Solaris 10 이상: inetadm으로 finger 활성화 여부 확인
    if command -v inetadm >/dev/null 2>&1; then
        probe_available=true
        local inetadm_out=""
        inetadm_out=$(inetadm 2>/dev/null | grep finger || true)
        if [ -n "$inetadm_out" ]; then
            evidence="${evidence}[Command: inetadm | grep finger]${newline}${inetadm_out}${newline}"
            if printf '%s\n' "$inetadm_out" | awk '{print $1}' | grep -q "^enabled$"; then
                finger_active=true
                active_details="${active_details}inetadm: finger 서비스 enabled 상태. "
            fi
        else
            evidence="${evidence}[Command: inetadm | grep finger]${newline}finger 서비스 미등록${newline}"
        fi
    fi

    # 3) 레거시(Solaris 5.9 이하): /etc/inetd.conf의 주석 처리되지 않은 finger 항목 확인
    if [ -f /etc/inetd.conf ]; then
        probe_available=true
        local inetd_out=""
        inetd_out=$(grep "^[[:space:]]*finger" /etc/inetd.conf 2>/dev/null || true)
        if [ -n "$inetd_out" ]; then
            finger_active=true
            active_details="${active_details}/etc/inetd.conf: finger 항목 활성화. "
            evidence="${evidence}[Command: grep '^finger' /etc/inetd.conf]${newline}${inetd_out}${newline}"
        else
            evidence="${evidence}[Command: grep '^finger' /etc/inetd.conf]${newline}활성화된 finger 항목 없음${newline}"
        fi
    fi

    # 4) 보조 증적: 79/tcp 포트 리슨 여부
    if command -v netstat >/dev/null 2>&1; then
        local netstat_out=""
        netstat_out=$(netstat -an 2>/dev/null | grep '\.79 ' || true)
        if [ -n "$netstat_out" ]; then
            evidence="${evidence}[Command: netstat -an | grep '\\.79 ']${newline}${netstat_out}${newline}"
        else
            evidence="${evidence}[Command: netstat -an | grep '\\.79 ']${newline}79번 포트 리슨 없음${newline}"
        fi
    fi

    local probe_cmds="svcs -H -o state,fmri | grep finger; inetadm | grep finger; grep '^finger' /etc/inetd.conf; netstat -an | grep '\\.79 '"

    # 최종 판정
    if [ "$finger_active" = true ]; then
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="Finger 서비스가 활성화되어 있습니다. ${active_details}Finger 서비스를 비활성화하시기 바랍니다."
        command_result="${evidence}"
        command_executed="${probe_cmds}"
    elif [ "$probe_available" = true ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="Finger 서비스가 비활성화되어 있습니다."
        command_result="${evidence}"
        command_executed="${probe_cmds}"
    else
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="svcs/inetadm 명령과 /etc/inetd.conf 파일을 확인할 수 없어 Finger 서비스 상태를 판단할 수 없습니다. 수동으로 점검하시기 바랍니다."
        command_result="svcs/inetadm 명령 없음, /etc/inetd.conf 파일 없음${newline}${evidence}"
        command_executed="${probe_cmds}"
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
