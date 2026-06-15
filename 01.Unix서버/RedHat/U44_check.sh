#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-28
# ============================================================================
# [점검 항목 상세]
# @ID          : U-44
# @Category    : UNIX > 3. 서비스 관리
# @Platform    : RedHat
# @Severity    : 상
# @Title       : tftp, talk 서비스 비활성화
# @Description : 인증 절차가 없는 tftp와 보안에 취약한 talk 서비스 비활성화 점검
# ==============================================================================

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; LIB_DIR="${SCRIPT_DIR}/../../lib"
source "${LIB_DIR}/common.sh"; source "${LIB_DIR}/result_manager.sh"; source "${LIB_DIR}/output_mode.sh"; source "${LIB_DIR}/metadata_parser.sh"

ITEM_ID="U-44"; ITEM_NAME="tftp, talk 서비스 비활성화"; SEVERITY="(상)"

GUIDELINE_PURPOSE="안전하지 않거나 불필요한 서비스를 제거함으로써 시스템 보안성 및 리소스의 효율적 운용하기 위함"
GUIDELINE_THREAT="사용하지 않는 서비스나 취약점이 발표된 서비스 운용 시 공격 시도 가능한 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="tftp, talk, ntalk 서비스가 비활성화된 경우"
GUIDELINE_CRITERIA_BAD="tftp, talk, ntalk 서비스가 활성화된 경우"
GUIDELINE_REMEDIATION="불필요한 tftp, talk, ntalk 서비스 비활성화 설정"

diagnose() {
    local status="양호"; diagnosis_result="GOOD"
    local inspection_summary="tftp 및 talk 서비스가 비활성화되어 있습니다."
    local command_result=""
    
    # 1) xinetd 기반 서비스: disable 항목이 없거나 disable=no 이면 활성화 상태 (xinetd 기본값)
    local active_svcs=""
    local svc_file disabled
    for svc_file in /etc/xinetd.d/tftp /etc/xinetd.d/talk /etc/xinetd.d/ntalk; do
        [ -f "$svc_file" ] || continue
        disabled=$(grep -E '^[[:space:]]*disable' "$svc_file" 2>/dev/null | awk -F= '{gsub(/[[:space:]]/,"",$2); print $2}' | tail -1 || echo "")
        if [ "$disabled" != "yes" ]; then
            active_svcs="${active_svcs}${svc_file}(disable=${disabled:-없음}) "
        fi
    done

    # 2) systemd socket-activation 기반 tftp 확인
    local socket_check=""
    if command -v systemctl >/dev/null 2>&1; then
        local unit state
        for unit in tftp.socket tftp; do
            state=$(systemctl is-active "$unit" 2>/dev/null || echo "inactive")
            if [ "$state" = "active" ]; then
                socket_check="${socket_check}${unit}(active) "
            fi
        done
    fi

    # 3) 실행 중인 프로세스 확인
    local proc_check=$(ps -ef | grep -Ei "tftpd|talkd" | grep -v grep || echo "")

    if [ -n "$active_svcs" ] || [ -n "$socket_check" ] || [ -n "$proc_check" ]; then
        status="취약"; diagnosis_result="VULNERABLE"
        inspection_summary="보안에 취약한 tftp 또는 talk 서비스가 활성화되어 있습니다."
        command_result="활성 서비스/프로세스: [ ${active_svcs}${socket_check}${proc_check} ]"
    else
        command_result="tftp, talk 서비스가 모두 비활성화되어 있습니다."
    fi

    save_dual_result "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" "${inspection_summary}" "${command_result}" "grep -E '^[[:space:]]*disable' /etc/xinetd.d/{tftp,talk,ntalk} 2>/dev/null; systemctl is-active tftp.socket tftp; ps -ef | grep -Ei 'tftpd|talkd' | grep -v grep" "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
}
main() { diagnose; }; main "$@"
