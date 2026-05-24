#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-04-20
# ============================================================================
# [점검 항목 상세]
# @ID          : U-54
# @Category    : UNIX > 4. 웹 서비스 관리
# @Platform    : RedHat
# @Severity    : 중
# @Title       : 암호화되지 않는 FTP 서비스 비활성화
# @Description : 암호화되지 않은 FTP 서비스 실행 여부 확인
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/metadata_parser.sh"

ITEM_ID="U-54"
ITEM_NAME="암호화되지 않는 FTP 서비스 비활성화"
SEVERITY="중"

# 가이드라인 정보
GUIDELINE_PURPOSE="암호화되지 않은 FTP 서비스를 비활성화함으로써 계정 및 중요 정보 유출 방지하기 위함"
GUIDELINE_THREAT="암호화되지 않은 FTP 서비스를 사용할 경우, 데이터가 평문으로 전송되어 비인가자가 스니핑을 통해 계정 및 중요 정보를 외부로 유출할 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="암호화되지 않은 FTP 서비스가 비활성화된 경우"
GUIDELINE_CRITERIA_BAD="암호화되지 않은 FTP 서비스가 활성화된 경우"
GUIDELINE_REMEDIATION="암호화되지 않은 FTP 서비스 중지 및 비활성화 설정"

diagnose() {
    local status="양호"
    diagnosis_result="GOOD"
    local inspection_summary="암호화되지 않은 FTP 서비스가 비활성화 되어 있습니다."
    local command_result=""
    local command_executed="systemctl is-active vsftpd proftpd pure-ftpd; cat /etc/xinetd.d/ftp; ss -tlnp | grep ':21'"

    local ftp_evidence=""

    # 1. vsftpd, proftpd, pure-ftpd 서비스 활성 상태 점검
    local ftp_daemons=("vsftpd" "proftpd" "pure-ftpd")
    for daemon in "${ftp_daemons[@]}"; do
        if systemctl is-active "${daemon}" >/dev/null 2>&1; then
            ftp_evidence+="[활성 데몬] ${daemon}, "
        fi
    done

    # 2. xinetd 기반 FTP 서비스 점검
    if [ -f "/etc/xinetd.d/ftp" ]; then
        local xinetd_disable=$(grep -v '^#' /etc/xinetd.d/ftp | grep -i 'disable' | head -n 1 || echo "")
        if echo "$xinetd_disable" | grep -qi 'disable.*=.*no'; then
            ftp_evidence+="[xinetd FTP 활성] /etc/xinetd.d/ftp disable=no, "
        fi
    fi

    # 3. 포트 21 리스닝 확인 (ss 명령)
    local port21_listening=$(ss -tlnp 2>/dev/null | grep ':21 ' || echo "")
    if [ -n "$port21_listening" ]; then
        ftp_evidence+="[포트 21 리스닝] ${port21_listening}, "
    fi

    # 4. 판정 로직
    if [ -n "$ftp_evidence" ]; then
        status="취약"
        diagnosis_result="VULNERABLE"
        inspection_summary="암호화되지 않은 FTP 서비스가 활성화 되어 있습니다."
        command_result="발견된 FTP 서비스: [ ${ftp_evidence} ]"
    else
        command_result="FTP 서비스가 비활성화 되어 있습니다."
    fi

    # [보정] JSON 파싱 에러 방지
    command_result=$(echo "$command_result" | tr -d '\n\r')

    save_dual_result \
        "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" \
        "${inspection_summary}" "${command_result}" "${command_executed}" \
        "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" \
        "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"

    verify_result_saved "${ITEM_ID}"
    return 0
}

main() {
    show_diagnosis_start "${ITEM_ID}" "${ITEM_NAME}"
    [ "$EUID" -ne 0 ] && { echo "root 권한이 필요합니다."; exit 1; }
    diagnose
    show_diagnosis_complete "${ITEM_ID}" "${diagnosis_result}"
    exit 0
}

main "$@"
