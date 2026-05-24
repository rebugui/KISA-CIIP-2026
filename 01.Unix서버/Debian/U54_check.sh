#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : U-54
# @Category    : Unix Server
# @Platform    : Debian
# @Severity    : 중
# @Title       : 암호화되지 않는 FTP 서비스 비활성화
# @Description : 암호화되지 않은 FTP 서비스 실행 여부 확인
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


ITEM_ID="U-54"
ITEM_NAME="암호화되지 않는 FTP 서비스 비활성화"
SEVERITY="중"

# 가이드라인 정보
GUIDELINE_PURPOSE="암호화되지 않은 FTP 서비스를 비활성화함으로써 계정 및 중요 정보 유출 방지하기 위함"
GUIDELINE_THREAT="암호화되지 않은 FTP 서비스를 사용할 경우, 데이터가 평문으로 전송되어 비인가자가 스니핑을 통해 계정 및 중요 정보를 외부로 유출할 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="암호화되지 않은 FTP 서비스가 비활성화된 경우"
GUIDELINE_CRITERIA_BAD="암호화되지 않은 FTP 서비스가 활성화된 경우"
GUIDELINE_REMEDIATION="암호화되지 않은 FTP 서비스 중지 및 비활성화 설정"

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
    # 암호화되지 않은 FTP 서비스 실행 여부 확인

    local ftp_running=false
    local ftp_details=""
    local ftp_services_checked=""

    # 1) 일반 FTP 서비스 확인 (vsftpd, proftpd, pure-ftpd, wu-ftpd)
    local ftp_daemons=("vsftpd" "proftpd" "pure-ftpd" "wu-ftpd" "ftpd")

    for daemon in "${ftp_daemons[@]}"; do
        if systemctl list-unit-files | grep -q "^${daemon}.service"; then
            ftp_services_checked="${ftp_services_checked}${daemon} "
            local is_active=$(systemctl is-active "${daemon}" 2>/dev/null || echo "inactive")
            local is_enabled=$(systemctl is-enabled "${daemon}" 2>/dev/null || echo "disabled")

            if [ "$is_active" = "active" ]; then
                ftp_running=true
                ftp_details="${ftp_details}${daemon}: ${is_active} (enabled: ${is_enabled})${newline}"
            fi
        fi
    done || true

    # 2) inetd/xinetd 기반 FTP 확인
    if [ -f /etc/xinetd.d/ftp ]; then
        local xinetd_ftp=$(grep -E "^[\s]*disable" /etc/xinetd.d/ftp 2>/dev/null | awk '{print $2}')
        if [ "$xinetd_ftp" = "no" ]; then
            ftp_running=true
            ftp_details="${ftp_details}inetd FTP: 활성화 (disable=no)${newline}"
        fi
        ftp_services_checked="${ftp_services_checked}inetd-ftp "
    fi

    if [ -f /etc/inetd.conf ]; then
        if grep -q "^ftp" /etc/inetd.conf 2>/dev/null; then
            ftp_running=true
            ftp_details="${ftp_details}inetd.conf ftp: 활성화${newline}"
        fi
    fi

    # 3) 포트 확인 (FTP: 21)
    if command -v ss &>/dev/null; then
        local ftp_port=$(ss -tuln 2>/dev/null | grep ":21 " || echo "")
        if [ -n "$ftp_port" ]; then
            ftp_running=true
            ftp_details="${ftp_details}FTP 포트 21 활성화${newline}"
        fi
    fi

    command_executed="systemctl is-active vsftpd proftpd pure-ftpd; grep disable /etc/xinetd.d/ftp; ss -tuln | grep ':21 '"

    # 최종 판정
    if [ "$ftp_running" = false ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="암호화되지 않은 FTP 서비스가 비활성화되어 있습니다."
        command_result="[FTP Service Status]${newline}$(systemctl is-active ftpd 2>&1 || systemctl is-active vsftpd 2>&1 || systemctl is-active proftpd 2>&1 || echo 'FTP services not running')"
    else
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="암호화되지 않은 FTP 서비스가 활성화되어 있습니다. FTP는 평문으로 데이터를 전송하므로 SFTP/FTP over TLS로 전환하거나 서비스를 중지하세요."
        command_result="${ftp_details}"
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
