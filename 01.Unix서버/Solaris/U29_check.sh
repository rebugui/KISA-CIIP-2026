#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : U-29
# @Category    : Unix Server
# @Platform    : Solaris
# @Severity    : 하
# @Title       : hosts.lpd 파일 소유자 및 권한 설정
# @Description : LPD 설정 확인
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


ITEM_ID="U-29"
ITEM_NAME="hosts.lpd 파일 소유자 및 권한 설정"
SEVERITY="하"

# 가이드라인 정보
GUIDELINE_PURPOSE="비인가자의 임의적인 /etc/hosts.lpd 변조를 막기 위해 /etc/hosts.lpd 파일 제거 또는 소유자 및 권한 관리하기 위함"
GUIDELINE_THREAT="/etc/hosts.lpd 파일의 접근 권한이 적절하지 않을 경우, 비인가자가 /etc/hosts.lpd 파일을 수정하여 허용된 사용자의 서비스를 방해할 수 있으며, 호스트 정보를 획득할 수 있는 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="/etc/hosts.lpd 파일이 존재하지 않거나, 불가피하게 사용 시 /etc/hosts.lpd 파일의 소유자가 root이고, 권한이 600 이하인 경우"
GUIDELINE_CRITERIA_BAD="/etc/hosts.lpd 파일이 존재하며, 파일의 소유자가 root가 아니거나, 권한이 600 이하가 아닌 경우"
GUIDELINE_REMEDIATION="/etc/hosts.lpd 파일 제거 또는 /etc/hosts.lpd 파일 소유자 및 권한 변경 설정"

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
    # /etc/hosts.lpd 파일 소유자 및 권한 설정 확인 (LPD 라인 프린터 데몬)

    local hosts_lpd_exists=0
    local hosts_lpd_secure=0
    local hosts_lpd_details=""

    # Capture ls and svcs output
    local hosts_lpd_ls=$(ls -l /etc/hosts.lpd 2>&1)
    local cups_status=$(svcs cups 2>/dev/null | head -5 || echo "CUPS service not found")
    command_result="[Command: ls -l /etc/hosts.lpd]${newline}${hosts_lpd_ls}${newline}${newline}[Command: svcs cups]${newline}${cups_status}"

    # /etc/hosts.lpd 파일 확인
    if [ -f "/etc/hosts.lpd" ]; then
        ((hosts_lpd_exists++)) || true
        local perms=$(perl -e 'if (-f $ARGV[0]) { printf "%04o\n", (stat($ARGV[0]))[2] & 07777; }' "/etc/hosts.lpd" 2>/dev/null)
        local owner=$(perl -e 'if (-f $ARGV[0]) { $uid = (stat($ARGV[0]))[4]; $gid = (stat($ARGV[0]))[5]; $user = getpwuid($uid); $group = getgrgid($gid); print "$user:$group\n"; }' "/etc/hosts.lpd" 2>/dev/null)

        # 보안 설정 확인: 소유자 root (그룹은 기준에 없음, Solaris 기본 root:sys도 양호) 및 권한 600 이하
        if [ "${owner%%:*}" = "root" ]; then
            if [ "$perms" = "0600" ] || [ "$perms" = "0400" ]; then
                ((hosts_lpd_secure++)) || true
                hosts_lpd_details="/etc/hosts.lpd: 존재, 소유자: ${owner}, 권한: ${perms} (보안 양호)"
            else
                hosts_lpd_details="/etc/hosts.lpd: 존재, 소유자: ${owner}, 권한: ${perms} (권한 취약 - 600 또는 400 권장)"
            fi
        else
            hosts_lpd_details="/etc/hosts.lpd: 존재, 소유자: ${owner} (소유자 root 아님 - 취약)"
        fi
    fi

    # LPD 서비스 실행 여부 확인 (Solaris: svcs 사용)
    local lpd_running=0
    if command -v lpstat &>/dev/null || svcs cups 2>/dev/null | grep -q online || svcs lpd 2>/dev/null | grep -q online; then
        ((lpd_running++)) || true
    fi

    # 결과 판정
    if [ "$hosts_lpd_exists" -eq 0 ]; then
        if [ "$lpd_running" -eq 0 ]; then
            # LPD 서비스 미사용 및 파일 없음
            diagnosis_result="GOOD"
            status="양호"
            inspection_summary="LPD 서비스 미사용 및 hosts.lpd 파일 없음 (보안 양호)"
            command_result="hosts.lpd: [not found], LPD: [not used]"
            command_executed="ls -l /etc/hosts.lpd 2>/dev/null; svcs cups lpd 2>/dev/null | grep online"
        else
            # LPD 서비스 사용 중이나 hosts.lpd 없음 (최신 시스템은 CUPS 사용)
            diagnosis_result="GOOD"
            status="양호"
            inspection_summary="LPD/CUPS 서비스 사용 중이나 hosts.lpd 파일 없음 (최신 시스템에서는 정상)"
            command_result="hosts.lpd: [not found], LPD/CUPS: [in use]"
            command_executed="ls -l /etc/hosts.lpd 2>/dev/null; svcs cups 2>/dev/null | grep online"
        fi
    else
        # hosts.lpd 파일 존재
        if [ "$hosts_lpd_secure" -gt 0 ]; then
            diagnosis_result="GOOD"
            status="양호"
            inspection_summary="${hosts_lpd_details}"
            command_result="${hosts_lpd_details}"
            command_executed="stat -c '%a:%U:%G' /etc/hosts.lpd 2>/dev/null"
        else
            diagnosis_result="VULNERABLE"
            status="취약"
            inspection_summary="${hosts_lpd_details} (소유자 root 및 권한 600 이하 필요)"
            command_result="${hosts_lpd_details}"
            command_executed="stat -c '%a:%U:%G' /etc/hosts.lpd 2>/dev/null"
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
