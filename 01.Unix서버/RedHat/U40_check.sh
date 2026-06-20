#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-28
# ============================================================================
# [점검 항목 상세]
# @ID          : U-40
# @Category    : UNIX > 3. 서비스 관리
# @Platform    : RedHat
# @Severity    : 상
# @Title       : NFS 접근 통제
# @Description : NFS 공유 설정 시 특정 호스트에 대한 접근 제한 설정 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

set -euo pipefail

# 스크립트 디렉토리 설정
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../../lib"

# 필수 라이브러리 로드
source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/metadata_parser.sh"

ITEM_ID="U-40"
ITEM_NAME="NFS 접근 통제"
SEVERITY="상"

# 가이드라인 정보
GUIDELINE_PURPOSE="접근 권한이 없는 비인가자의 접근을 통제하기 위함"
GUIDELINE_THREAT="접근 통제 설정이 적절하지 않을 경우, 인증 절차 없이 비인가자가 디렉터리나 파일의 접근이 가능하며, 해당 공유 시스템에 원격으로 마운트하여 중요 파일을 변조하거나 유출할 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="접근 통제가 설정되어 있으며 NFS 설정 파일 접근 권한이 644 이하인 경우"
GUIDELINE_CRITERIA_BAD="접근 통제가 설정되어 있지 않고 NFS 설정 파일 접근 권한이 644를 초과하는 경우"
GUIDELINE_REMEDIATION="NFS 서비스를 사용하지 않는 경우 서비스 중지 및 비활성화 설정 불가피하게 사용 시 접근 통제 설정 및 NFS 설정 파일 접근 권한 644 설정"

diagnose() {
    # [중요] 파싱 에러 방지를 위한 기존 변수 초기값 유지
    local status="양호"
    diagnosis_result="GOOD"
    local inspection_summary="NFS 접근 통제 설정이 적절하게 이루어져 있습니다."
    local command_result=""
    local command_executed="cat /etc/exports /etc/exports.d/*.exports 2>/dev/null; stat -c '%a %U' /etc/exports /etc/exports.d/*.exports 2>/dev/null; systemctl is-active nfs-server 2>/dev/null; ss -tuln 2>/dev/null | grep -E ':2049|:20048'"

    # 1. 실제 데이터 추출
    # exports 후보 파일 수집: /etc/exports 및 /etc/exports.d/*.exports (RHEL: exports(5) drop-in)
    local exports_files=()
    if [ -f /etc/exports ]; then
        exports_files+=("/etc/exports")
    fi
    if [ -d /etc/exports.d ]; then
        local _ef
        for _ef in /etc/exports.d/*.exports; do
            [ -f "$_ef" ] && exports_files+=("$_ef")
        done
    fi

    # NFS 서비스/포트 활성 여부 (exports 파일 부재 시 fall-through 차단)
    local nfs_daemon_active=false
    if systemctl is-active nfs-server &>/dev/null || systemctl is-active nfs-kernel-server &>/dev/null; then
        nfs_daemon_active=true
    fi
    local nfs_port_listening=false
    if command -v ss &>/dev/null; then
        if ss -tuln 2>/dev/null | grep -qE ':2049 |:20048 '; then
            nfs_port_listening=true
        fi
    fi

    if [ "${#exports_files[@]}" -gt 0 ]; then
        local unsafe_configs=""
        local perm_issues=""
        local summary_owner_perm=""
        local summary_share=""
        local exports_file
        for exports_file in "${exports_files[@]}"; do
            # 와일드카드(*)를 사용하여 모든 호스트에 개방된 설정 탐색
            local _unsafe
            _unsafe=$(grep -v "^#" "$exports_file" | grep "*" || echo "")
            if [ -n "$_unsafe" ]; then
                unsafe_configs="${unsafe_configs:+${unsafe_configs}; }[${exports_file}] ${_unsafe}"
            fi

            # 설정 파일 권한 점검 (소유자 root + 644 초과 비트 없음)
            local file_owner
            file_owner=$(stat -c '%U' "$exports_file" 2>/dev/null || echo "")
            local file_perms
            file_perms=$(stat -c '%a' "$exports_file" 2>/dev/null || echo "")
            if [ "$file_owner" != "root" ]; then
                perm_issues="${perm_issues:+${perm_issues}, }[${exports_file}] 소유자가 root가 아님(${file_owner:-확인불가})"
            fi
            if [ -n "$file_perms" ]; then
                # 644(rw-r--r--)를 초과하는 비트(그룹/기타 쓰기, 실행, 특수비트) 존재 여부 (비트 연산)
                if [ $(( 8#${file_perms} & 8#7133 )) -ne 0 ]; then
                    perm_issues="${perm_issues:+${perm_issues}, }[${exports_file}] 파일 권한이 644를 초과함(${file_perms})"
                fi
            else
                perm_issues="${perm_issues:+${perm_issues}, }[${exports_file}] 파일 권한 확인 불가"
            fi
            summary_owner_perm="${summary_owner_perm:+${summary_owner_perm} | }${exports_file}: ${file_owner:-확인불가} ${file_perms:-확인불가}"
            local _share
            _share=$(grep -v "^#" "$exports_file" | xargs 2>/dev/null || echo "설정 없음")
            summary_share="${summary_share:+${summary_share} | }${exports_file}: ${_share:-설정 없음}"
        done

        # 2. 판정 로직 (접근 통제 + 설정 파일 권한)
        if [ -n "$unsafe_configs" ] || [ -n "$perm_issues" ]; then
            status="취약"
            diagnosis_result="VULNERABLE"
            local vuln_detail=""
            [ -n "$unsafe_configs" ] && vuln_detail="NFS 공유가 모든 호스트(*)에 허용됨"
            [ -n "$perm_issues" ] && vuln_detail="${vuln_detail:+${vuln_detail}; }${perm_issues}"
            inspection_summary="NFS 접근 통제 미흡: ${vuln_detail}"
            command_result="취약 설정 내역: [ ${unsafe_configs:-없음} ] / 파일 소유자·권한: [ ${summary_owner_perm:-확인불가} ]"
        else
            command_result="공유 설정 내역: [ ${summary_share} ] / 파일 소유자·권한: [ ${summary_owner_perm} ]"
        fi
    else
        # exports 파일 없음 — NFS 데몬/포트가 활성이면 정적 판정 불가 → MANUAL
        if [ "$nfs_daemon_active" = true ] || [ "$nfs_port_listening" = true ]; then
            status="수동진단"
            diagnosis_result="MANUAL"
            inspection_summary="NFS 서비스/포트가 활성 상태이나 /etc/exports 및 /etc/exports.d/*.exports를 확인할 수 없어 접근 통제 설정의 정적 판정 불가 (수동 점검 필요: exportfs -v)"
            command_result="NFS 설정 파일 미존재(/etc/exports, /etc/exports.d/*.exports) / NFS daemon active=${nfs_daemon_active}, port listening=${nfs_port_listening}"
        else
            command_result="NFS 설정 파일(/etc/exports, /etc/exports.d/*.exports)이 존재하지 않으며 NFS 서비스/포트도 비활성 상태입니다."
        fi
    fi

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
