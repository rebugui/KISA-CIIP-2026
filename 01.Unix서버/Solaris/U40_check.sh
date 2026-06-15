#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : U-40
# @Category    : Unix Server
# @Platform    : Solaris
# @Severity    : 상
# @Title       : NFS 접근 통제
# @Description : NFS exports 설정 확인
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


ITEM_ID="U-40"
ITEM_NAME="NFS 접근 통제"
SEVERITY="상"

# 가이드라인 정보
GUIDELINE_PURPOSE="접근 권한이 없는 비인가자의 접근을 통제하기 위함"
GUIDELINE_THREAT="접근 통제 설정이 적절하지 않을 경우, 인증 절차 없이 비인가자가 디렉터리나 파일의 접근이 가능하며, 해당 공유 시스템에 원격으로 마운트하여 중요 파일을 변조하거나 유출할 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="접근 통제가 설정되어 있으며 NFS 설정 파일 접근 권한이 644 이하인 경우"
GUIDELINE_CRITERIA_BAD="접근 통제가 설정되어 있지 않고 NFS 설정 파일 접근 권한이 644를 초과하는 경우"
GUIDELINE_REMEDIATION="NFS 서비스를 사용하지 않는 경우 서비스 중지 및 비활성화 설정 불가피하게 사용 시 접근 통제 설정 및 NFS 설정 파일 접근 권한 644 설정"

# ============================================================================
# 진단 함수
# ============================================================================

# 공유 설정 라인 접근 통제 판정 (dfstab/share 출력 공용)
# $1: 공유 설정 텍스트, $2: 출처 라벨
judge_share_entries() {
    local src_label="$2"
    local line
    while IFS= read -r line; do
        [ -z "$line" ] && continue
        # 호스트 접근 제한 옵션(rw=호스트, ro=호스트, access=호스트) 존재 시 접근 통제 설정으로 인정
        if echo "$line" | grep -Eq '(rw|ro|access)=[^[:space:],]'; then
            continue
        fi
        # 접근 제한 없는 공유: 명시적 rw 또는 옵션 없음(기본 rw) → 전체 공개
        if echo "$line" | grep -Eq '(^|[[:space:],])rw($|[[:space:],"])'; then
            is_secure=false
            issues+=("${src_label} 전체 공개 쓰기(rw) 공유: $line")
        else
            is_secure=false
            issues+=("${src_label} 호스트 접근 제한 없는 공유: $line")
        fi
    done <<< "$1"
}

# 진단 수행
diagnose() {


    diagnosis_result="unknown"
    local status="미진단"
    local inspection_summary=""
    local command_result=""
    local command_executed=""
    local newline=$'\n'

    # NFS 접근 통제 확인
    local nfs_installed=false
    local is_secure=true
    local issues=()
    local exports_info=""

    # 1) Solaris 주 설정 파일 /etc/dfs/dfstab 공유 설정 확인
    if [ -f /etc/dfs/dfstab ]; then
        local dfstab_entries
        dfstab_entries=$(grep -v '^[[:space:]]*#' /etc/dfs/dfstab 2>/dev/null | grep -v '^[[:space:]]*$' || true)
        if [ -n "$dfstab_entries" ]; then
            nfs_installed=true
            exports_info="${exports_info}/etc/dfs/dfstab 공유(share) 설정 존재\\n${dfstab_entries}\\n\\n"
            judge_share_entries "$dfstab_entries" "dfstab"
        else
            exports_info="${exports_info}/etc/dfs/dfstab 공유(share) 설정 없음\\n"
        fi
    fi

    # 2) share 명령 출력 확인 (현재 공유 중인 자원)
    if command -v share >/dev/null 2>&1; then
        local share_output
        share_output=$(share 2>/dev/null || true)
        if [ -n "$share_output" ]; then
            nfs_installed=true
            exports_info="${exports_info}share 명령 공유 자원:\\n${share_output}\\n\\n"
            judge_share_entries "$share_output" "share"
        fi
    fi

    # 3) NFS 설정 파일 접근 권한 확인 (소유자 root + 644 이하)
    #    dfstab(영속 공유 설정) 및 sharetab(현재 공유 테이블) 점검
    local cfg
    for cfg in /etc/dfs/dfstab /etc/dfs/sharetab; do
        [ -f "$cfg" ] || continue
        local cfg_owner cfg_perms
        cfg_owner=$(stat -c '%U' "$cfg" 2>/dev/null || echo "")
        cfg_perms=$(stat -c '%a' "$cfg" 2>/dev/null || echo "")
        if [ "$cfg_owner" != "root" ] && [ -n "$cfg_owner" ]; then
            is_secure=false
            issues+=("${cfg} 소유자가 root가 아님(${cfg_owner})")
        fi
        if [ -n "$cfg_perms" ]; then
            # 644(rw-r--r--) 초과 비트(그룹/기타 쓰기, 실행, 특수비트) 존재 여부
            if [ $(( 8#${cfg_perms} & 8#7133 )) -ne 0 ]; then
                is_secure=false
                issues+=("${cfg} 접근 권한이 644를 초과함(${cfg_perms})")
            fi
        else
            is_secure=false
            issues+=("${cfg} 접근 권한 확인 불가")
        fi
        exports_info="${exports_info}${cfg} 소유자·권한: ${cfg_owner:-확인불가} ${cfg_perms:-확인불가}\\n"
    done

    # 4) NFS 서버 SMF 서비스 상태 확인 (svcs, U-39와 동일 FMRI)
    if command -v svcs >/dev/null 2>&1; then
        local svc_state
        svc_state=$(svcs -H -o state svc:/network/nfs/server 2>/dev/null || echo "")
        exports_info="${exports_info}SMF 서비스 network/nfs/server 상태: ${svc_state:-미등록}\\n"
        if [ "$svc_state" = "online" ]; then
            nfs_installed=true
        fi
    elif command -v ps >/dev/null 2>&1; then
        # svcs 미지원 환경: NFS 서버 데몬 프로세스 확인 (fallback)
        local ps_output
        ps_output=$(ps -ef 2>/dev/null | grep -E 'nfsd|mountd' | grep -vE 'automountd|grep' || true)
        if [ -n "$ps_output" ]; then
            nfs_installed=true
            exports_info="${exports_info}NFS 서버 데몬(nfsd/mountd) 실행 중\\n${ps_output}\\n"
        fi
    fi

    # 최종 판정
    if [ "$nfs_installed" = false ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="NFS 서비스 미사용"
        command_result="NFS service disabled${newline}${exports_info}"
        command_executed="svcs -H -o state svc:/network/nfs/server; share; cat /etc/dfs/dfstab"
    elif [ "$is_secure" = true ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="NFS 접근 통제 적절히 설정됨"
        command_result="${exports_info}"
        command_executed="cat /etc/dfs/dfstab; share; svcs -H -o state svc:/network/nfs/server"
    else
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="NFS 접근 통제 미흡: ${issues[*]}"
        command_result="${exports_info}"
        command_executed="cat /etc/dfs/dfstab; share; svcs -H -o state svc:/network/nfs/server"
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
