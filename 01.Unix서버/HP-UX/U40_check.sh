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
# @Platform    : HP-UX
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

    # 1) NFS 서비스 설치 확인
    if [ -f /etc/exports ]; then
        nfs_installed=true
        exports_info="NFS exports 파일 존재\\n\\n"

        # exports 파일 내용 확인
        if [ -s /etc/exports ]; then
            exports_info="${exports_info}$(cat /etc/exports)\\n\\n"

            # 각 exports 라인 확인
            while IFS= read -r line; do
                # 주석和无용行 무시
                [[ "$line" =~ ^#.*$ ]] && continue
                [[ -z "$line" ]] && continue

                # 취약한 옵션 확인
                if ! echo "$line" | grep -q "ro"; then
                    if echo "$line" | grep -q "rw"; then
                        is_secure=false
                        issues+=("쓰기 권한(rw) 허용됨: $line")
                    fi
                fi

                # root_squash 확인 (없으면 취약)
                if ! echo "$line" | grep -q "root_squash"; then
                    if echo "$line" | grep -q "no_root_squash"; then
                        is_secure=false
                        issues+=("root 권한 승급 가능(no_root_squash): $line")
                    else
                        # 기본값은 root_squash지만 명시적인 것이 좋음
                        issues+=("root_squash 옵션 미명시: $line")
                    fi
                fi

                # sync 확인
                if ! echo "$line" | grep -q "sync"; then
                    if echo "$line" | grep -q "async"; then
                        issues+=("비동기 모드(async) 사용: $line")
                    fi
                fi

                # insecure 옵션 확인 (1024 이상 포트 허용)
                if echo "$line" | grep -q "insecure"; then
                    is_secure=false
                    issues+=("insecure 옵션 사용: $line")
                fi
            done < /etc/exports || true
        else
            exports_info="${exports_info}exports 파일이 비어있음 (안전)\\n"
        fi
    fi

    # 2) HP-UX 주 설정 파일 /etc/dfs/dfstab 공유 설정 확인
    if [ -f /etc/dfs/dfstab ]; then
        local dfstab_entries
        dfstab_entries=$(grep -v '^[[:space:]]*#' /etc/dfs/dfstab 2>/dev/null | grep -v '^[[:space:]]*$' || true)
        if [ -n "$dfstab_entries" ]; then
            nfs_installed=true
            exports_info="${exports_info}/etc/dfs/dfstab 공유(share) 설정 존재\\n${dfstab_entries}\\n\\n"
            while IFS= read -r line; do
                [ -z "$line" ] && continue
                # 호스트 접근 제한 옵션(rw=호스트, ro=호스트, access=호스트) 존재 시 접근 통제 설정으로 인정
                if echo "$line" | grep -Eq '(rw|ro|access)=[^[:space:],]'; then
                    continue
                fi
                # 접근 제한 없는 공유: 명시적 rw 또는 옵션 없음(기본 rw) → 전체 공개
                if echo "$line" | grep -Eq '(^|[[:space:],])rw($|[[:space:],])'; then
                    is_secure=false
                    issues+=("dfstab 전체 공개 쓰기(rw) 공유: $line")
                else
                    is_secure=false
                    issues+=("dfstab 호스트 접근 제한 없는 공유: $line")
                fi
            done <<< "$dfstab_entries"
        else
            exports_info="${exports_info}/etc/dfs/dfstab 공유(share) 설정 없음\\n"
        fi
    fi

    # 2-1) NFS 서비스 실행 확인 (HP-UX: /sbin/init.d/nfs.server 사용)
    if /sbin/init.d/nfs.server status 2>/dev/null | grep -q "running" &>/dev/null; then
        nfs_installed=true
        exports_info="${exports_info}NFS 서비스 실행 중\\n"
    fi

    # 3) 포트 확인 (NFS: 2049, mountd: 20048)
    if command -v ss &>/dev/null; then
        local nfs_port=$(ss -tuln | grep -E ":2049 |:20048 " || echo "")
        if [ -n "$nfs_port" ]; then
            nfs_installed=true
            exports_info="${exports_info}NFS 포트 활성화 (2049/20048)\\n"
        fi
    fi

    # 4) NFS 설정 파일 접근 권한 확인 (가이드 기준: 644 이하, group/other 쓰기 금지)
    #    NFS 사용 중일 때만 검사 (HP-UX: /etc/dfs/dfstab, 호환: /etc/exports)
    if [ "$nfs_installed" = true ]; then
        local nfs_conf
        for nfs_conf in /etc/dfs/dfstab /etc/exports; do
            [ -f "$nfs_conf" ] || continue
            local conf_perms=$(perl -e '@s=stat(shift); printf "%04o\n", $s[2] & 07777' "$nfs_conf" 2>/dev/null || true)
            if [[ ! "$conf_perms" =~ ^[0-7]{3,4}$ ]]; then
                # 권한 확인 불가 → 증거 미확보, 보수적으로 issue 기록(수동 확인 유도)
                issues+=("${nfs_conf} 권한 확인 불가 (perl stat 실패)")
                exports_info="${exports_info}${nfs_conf} 권한 확인 불가\\n"
                continue
            fi
            exports_info="${exports_info}${nfs_conf} 권한: ${conf_perms}\\n"
            # 644 초과(=group/other 쓰기 비트 포함 등 644에 없는 비트) → 취약
            if [ "$(( 8#$conf_perms & ~8#644 & 07777 ))" -ne 0 ]; then
                is_secure=false
                issues+=("${nfs_conf} 권한 644 초과 (${conf_perms})")
            fi
        done
    fi

    # 최종 판정
    if [ "$nfs_installed" = false ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="NFS 서비스 미사용"
        local nfs_check=$(/sbin/init.d/nfs.server status 2>/dev/null | head -3; ss -tuln 2>/dev/null | grep -E ':2049|:20048' || echo "NFS not running")
        command_result="${nfs_check}"
        command_executed="cat /etc/dfs/dfstab /etc/exports 2>/dev/null; /sbin/init.d/nfs.server status 2>/dev/null; ss -tuln | grep -E ':2049|:20048'"
    elif [ "$is_secure" = true ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="NFS 접근 통제 적절히 설정됨"
        command_result="${exports_info}"
        command_executed="cat /etc/dfs/dfstab /etc/exports 2>/dev/null; /sbin/init.d/nfs.server status 2>/dev/null"
    else
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="NFS 접근 통제 미흡: ${issues[*]}"
        command_result="${exports_info}"
        command_executed="cat /etc/dfs/dfstab /etc/exports 2>/dev/null; exportfs -v 2>/dev/null"
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
