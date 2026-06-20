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
# @Platform    : AIX
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
    local conf_checked=false
    local issues=()
    local exports_info=""

    # 1) NFS 서비스 설치 확인
    if [ -f /etc/exports ]; then
        nfs_installed=true
        conf_checked=true
        exports_info="NFS exports 파일 존재\\n\\n"

        # /etc/exports 파일 권한 확인 (644 이하 요구)
        # perl 미가용/실패 시 권한 확인 불가 → 정규식 가드에서 탈락하여 안전 측(취약) 판정
        local exports_perms=$(perl -e '@s=stat(shift); printf "%04o", $s[2] & 07777' /etc/exports 2>/dev/null || true)
        exports_info="${exports_info}/etc/exports 권한: ${exports_perms:-확인불가}\\n"
        if [[ "$exports_perms" =~ ^[0-7]{3,4}$ ]] && [ $(( 8#${exports_perms} & ~(8#644) & 8#7777 )) -eq 0 ]; then
            :
        else
            is_secure=false
            issues+=("/etc/exports 권한 ${exports_perms:-확인불가} (644 초과 또는 확인불가)")
        fi

        # exports 파일 내용 확인
        if [ -s /etc/exports ]; then
            exports_info="${exports_info}$(cat /etc/exports)\\n\\n"

            # 각 exports 라인 확인
            while IFS= read -r line; do
                # 주석和无용行 무시
                [[ "$line" =~ ^#.*$ ]] && continue
                [[ -z "$line" ]] && continue

                # 옵션 부분만 추출 (첫 필드는 공유 경로 - 경로 문자열 'ro' 오탐 방지)
                local opts_part=$(echo "$line" | awk '{$1=""; print $0}')

                # 모든 호스트('*') 공유 확인
                if echo "$opts_part" | grep -Eq '(^|[[:space:]])\*|=\*' ; then
                    is_secure=false
                    issues+=("모든 호스트(*)에 공유 허용: $line")
                fi

                # 취약한 옵션 확인 (정확한 토큰 매칭: no_root_squash 내 'ro' 오탐 방지)
                if ! echo "$opts_part" | grep -Eq '(^|[(,[:space:]])-?ro($|[),[:space:]])'; then
                    if echo "$opts_part" | grep -Eq '(^|[(,[:space:]])-?rw($|[),=[:space:]])'; then
                        is_secure=false
                        issues+=("쓰기 권한(rw) 허용됨: $line")
                    fi
                fi

                # root_squash 확인 (no_root_squash 정확 토큰 매칭 우선)
                if echo "$opts_part" | grep -Eq '(^|[(,[:space:]])no_root_squash($|[),[:space:]])'; then
                    is_secure=false
                    issues+=("root 권한 승급 가능(no_root_squash): $line")
                elif ! echo "$opts_part" | grep -Eq '(^|[(,[:space:]])root_squash($|[),[:space:]])'; then
                    # 기본값은 root_squash지만 명시적인 것이 좋음
                    issues+=("root_squash 옵션 미명시: $line")
                fi

                # sync 확인 (async 정확 토큰 매칭)
                if echo "$opts_part" | grep -Eq '(^|[(,[:space:]])async($|[),[:space:]])'; then
                    issues+=("비동기 모드(async) 사용: $line")
                fi

                # insecure 옵션 확인 (1024 이상 포트 허용)
                if echo "$opts_part" | grep -Eq '(^|[(,[:space:]])insecure($|[),[:space:]])'; then
                    is_secure=false
                    issues+=("insecure 옵션 사용: $line")
                fi
            done < /etc/exports || true
        else
            exports_info="${exports_info}exports 파일이 비어있음 (안전)\\n"
        fi
    fi

    # 2) NFS 서비스 실행 확인 (AIX: nfsd)
    local nfsd_lssrc=$(lssrc -s nfsd 2>/dev/null || echo "")
    if echo "$nfsd_lssrc" | grep -q "active"; then
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

    # 3-1) NFS 서비스는 활성이지만 /etc/exports 가 존재하지 않는 경우:
    #      AIX는 exportfs -i (런타임, /etc/xtab 만) 또는 mknfsexp 로 /etc/exports 미보존 공유가 가능.
    #      접근 통제/644 권한을 정적으로 입증할 수 없으므로 활성 공유를 수집하여 수동 판정으로 회부.
    if [ "$nfs_installed" = true ] && [ "$conf_checked" = false ]; then
        local active_shares=""
        if command -v exportfs &>/dev/null; then
            active_shares=$(exportfs -v 2>/dev/null || true)
        fi
        if [ -z "$active_shares" ] && [ -f /etc/xtab ]; then
            active_shares=$(cat /etc/xtab 2>/dev/null || true)
        fi
        if [ -z "$active_shares" ] && command -v showmount &>/dev/null; then
            active_shares=$(showmount -e 2>/dev/null || true)
        fi
        if [ -n "$active_shares" ]; then
            exports_info="${exports_info}활성 공유 목록(/etc/exports 부재, 런타임 공유 추정):\\n${active_shares}\\n"
        else
            exports_info="${exports_info}NFS 서비스 활성 상태이나 /etc/exports 부재, 활성 공유 수집 실패\\n"
        fi
        issues+=("NFS 서비스 활성 상태이나 설정 파일(/etc/exports) 미존재 - 접근 통제 및 권한 정적 입증 불가 (수동 확인 필요)")
        is_secure=false
        diagnosis_result="MANUAL"
    fi

    # 최종 판정
    if [ "$diagnosis_result" = "MANUAL" ]; then
        status="수동진단"
        inspection_summary="NFS 활성이나 /etc/exports 부재로 접근 통제/권한 입증 불가: ${issues[*]}"
        command_result="${exports_info}"
        command_executed="cat /etc/exports 2>/dev/null; lssrc -s nfsd 2>/dev/null; exportfs -v 2>/dev/null; cat /etc/xtab 2>/dev/null; showmount -e 2>/dev/null"
    elif [ "$nfs_installed" = false ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="NFS 서비스 미사용"
        local lssrc_out=$(lssrc -s nfsd 2>/dev/null || echo "NFS services not found")
        local ss_out=$(ss -tuln | grep -E ':2049|:20048' 2>/dev/null || echo "NFS ports not listening")
        command_result="[Command: lssrc -s nfsd]${newline}${lssrc_out}${newline}${newline}[Command: ss -tuln | grep NFS ports]${newline}${ss_out}"
        command_executed="lssrc -s nfsd; ss -tuln | grep -E ':2049|:20048'"
    elif [ "$is_secure" = true ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="NFS 접근 통제 적절히 설정됨"
        command_result="${exports_info}"
        command_executed="cat /etc/exports; lssrc -s nfsd 2>/dev/null | grep -q 'active'"
    else
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="NFS 접근 통제 미흡: ${issues[*]}"
        local cat_exports=$(cat /etc/exports 2>/dev/null || echo "File not readable")
        local exportfs_out=$(exportfs -v 2>/dev/null || echo "exportfs failed")
        command_result="[Command: cat /etc/exports]${newline}${cat_exports}${newline}${newline}[Command: exportfs -v]${newline}${exportfs_out}"
        command_executed="cat /etc/exports; exportfs -v 2>/dev/null"
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
