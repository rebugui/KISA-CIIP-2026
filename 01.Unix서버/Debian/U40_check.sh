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
# @Platform    : Debian
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
    local exports_files=()
    local exports_inspected=false

    # exports 후보 파일 수집: /etc/exports 및 /etc/exports.d/*.exports (Debian: exports(5))
    if [ -f /etc/exports ]; then
        exports_files+=("/etc/exports")
    fi
    if [ -d /etc/exports.d ]; then
        local _ef
        for _ef in /etc/exports.d/*.exports; do
            [ -f "$_ef" ] && exports_files+=("$_ef")
        done
    fi

    # 1) NFS exports 파일(들) 점검
    if [ "${#exports_files[@]}" -gt 0 ]; then
        nfs_installed=true
        exports_info="NFS exports 파일 존재: ${exports_files[*]}${newline}${newline}"

        local exports_file
        for exports_file in "${exports_files[@]}"; do
            exports_inspected=true
            exports_info="${exports_info}[${exports_file}]${newline}"

            # exports 파일 내용 확인
            if [ -s "$exports_file" ]; then
                exports_info="${exports_info}$(cat "$exports_file")${newline}${newline}"

                # 각 exports 라인 확인
                while IFS= read -r line; do
                    # 주석 및 공백 행 무시 (들여쓰기된 주석 포함)
                    [[ "$line" =~ ^[[:space:]]*#.*$ ]] && continue
                    [[ "$line" =~ ^[[:space:]]*$ ]] && continue

                    # 호스트 접근 통제 확인: 모든 호스트(*) 대상 공유는 접근 통제 미흡
                    if echo "$line" | grep -qE '(^|[[:space:]])\*(\(|[[:space:]]|$)'; then
                        is_secure=false
                        issues+=("모든 호스트(*)에 공유 허용(접근 통제 없음) [${exports_file}]: $line")
                    fi

                    # 취약한 옵션 확인 (옵션 경계 매칭: root_squash 내부의 'ro' 오탐 방지)
                    if ! echo "$line" | grep -qE '(^|[(,])ro([),]|$)'; then
                        if echo "$line" | grep -qE '(^|[(,])rw([),]|$)'; then
                            is_secure=false
                            issues+=("쓰기 권한(rw) 허용됨 [${exports_file}]: $line")
                        fi
                    fi

                    # root_squash 확인 (no_root_squash를 먼저 검사: 부분 문자열 오탐 방지)
                    if echo "$line" | grep -qE '(^|[(,])no_root_squash([),]|$)'; then
                        is_secure=false
                        issues+=("root 권한 승급 가능(no_root_squash) [${exports_file}]: $line")
                    elif ! echo "$line" | grep -qE '(^|[(,])root_squash([),]|$)'; then
                        # 기본값은 root_squash지만 명시적인 것이 좋음
                        issues+=("root_squash 옵션 미명시 [${exports_file}]: $line")
                    fi

                    # sync 확인
                    if ! echo "$line" | grep -q "sync"; then
                        if echo "$line" | grep -q "async"; then
                            issues+=("비동기 모드(async) 사용 [${exports_file}]: $line")
                        fi
                    fi

                    # insecure 옵션 확인 (1024 이상 포트 허용)
                    if echo "$line" | grep -q "insecure"; then
                        is_secure=false
                        issues+=("insecure 옵션 사용 [${exports_file}]: $line")
                    fi
                done < "$exports_file" || true
            else
                exports_info="${exports_info}exports 파일이 비어있음 (안전)${newline}"
            fi

            # exports 파일 권한 확인 (root 소유, 644 이하)
            local exp_perm=$(stat -c "%a" "$exports_file" 2>/dev/null || echo "")
            local exp_owner=$(stat -c "%U" "$exports_file" 2>/dev/null || echo "")
            exports_info="${exports_info}[파일 권한] ${exports_file} 권한=${exp_perm:-확인불가} 소유자=${exp_owner:-확인불가}${newline}"
            if [ -n "$exp_perm" ] && [[ "$exp_perm" =~ ^[0-7]{3,4}$ ]]; then
                if [ "$(( 8#$exp_perm & ~8#644 & 07777 ))" -ne 0 ] || [ "$exp_owner" != "root" ]; then
                    is_secure=false
                    issues+=("${exports_file} 권한/소유자 부적절 (권한 ${exp_perm}, 소유자 ${exp_owner}; root 소유 644 이하 필요)")
                fi
            fi
            exports_info="${exports_info}${newline}"
        done
    fi

    # 2) NFS 서비스 실행 확인
    local nfs_daemon_running=false
    if systemctl is-active nfs-server &>/dev/null || systemctl is-active nfs-kernel-server &>/dev/null; then
        nfs_installed=true
        nfs_daemon_running=true
        exports_info="${exports_info}NFS 서비스 실행 중${newline}"
    fi

    # 3) 포트 확인 (NFS: 2049, mountd: 20048)
    local nfs_port_listening=false
    if command -v ss &>/dev/null; then
        local nfs_port=$(ss -tuln | grep -E ":2049 |:20048 " || echo "")
        if [ -n "$nfs_port" ]; then
            nfs_installed=true
            nfs_port_listening=true
            exports_info="${exports_info}NFS 포트 활성화 (2049/20048)${newline}"
        fi
    fi

    # 최종 판정
    if [ "$nfs_installed" = false ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="NFS 서비스 미사용"
        command_result="NFS: disabled"
        command_executed="systemctl is-active nfs-server nfs-kernel-server; ss -tuln | grep -E ':2049|:20048'"
    elif [ "$exports_inspected" = false ] && { [ "$nfs_daemon_running" = true ] || [ "$nfs_port_listening" = true ]; }; then
        # NFS 데몬/포트는 활성이나 점검 가능한 exports 파일이 없음
        # → /etc/exports.d 외부 설정·런타임 exportfs 등의 가능성 존재, 정적 판정 불가
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="NFS 서비스/포트가 활성 상태이나 /etc/exports 및 /etc/exports.d/*.exports를 확인할 수 없어 접근 통제 설정의 정적 판정 불가 (수동 점검 필요: exportfs -v)"
        command_result="${exports_info}점검 가능한 exports 파일 없음 (정적 판정 불가)${newline}"
        command_executed="ls -l /etc/exports /etc/exports.d/ 2>/dev/null; systemctl is-active nfs-server nfs-kernel-server; ss -tuln | grep -E ':2049|:20048'; exportfs -v 2>/dev/null"
    elif [ "$is_secure" = true ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="NFS 접근 통제 적절히 설정됨"
        command_result="${exports_info}"
        command_executed="cat /etc/exports /etc/exports.d/*.exports 2>/dev/null; systemctl is-active nfs-server"
    else
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="NFS 접근 통제 미흡: ${issues[*]}"
        command_result="${exports_info}"
        command_executed="cat /etc/exports /etc/exports.d/*.exports 2>/dev/null; exportfs -v 2>/dev/null"
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
