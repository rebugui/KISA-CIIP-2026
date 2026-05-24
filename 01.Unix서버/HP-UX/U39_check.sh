#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : U-39
# @Category    : Unix Server
# @Platform    : HP-UX
# @Severity    : 상
# @Title       : 불필요한 NFS 서비스 비활성화
# @Description : SSH 보안 설정 확인 - Protocol 2, PermitRootLogin no, X11Forwarding no, MaxAuthTries <= 3
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


ITEM_ID="U-39"
ITEM_NAME="불필요한 NFS 서비스 비활성화"
SEVERITY="상"

# 가이드라인 정보
GUIDELINE_PURPOSE="NFS(Network File System) 서비스는 한 서버의 파일을 많은 서비스 서버들이 공유하여 사용할 때 이용하는 서비스지만 이를 이용한 침해 사고 위험성이 높으므로 사용하지 않는 경우 중지하기 위함"
GUIDELINE_THREAT="NFS 서비스는 서버의 디스크를 클라이언트와 공유하는 서비스로 적정한 보안 설정이 적용되어 있지 않다면 불필요한 파일 공유로 인한 유출 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="불필요한 NFS 서비스 관련 데몬 이 비활성화된 경우"
GUIDELINE_CRITERIA_BAD="불필요한 NFS 서비스 관련 데몬이 활성화된 경우"
GUIDELINE_REMEDIATION="NFS 서비스를 사용하지 않는 경우 서비스 중지 및 비활성화 설정 ※ 로컬 서버에 마운트되어 있는 디렉터리 제거 및 공유 디렉터리 제거 후 서비스 중지 가능"

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
    # /opt/ssh/etc/sshd_config 보안 설정 확인 (HP-UX SSH 경로)

    local is_secure=true
    local config_details=""
    local issues=()

    local sshd_config="/opt/ssh/etc/sshd_config"

    if [ ! -f "$sshd_config" ]; then
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="SSH 설정 파일 없음 (서비스 미설치)"
        local ssh_ls=$(ls -la "$sshd_config" 2>/dev/null || echo "File not found: $sshd_config")
        command_result="${ssh_ls}"
        command_executed="ls -la $sshd_config"
    else
        # 1) Protocol 설정 확인 (Protocol 2 또는 Protocol 2,1)
        local protocol=$(grep -E "^Protocol" "$sshd_config" | awk '{print $2}')
        if [ -z "$protocol" ]; then
            # 기본값은 2 (OpenSSH 5.4+는 Protocol 2만 지원)
            protocol="2"
        fi
        if [ "$protocol" != "2" ]; then
            is_secure=false
            issues+=("Protocol=${protocol} (2여야 함)")
        fi

        # 2) PermitRootLogin 확인
        local root_login=$(grep -E "^PermitRootLogin" "$sshd_config" | awk '{print $2}')
        if [ -z "$root_login" ]; then
            root_login=$(ssh -G root 2>/dev/null | grep permitrootlogin | awk '{print $2}' || echo "yes")
        fi
        if [ "$root_login" != "no" ]; then
            is_secure=false
            issues+=("PermitRootLogin=${root_login} (no여야 함)")
        fi

        # 3) X11Forwarding 확인
        local x11_forwarding=$(grep -E "^X11Forwarding" "$sshd_config" | awk '{print $2}')
        if [ -z "$x11_forwarding" ]; then
            x11_forwarding="yes"  # 기본값
        fi
        if [ "$x11_forwarding" != "no" ]; then
            is_secure=false
            issues+=("X11Forwarding=${x11_forwarding} (no여야 함)")
        fi

        # 4) MaxAuthTries 확인 (<= 3)
        local max_auth_tries=$(grep -E "^MaxAuthTries" "$sshd_config" | awk '{print $2}')
        if [ -n "$max_auth_tries" ]; then
            if [ "$max_auth_tries" -gt 3 ]; then
                is_secure=false
                issues+=("MaxAuthTries=${max_auth_tries} (<= 3이어야 함)")
            fi
        else
            # 기본값은 6
            is_secure=false
            issues+=("MaxAuthTries 미설정 (기본값 6, <= 3이어야 함)")
        fi

        config_details="Protocol=${protocol}, PermitRootLogin=${root_login}, X11Forwarding=${x11_forwarding}"
        [ -n "$max_auth_tries" ] && config_details="${config_details}, MaxAuthTries=${max_auth_tries}"

        if [ "$is_secure" = true ]; then
            diagnosis_result="GOOD"
            status="양호"
            inspection_summary="SSH 보안 설정 적절함 (${config_details})"
            command_result="${config_details}"
            command_executed="grep -E '^Protocol|^PermitRootLogin|^X11Forwarding|^MaxAuthTries' /opt/ssh/etc/sshd_config"
        else
            diagnosis_result="VULNERABLE"
            status="취약"
            inspection_summary="SSH 보안 설정 미흡: ${issues[*]}"
            command_result="${config_details}"
            command_executed="grep -E '^Protocol|^PermitRootLogin|^X11Forwarding|^MaxAuthTries' /opt/ssh/etc/sshd_config"
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
