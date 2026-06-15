#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : U-28
# @Category    : Unix Server
# @Platform    : Debian
# @Severity    : 상
# @Title       : 접속 IP 및 포트 제한
# @Description : /etc/hosts.allow, hosts.deny 확인
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


ITEM_ID="U-28"
ITEM_NAME="접속 IP 및 포트 제한"
SEVERITY="상"

# 가이드라인 정보
GUIDELINE_PURPOSE="허용한 호스트만 서비스를 사용하게하여 서비스 취약점을 이용한 외부자 공격을 방지하기 위함"
GUIDELINE_THREAT="허용할 호스트에 대한 IP 및 포트 제한이 적용되지 않을 경우, Telnet, FTP 같은 보안에 취약한 네트워크 서비스를 통하여 불법적인 접근 및 시스템 침해 사고가 발생할 수 있는 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="접속을 허용할 특정 호스트에 대한 IP 주소 및 포트 제한을 설정한 경우"
GUIDELINE_CRITERIA_BAD="접속을 허용할 특정 호스트에 대한 IP 주소 및 포트 제한을 설정하지 않은 경우"
GUIDELINE_REMEDIATION="OS에 기본으로 제공하는 방화벽 애플리케이션이나 TCP Wrapper와 같은 호스트별 서비스 제한 애플리케이션을 사용하여 접근 허용 IP 등록 설정"

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
    # /etc/hosts.allow, hosts.deny TCP Wrappers 접속 제한 확인

    local hosts_allow_exists=0
    local hosts_deny_exists=0
    local hosts_allow_content=""
    local hosts_deny_content=""
    local tcp_wrappers_enabled=0
    local details=""

    # Capture file contents for raw output
    local hosts_allow_ls=$(ls -l /etc/hosts.allow 2>&1)
    local hosts_deny_ls=$(ls -l /etc/hosts.deny 2>&1)
    local hosts_allow_cat=$(cat /etc/hosts.allow 2>/dev/null || echo "파일 없음")
    local hosts_deny_cat=$(cat /etc/hosts.deny 2>/dev/null || echo "파일 없음")

    # Build command_result
    command_result="[File: /etc/hosts.allow]${newline}${hosts_allow_ls}${newline}${newline}${hosts_allow_cat}${newline}${newline}[File: /etc/hosts.deny]${newline}${hosts_deny_ls}${newline}${newline}${hosts_deny_cat}"

    # /etc/hosts.allow 확인
    if [ -f "/etc/hosts.allow" ]; then
        ((hosts_allow_exists++)) || true
        local perms=$(stat -c "%a" "/etc/hosts.allow" 2>/dev/null)
        local owner=$(stat -c "%U:%G" "/etc/hosts.allow" 2>/dev/null)

        # 파일 내용 확인 (주석 및 빈줄 제외)
        local content_lines=$(grep -v "^#" /etc/hosts.allow 2>/dev/null | grep -v "^$" | wc -l)

        if [ "$content_lines" -gt 0 ]; then
            ((tcp_wrappers_enabled++)) || true
            hosts_allow_content="/etc/hosts.allow: ${content_lines}개 규칙 (권한: ${perms}, 소유자: ${owner})"
        fi
    fi

    # /etc/hosts.deny 확인
    if [ -f "/etc/hosts.deny" ]; then
        ((hosts_deny_exists++)) || true
        local perms=$(stat -c "%a" "/etc/hosts.deny" 2>/dev/null)
        local owner=$(stat -c "%U:%G" "/etc/hosts.deny" 2>/dev/null)

        # 파일 내용 확인 (주석 및 빈줄 제외)
        local content_lines=$(grep -v "^#" /etc/hosts.deny 2>/dev/null | grep -v "^$" | wc -l)

        if [ "$content_lines" -gt 0 ]; then
            hosts_deny_content="/etc/hosts.deny: ${content_lines}개 규칙 (권한: ${perms}, 소유자: ${owner})"
        fi
    fi

    # 유효 규칙 추출 (주석 및 빈 줄 제외)
    local allow_rules=""
    local deny_rules=""
    local unreadable_files=""

    if [ -f "/etc/hosts.allow" ]; then
        if [ -r "/etc/hosts.allow" ]; then
            allow_rules=$(grep -vE '^[[:space:]]*#|^[[:space:]]*$' /etc/hosts.allow 2>/dev/null || true)
        else
            unreadable_files="${unreadable_files} /etc/hosts.allow"
        fi
    fi

    if [ -f "/etc/hosts.deny" ]; then
        if [ -r "/etc/hosts.deny" ]; then
            deny_rules=$(grep -vE '^[[:space:]]*#|^[[:space:]]*$' /etc/hosts.deny 2>/dev/null || true)
        else
            unreadable_files="${unreadable_files} /etc/hosts.deny"
        fi
    fi

    command_executed="grep -vE '^[[:space:]]*#|^[[:space:]]*\$' /etc/hosts.allow /etc/hosts.deny"

    # 결과 판정 (TCP Wrapper 기준: 주석 제외 유효 규칙 내용 검증)
    if [ -n "$unreadable_files" ]; then
        # 설정 파일이 존재하나 읽을 수 없음 → 수동 확인 필요
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="TCP Wrapper 설정 파일을 읽을 수 없어 수동 확인이 필요합니다 (대상:${unreadable_files})"
    elif grep -qiE 'ALL[[:space:]]*:[[:space:]]*ALL' <<< "$allow_rules"; then
        # hosts.allow에 전체 허용(ALL: ALL) 존재 → 차단 정책과 무관하게 취약
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="hosts.allow에 모든 호스트 허용(ALL: ALL) 설정이 존재하여 접속 제한이 무력화된 상태입니다."
    elif grep -qiE 'ALL[[:space:]]*:[[:space:]]*ALL' <<< "$deny_rules"; then
        # hosts.deny 기본 차단(ALL: ALL) + hosts.allow는 특정 호스트만 허용(또는 비어 있음) → 양호
        diagnosis_result="GOOD"
        status="양호"
        if [ -n "$hosts_allow_content" ]; then
            details="${details}${hosts_allow_content}. "
        fi
        if [ -n "$hosts_deny_content" ]; then
            details="${details}${hosts_deny_content}. "
        fi
        inspection_summary="hosts.deny에 기본 차단(ALL: ALL) 정책이 설정되어 있고 hosts.allow는 특정 호스트만 허용합니다. ${details}"
    else
        # 유효한 기본 차단(ALL: ALL) 정책 없음 (파일 부재 또는 주석/빈 줄만 존재) → 모든 접속 허용 상태
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="TCP Wrapper 기준 기본 차단(ALL: ALL) 정책이 없어 모든 접속이 허용되는 상태입니다 (설정 파일 부재 또는 유효 규칙 없음)."
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
