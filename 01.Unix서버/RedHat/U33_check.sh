#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-28
# ============================================================================
# [점검 항목 상세]
# @ID          : U-33
# @Category    : UNIX > 2. 파일 및 디렉토리 관리
# @Platform    : RedHat
# @Severity    : 하
# @Title       : 숨겨진 파일 및 디렉토리 검색 및 제거
# @Description : 시스템 내 불필요하거나 의심스러운 숨겨진 파일 및 디렉터리 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/metadata_parser.sh"

ITEM_ID="U-33"
ITEM_NAME="숨겨진 파일 및 디렉토리 검색 및 제거"
SEVERITY="하"

GUIDELINE_PURPOSE="숨겨진 파일 및 디렉토리 중 의심스러운 내용은 정상 사용자가 아닌 공격자에 의해 생성되었을 가능성이 높으므로 이를 제거하여 보안 위협을 방지하기 위함"
GUIDELINE_THREAT="숨겨진 파일 및 디렉토리를 방치할 경우, 비인가자가 생성한 악성 파일 또는 백 도어 등을 탐지하지 못할 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="불필요하거나 의심스러운 숨겨진 파일 및 디렉토리를 제거한 경우"
GUIDELINE_CRITERIA_BAD="불필요하거나 의심스러운 숨겨진 파일 및 디렉토리를 제거하지 않은 경우"
GUIDELINE_REMEDIATION="ls-al 명령어로 숨겨진 파일 존재 파악 후 불법적이거나 의심스러운 파일을 제거하도록 설정"

diagnose() {
    local status="양호"
    diagnosis_result="GOOD"
    local inspection_summary="의심스러운 숨겨진 파일이 발견되지 않았습니다."
    local command_result=""
    local command_executed="find /tmp /var/tmp /dev/shm -name '.*' ( -type f -o -type d -o -type l ); find <home> -maxdepth 1 -name '.*'"

    # 1. 임시 디렉터리 탐색: 숨김 파일 + 숨김 디렉터리 모두 점검
    local hidden_files
    hidden_files=$(find /tmp /var/tmp /dev/shm -name ".*" \( -type f -o -type d -o -type l \) 2>/dev/null | grep -vE "\.X11-unix|\.ICE-unix|\.XIM-unix|\.font-unix|\.Test-unix" | head -n 10 || true)

    # 2. 사용자 홈 디렉터리 탐색: 통상적인 환경설정 dot 파일을 제외한 숨김 항목
    local home_dirs
    home_dirs=$(awk -F: '($3==0 || $3>=1000) && $6 ~ /^\// {print $6}' /etc/passwd 2>/dev/null | sort -u || true)
    local home_hidden=""
    local hd
    for hd in $home_dirs; do
        [ -d "$hd" ] || continue
        local found
        found=$(find "$hd" -maxdepth 1 -name ".*" \( -type f -o -type d -o -type l \) 2>/dev/null \
            | grep -vE "/\.(bash_history|bash_logout|bash_profile|bashrc|profile|cshrc|tcshrc|kshrc|login|logout|viminfo|vimrc|emacs|emacs\.d|lesshst|ssh|gnupg|gnupg2|cache|config|local|mozilla|pki|java|ansible|kube|docker|m2|npm|gitconfig|gitignore|wget-hsts|Xauthority|ICEauthority|selected_editor|sudo_as_admin_successful|history|sh_history|mysql_history|psql_history|rnd)$" \
            | head -n 5 || true)
        [ -n "$found" ] && home_hidden="${home_hidden}${found}"$'\n'
    done

    if [ -n "$hidden_files" ]; then
        # 단순 존재만으로는 '의심스러운' 항목인지 정적으로 판별 불가하므로 수동진단으로 분류 (오라클 criteria_bad: 불필요/의심스러운 항목)
        status="수동진단"
        diagnosis_result="MANUAL"
        inspection_summary="임시 디렉터리 내에 숨겨진 파일/디렉터리가 존재합니다. 불필요하거나 의심스러운 항목인지 악성 여부를 수동으로 확인하십시오."
        command_result=$(echo -e "발견된 숨김 항목 리스트(/tmp,/var/tmp):\n${hidden_files}\n${home_hidden}")
    elif [ -n "$home_hidden" ]; then
        status="수동진단"
        diagnosis_result="MANUAL"
        inspection_summary="사용자 홈 디렉터리에 통상적이지 않은 숨김 파일/디렉터리가 존재합니다. 불필요하거나 의심스러운 항목인지 수동으로 확인하십시오."
        command_result=$(echo -e "발견된 숨김 항목 리스트(홈 디렉터리):\n${home_hidden}")
    else
        command_result="임시 디렉토리 및 홈 디렉터리 내에 의심스러운 숨겨진 파일이 없습니다."
    fi

    save_dual_result \
        "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" \
        "${inspection_summary}" "${command_result}" "${command_executed}" \
        "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" \
        "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
    
    return 0
}

main() { [ "$EUID" -ne 0 ] && exit 1; diagnose; }
main "$@"
