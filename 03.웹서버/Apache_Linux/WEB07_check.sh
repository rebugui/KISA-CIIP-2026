#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : WEB-07
# @Category    : Web Server
# @Platform    : Apache_Linux
# @Severity    : 중
# @Title       : 웹 서비스 경로 내 불필요한 파일 제거
# @Description : 웹 서버 디렉터리 내의 불필요한 백업 파일, 샘플 파일, 테스트 파일 제거 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==========================================================================

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

ITEM_ID="WEB-07"
ITEM_NAME="웹 서비스 경로 내 불필요한 파일 제거"
SEVERITY="중"

GUIDELINE_PURPOSE="웹 서비스 설치 시 기본으로 생성되는 샘플, 매뉴얼 파일 등 서비스에 불필요한 파일을 제거하여 불필요한 공격 대상으로 이용되는 것을 방지하기 위함"
GUIDELINE_THREAT="웹 서비스 설치 시 기본으로 생성되는 파일 및 디렉터리나 백 업, 테스트 파일 등을 제거하지 않은 경우, 비인가자에게 시스템 관련 정보 및 웹 서버 정보가 노출되거나 해킹에 악용될 수 있음"
GUIDELINE_CRITERIA_GOOD="기본으로 생성되는 불필요한 파일 및 디렉터리가 존재하지 않을 경우"
GUIDELINE_CRITERIA_BAD="기본으로 생성되는 불필요한 파일 및 디렉터리가 존재하는 경우"
GUIDELINE_REMEDIATION="불필요한 파일 및 디렉터리를 제거하도록 설정"

diagnose() {
    echo "진단 항목: ${ITEM_ID} - ${ITEM_NAME}"

    local diagnosis_result="UNKNOWN"
    local status="미진단"
    local inspection_summary=""
    local command_result=""
    local command_executed=""
    local unnecessary_files_found=""
    local web_root_dirs=()

    # Apache process check
    if command -v pgrep >/dev/null; then
        if ! pgrep -x "httpd" > /dev/null && ! pgrep -x "apache2" > /dev/null; then
            diagnosis_result="N/A"
            status="N/A"
            inspection_summary="Apache 웹 서버가 실행 중이 아닙니다."
            command_result="Apache process not found"
            command_executed="pgrep -x httpd; pgrep -x apache2"
            # Run-all 모드 확인

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
        fi
    else
        echo "[INFO] pgrep command missing, skipping process check."
    fi

    # Find Apache configuration file and DocumentRoot
    local apache_conf_locations=(
        "/etc/apache2/apache2.conf"
        "/etc/httpd/conf/httpd.conf"
        "/usr/local/apache2/conf/httpd.conf"
    )
    local apache_conf=""

    for conf_file in "${apache_conf_locations[@]}"; do
        if [ -f "${conf_file}" ]; then
            apache_conf="${conf_file}"
            break
        fi
    done

    if [ -n "${apache_conf}" ]; then
        # Extract DocumentRoot paths
        local docroots=$(grep -E "^\s*DocumentRoot" "${apache_conf}" 2>/dev/null | grep -v "^\s*#" | awk '{print $2}' | tr -d '"' || true)

        # Also check sites-enabled for Ubuntu/Debian
        if [ -d "/etc/apache2/sites-available" ]; then
            local additional_roots=$(grep -rhE "^\s*DocumentRoot" /etc/apache2/sites-available/*.conf 2>/dev/null | grep -v "^\s*#" | awk '{print $2}' | tr -d '"' || true)
            docroots="${docroots}"$'\n'"${additional_roots}"
        fi

        # Collect unique web root directories
        for root in ${docroots}; do
            if [ -n "${root}" ] && [ -d "${root}" ]; then
                web_root_dirs+=("${root}")
            fi
        done
    fi

    # Default web directories if DocumentRoot not found
    if [ ${#web_root_dirs[@]} -eq 0 ]; then
        local default_dirs=("/var/www/html" "/var/www" "/usr/local/apache2/htdocs" "/srv/www")
        for dir in "${default_dirs[@]}"; do
            if [ -d "${dir}" ]; then
                web_root_dirs+=("${dir}")
            fi
        done
    fi

    # Patterns for unnecessary files
    # Tier A: 확장자로 명확히 식별되는 백업/임시 파일 (기본 생성 불필요 파일과 1:1 대응) → 취약
    local definite_patterns=(
        "*.bak"
        "*.backup"
        "*.old"
        "*.orig"
        "*.save"
        "*~"
        "*.swp"
        "*.tmp"
        "*.temp"
        "*.dump"
    )
    # Tier B: 정상 업무 콘텐츠와 부분 문자열이 충돌할 수 있는 모호한 패턴
    #         (예: testimonials.html→*test*, example-pricing.html→*example*) → 수동진단
    #         기본 설치 산출물(샘플/매뉴얼/테스트)인지 분석가 확인 필요
    local ambiguous_patterns=(
        "*sample*"
        "*example*"
        "*test*"
        "*install*"
        "*setup*"
        "*readme*"
        "*.sql"
        "*.log"
    )

    # Search for unnecessary files
    local search_paths=""
    for web_dir in "${web_root_dirs[@]}"; do
        search_paths="${search_paths} ${web_dir}"
    done

    if [ -z "${search_paths}" ]; then
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="웹 디렉터리를 찾을 수 없습니다. /var/www/html, DocumentRoot 등에서 수동으로 불필요한 파일(.bak, .old, sample, test 등)을 확인하세요."
        command_result="No web directories found"
        command_executed="ls -la /var/www/html /var/www /usr/local/apache2/htdocs 2>/dev/null"
        save_dual_result "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" "${inspection_summary}" "${command_result}" "${command_executed}" "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
        verify_result_saved "${ITEM_ID}"
        return 0
    fi

    # Build find command for a given pattern set
    build_find_cmd() {
        local _cmd="find ${search_paths} -type f"
        local _first=true
        local _pat
        for _pat in "$@"; do
            if [ "${_first}" = true ]; then
                _cmd="${_cmd} -name \"${_pat}\""
                _first=false
            else
                _cmd="${_cmd} -o -name \"${_pat}\""
            fi
        done
        _cmd="${_cmd} 2>/dev/null | head -20"
        echo "${_cmd}"
    }

    local definite_cmd
    definite_cmd="$(build_find_cmd "${definite_patterns[@]}")"
    local ambiguous_cmd
    ambiguous_cmd="$(build_find_cmd "${ambiguous_patterns[@]}")"

    command_executed="[definite] ${definite_cmd}"$'\n'"[ambiguous] ${ambiguous_cmd}"

    # Execute find commands (Tier A: definite backup/temp, Tier B: ambiguous substring)
    local definite_files
    definite_files=$(eval "${definite_cmd}" || true)
    local ambiguous_files
    ambiguous_files=$(eval "${ambiguous_cmd}" || true)

    if [ -n "${definite_files}" ]; then
        # Tier A — 확장자로 명확한 백업/임시 파일 존재 → 취약
        local file_count
        file_count=$(echo "${definite_files}" | wc -l)
        diagnosis_result="VULNERABLE"
        status="취약"
        command_result="${definite_files}"
        inspection_summary="웹 디렉터리에서 ${file_count}개의 불필요한 백업/임시 파일(.bak, .old, .orig, ~ 등)이 발견되었습니다. 해당 파일은 삭제하세요. 보안 위험: 소스 코드 노출, 설정 정보 유출."
    elif [ -n "${ambiguous_files}" ]; then
        # Tier B — 정상 업무 콘텐츠와 충돌 가능한 모호한 매칭 → 수동진단 (분석가 확인)
        local amb_count
        amb_count=$(echo "${ambiguous_files}" | wc -l)
        diagnosis_result="MANUAL"
        status="수동진단"
        command_result="${ambiguous_files}"
        inspection_summary="웹 디렉터리에서 이름이 sample/example/test/install/setup/readme 또는 .sql/.log 를 포함하는 파일 ${amb_count}개가 발견되었습니다. 정상 업무 콘텐츠(예: testimonials.html)와 부분 문자열이 겹칠 수 있으므로, 해당 파일이 웹 서버 기본 설치 시 생성된 불필요한 샘플/매뉴얼/테스트 파일인지 직접 확인하여 양호/취약을 판정하세요."
    else
        command_result="No unnecessary files found"
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="웹 디렉터리에서 기본 생성되는 불필요한 파일(백업, 샘플, 테스트 파일 등)이 발견되지 않았습니다. 보안 권고사항 준수"
    fi

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

main() {
    show_diagnosis_start "${ITEM_ID}" "${ITEM_NAME}"
    check_disk_space
    diagnose
    show_diagnosis_complete "${ITEM_ID}" "${diagnosis_result:-UNKNOWN}"
}

if true; then
    main "$@"
fi
