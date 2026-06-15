#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : WEB-24
# @Category    : Web Server
# @Platform    : Apache_Linux
# @Severity    : 중
# @Title       : 별도의 업로드 경로 사용 및 권한 설정
# @Description : Clickjacking 공격을 방지하기 위해 X-Frame-Options 헤더를 설정합니다. DENY 또는 SAMEORIGIN 값을 사용하여 페이지가 다른 사이트의 프레임에 로드되는 것을 방지해야 합니다.
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

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

ITEM_ID="WEB-24"
ITEM_NAME="별도의 업로드 경로 사용 및 권한 설정"
SEVERITY="중"
GUIDELINE_PURPOSE="웹 서버 루트 디렉터리 내 업로드 경로가 아닌 별도의 디렉터리에서 파일을 업로드할 수 있도록하여 루트 디렉터리 내 악의적인 파일 업로드 및 실행을 방지하기 위함"
GUIDELINE_THREAT="웹 서버 내 별도의 파일 업로드 경로 사용 및 적절한 권한 설정을 하지 않을 경우, 악의적인 목적을 가진 파일을 업로드하여 시스템 침투, 중요 정보 유출 및 변조 등의 침해 사고의 가능성이 있음"
GUIDELINE_CRITERIA_GOOD="별도의 업로드 경로를 사용하고 일반 사용자의 접근 권한이 부여되지 않은 경우"
GUIDELINE_CRITERIA_BAD="별도의 업로드 경로를 사용하지 않거나, 일반 사용자의 접근 권한이 부여된 경우"
GUIDELINE_REMEDIATION="기본 경로가 아닌 별도의 업로드 경로를 지정하고, 해당 경로에 대한 일반 사용자의 접근 권한을 제한하도록 설정"

diagnose() {
    echo "진단 항목: ${ITEM_ID} - ${ITEM_NAME}"
    local diagnosis_result="MANUAL"
    local status="수동진단"
    local inspection_summary=""
    local command_result=""
    local command_executed=""

    # Apache 실행 여부 확인 (미실행 시 점검 대상 아님)
    local apache_running=false
    if command -v pgrep >/dev/null 2>&1; then
        if pgrep -x "httpd" >/dev/null 2>&1 || pgrep -x "apache2" >/dev/null 2>&1; then
            apache_running=true
        fi
    else
        if ps aux 2>/dev/null | grep -E 'httpd|apache2' | grep -v grep | grep -q "httpd\|apache2"; then
            apache_running=true
        fi
    fi

    if [ "$apache_running" = false ]; then
        diagnosis_result="N/A"
        status="N/A"
        inspection_summary="Apache 웹 서버가 실행 중이 아닙니다."
        command_result="Apache process not found"
        command_executed="pgrep -x 'httpd|apache2'"

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

        verify_result_saved "${ITEM_ID}"
        return 0
    fi

    # 별도 업로드 디렉터리 탐색 및 일반 사용자 접근 권한 점검
    # 판단기준(가이드): 별도 업로드 경로 사용 + 일반 사용자 접근 권한 미부여 -> 양호
    #                  별도 경로 미사용 또는 일반 사용자 접근 권한 부여 -> 취약
    # 결정 신호: 업로드 디렉터리 권한의 'others' 비트(world 접근 허용 시 일반 사용자 접근 가능 -> 취약)
    # 웹 루트(DocumentRoot) 후보를 수집한다. 업로드 경로가 웹 루트 내부에 있으면
    # criteria_bad('별도의 업로드 경로를 사용하지 않음')에 해당하여 취약으로 판단한다.
    local web_roots=()
    local conf_candidates=(
        "/etc/apache2/apache2.conf"
        "/etc/apache2/sites-enabled/"*.conf
        "/etc/httpd/conf/httpd.conf"
        "/etc/httpd/conf.d/"*.conf
        "/usr/local/apache2/conf/httpd.conf"
    )
    for conf_pat in "${conf_candidates[@]}"; do
        for conf_file in $conf_pat; do
            [ -f "${conf_file}" ] || continue
            [ -r "${conf_file}" ] || continue
            while IFS= read -r dr; do
                [ -n "${dr}" ] && web_roots+=("${dr%/}")
            done < <(grep -hiE '^[[:space:]]*DocumentRoot[[:space:]]+' "${conf_file}" 2>/dev/null \
                | grep -vE '^[[:space:]]*#' \
                | sed -E 's/^[[:space:]]*DocumentRoot[[:space:]]+//; s/^"//; s/"[[:space:]]*$//; s/[[:space:]]*$//')
        done
    done
    # 설정에서 못 읽었을 때를 대비한 기본 웹 루트 후보(잘 알려진 경로)
    # 주의: 표준 DocumentRoot의 형제 디렉터리(예: /var/www/uploads)를 웹 루트 내부로
    #       오판하지 않도록 상위 경로 '/var/www'는 포함하지 않는다.
    local default_roots=("/var/www/html" "/usr/local/apache2/htdocs")

    is_inside_web_root() {
        # $1 업로드 경로가 알려진/기본 웹 루트의 내부(또는 동일)인지 판별
        # DocumentRoot를 설정에서 확인한 경우(web_roots 비어있지 않음)에는 실제
        # DocumentRoot만으로 판별하고, 기본 후보(default_roots)는 설정을 읽지 못한
        # 폴백 상황(web_roots 비어있음)에서만 사용한다.
        local up="${1%/}"
        local root
        local -a roots_to_check=()
        if [ "${#web_roots[@]}" -gt 0 ]; then
            roots_to_check=("${web_roots[@]}")
        else
            roots_to_check=("${default_roots[@]}")
        fi
        for root in "${roots_to_check[@]}"; do
            [ -n "${root}" ] || continue
            if [ "${up}" = "${root}" ] || case "${up}/" in "${root}/"*) true;; *) false;; esac; then
                printf '%s' "${root}"
                return 0
            fi
        done
        return 1
    }

    local candidate_dirs=(
        "/var/www/html/uploads"
        "/var/www/html/upload"
        "/usr/local/apache2/htdocs/uploads"
        "/usr/local/apache2/htdocs/upload"
        "/var/www/uploads"
        "/data/uploads"
        "/srv/uploads"
        "/var/uploads"
    )
    local found_dir=""
    local dirs_checked=""
    local has_world_access=false
    local inside_web_root=false
    local inside_evidence=""

    for d in "${candidate_dirs[@]}"; do
        if [ -d "${d}" ]; then
            local perm=$(stat -c "%a" "${d}" 2>/dev/null || echo "")
            if [ -n "${perm}" ]; then
                found_dir="${d}"
                local matched_root
                if matched_root=$(is_inside_web_root "${d}"); then
                    inside_web_root=true
                    inside_evidence="${inside_evidence}"$'\n'"[INSIDE-WEBROOT] ${d} ⊂ ${matched_root}"
                    dirs_checked="${dirs_checked}"$'\n'"[DIR] ${d}: ${perm} (웹 루트 내부: ${matched_root})"
                else
                    dirs_checked="${dirs_checked}"$'\n'"[DIR] ${d}: ${perm} (웹 루트 외부)"
                fi
                # others 권한 비트 (3자리 또는 4자리 8진수의 마지막 자리)
                local others_bit="${perm: -1}"
                if [ "${others_bit}" != "0" ]; then
                    has_world_access=true
                fi
            fi
        fi
    done

    command_executed="grep DocumentRoot <apache conf>; stat -c '%a' <upload dir candidates> 2>/dev/null"

    if [ -z "${found_dir}" ]; then
        # 별도 업로드 경로를 자동으로 식별할 수 없음 -> 정책/구성 수동 확인 필요
        diagnosis_result="MANUAL"
        status="수동진단"
        command_result="No upload directory candidate found"
        inspection_summary="업로드 디렉터리를 자동으로 식별하지 못했습니다. 애플리케이션이 사용하는 업로드 경로가 웹 루트(DocumentRoot)와 분리되어 있는지, 해당 경로에 일반 사용자 접근 권한이 제한(예: chmod 750)되어 있는지 수동으로 확인하세요."
    elif [ "${inside_web_root}" = true ]; then
        # criteria_bad: 별도의 업로드 경로를 사용하지 않음(웹 루트 내부 업로드)
        diagnosis_result="VULNERABLE"
        status="취약"
        command_result="${dirs_checked}"
        inspection_summary="업로드 디렉터리가 웹 루트(DocumentRoot) 내부에 위치하여 별도의 업로드 경로를 사용하지 않습니다. 웹 루트 외부의 별도 경로로 이전하고 일반 사용자 접근 권한을 제한하세요.${inside_evidence}"
    elif [ "${has_world_access}" = true ]; then
        diagnosis_result="VULNERABLE"
        status="취약"
        command_result="${dirs_checked}"
        inspection_summary="업로드 디렉터리에 일반 사용자(others) 접근 권한이 부여되어 있습니다. chmod 750 등으로 일반 사용자 접근 권한을 제거하고 적절한 소유자를 지정하세요."
    elif [ "${#web_roots[@]}" -eq 0 ]; then
        # 업로드 경로가 기본 웹 루트 외부이지만 DocumentRoot를 설정에서 확인하지 못해
        # 분리 여부를 단정할 수 없음 -> GOOD 대신 MANUAL
        diagnosis_result="MANUAL"
        status="수동진단"
        command_result="${dirs_checked}"
        inspection_summary="업로드 디렉터리가 기본 웹 루트 외부로 보이나 Apache 설정에서 DocumentRoot를 확인하지 못해 웹 루트와의 분리 여부를 단정할 수 없습니다. DocumentRoot 경로와 업로드 경로의 분리 여부를 수동으로 확인하세요."
    else
        diagnosis_result="GOOD"
        status="양호"
        command_result="${dirs_checked}"
        inspection_summary="별도의 업로드 디렉터리가 웹 루트(DocumentRoot) 외부에 존재하며 일반 사용자(others) 접근 권한이 부여되지 않았습니다. (판단기준 충족)"
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
