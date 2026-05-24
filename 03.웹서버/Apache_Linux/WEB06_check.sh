#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : WEB-06
# @Category    : Web Server
# @Platform    : Apache
# @Severity    : 상
# @Title       : 웹서비스상위디렉터리접근제한설정
# @Description : '..'와 같은 문자 사용 등을 통한 상위 디렉터리 접근 제한 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==========================================================================
# @Platform    : Apache
# @Severity    : 상
# @Title       : 웹 서비스 상위 디렉터리 접근 제한 설정
# @Description : ".."와 같은 문자 사용 등을 통한 상위 디렉터리 접근 제한 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ===================================================================


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

ITEM_ID="WEB-06"
ITEM_NAME="웹 서비스 상위 디렉터리 접근 제한 설정"
SEVERITY="상"

GUIDELINE_PURPOSE="상위 디렉터리 접근 제한 설정을 통해 비인가자의 특정 디렉터리에 대한 접근 및 열람을 제한하여 중요 파일 및 데이터를 보호하고,Unicode 버그 및 서비스 거부 공격 등을 방지하기 위함"
GUIDELINE_THREAT="상위 디렉터리로 이동하는 것이 가능할 경우 접근하고자하는 디렉터리의 하위 경로에서 상위로 이동하며 정보 탐색이 가능하여 중요 정보가 노출될 위험이 존재함 악의적인 목적을 가진 사용자가 중요 파일 및 디렉터리의 접근이 가능하여 데이터가 유출될 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="상위 디렉터리 접근 기능을 제거한 경우"
GUIDELINE_CRITERIA_BAD="상위 디렉터리 접근 기능을 제거하지 않은 경우"
GUIDELINE_REMEDIATION="상위 디렉터리 접근 기능 제거 설정"

diagnose() {
    echo "진단 항목: ${ITEM_ID} - ${ITEM_NAME}"

    local diagnosis_result="MANUAL"
    local status="수동진단"
    local inspection_summary=""
    local command_result=""
    local command_executed=""
    local apache_conf=""

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

    # Find Apache configuration file
    local apache_conf_locations=(
        "/etc/apache2/apache2.conf"
        "/etc/httpd/conf/httpd.conf"
        "/usr/local/apache2/conf/httpd.conf"
    )

    for conf_file in "${apache_conf_locations[@]}"; do
        if [ -f "${conf_file}" ]; then
            apache_conf="${conf_file}"
            break
        fi
    done

    if [ -z "${apache_conf}" ]; then
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="Apache 설정 파일을 찾을 수 없습니다. 상위 디렉터리 접근 제한 설정을 수동으로 확인하세요."
        command_result="Apache configuration file not found"
        command_executed="ls -la /etc/apache2/apache2.conf /etc/httpd/conf/httpd.conf /usr/local/apache2/conf/httpd.conf"
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

    # Check for AllowOverride settings (affects .htaccess override)
    local allowoverride_settings=""
    allowoverride_settings=$(grep -h "AllowOverride" "${apache_conf}" /etc/apache2/sites-available/*.conf /etc/apache2/conf-available/*.conf 2>/dev/null | grep -v "^\s*#" | head -5 || true)

    # Check for Directory protections
    local directory_protections=""
    directory_protections=$(grep -h -A2 "<Directory" "${apache_conf}" /etc/apache2/sites-available/*.conf 2>/dev/null | grep -E "Require|Allow|Deny" | head -5 || true)

    command_executed="grep -h 'AllowOverride' ${apache_conf} /etc/apache2/sites-available/*.conf 2>/dev/null | grep -v '^\\s*#'; grep -A2 '<Directory' ${apache_conf} | grep -E 'Require|Allow|Deny'"

    inspection_summary="Apache는 기본적으로 상위 디렉터리 접근(../, ..\\)을 차단하지만, 정확한 진단을 위해서는 수동 확인이 필요합니다."

    if [ -n "${allowoverride_settings}" ]; then
        inspection_summary="${inspection_summary} 발견된 AllowOverride 설정: ${allowoverride_settings}. "
    fi

    if [ -n "${directory_protections}" ]; then
        inspection_summary="${inspection_summary} 발견된 접근 제어 설정: ${directory_protections}. "
    fi

    inspection_summary="${inspection_summary} 수동 확인 항목: (1) DocumentRoot 이외의 경로 접근 시 403 Forbidden 반환되는지 테스트 (2) 각 <Directory> 블록의 Require, Allow, Deny 지시어 검토 (3) AllowOverride None 설정으로 .htaccess 오버라이드 제한 (4) 웹 애플리케이션 레벨의 경로 검증 로직 확인."

    command_result="AllowOverride: ${allowoverride_settings:-없음} | Directory protections: ${directory_protections:-없음}"

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
