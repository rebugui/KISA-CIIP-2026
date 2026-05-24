#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : WEB-23
# @Category    : Web Server
# @Platform    : Nginx
# @Severity    : 상
# @Title       : 웹서비스웹쉘(shell)삭제
# @Description : 웹 서비스 디렉터리 내의 웹 쉘(shell) 파일 삭제 여부 점검
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

ITEM_ID="WEB-23"
ITEM_NAME="LDAP 알고리즘 적절하게 구성"
SEVERITY="중"

GUIDELINE_PURPOSE="LDAP 연결 시 안전한 비밀번호 다이제스트 알고리즘을 사용하여 비밀번호 평문 전송 시 발생할 수 있는 스니핑 등의 공격에 대비하기 위함"
GUIDELINE_THREAT="취약한 다이제스트 알고리즘을 사용하는 경우 공격자의 스니핑, 무차별 공격 등을 통해 인증 정보가 노출될 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="LDAP 연결 인증 시 안전한 비밀번호 다이제스트 알고리즘을 사용하는 경우"
GUIDELINE_CRITERIA_BAD="LDAP 연결 인증 시 안전한 비밀번호 다이제스트 알고리즘을 사용하지 않는 경우"
GUIDELINE_REMEDIATION="LDAP 연결 인증 시 SHA-256 이상의 알고리즘을 사용하도록 설정"

diagnose() {
    echo "진단 항목: ${ITEM_ID} - ${ITEM_NAME}"

    local diagnosis_result="MANUAL"
    local status="수동진단"
    local inspection_summary=""
    local command_result=""
    local command_executed=""

    # Process check
    if command -v pgrep >/dev/null; then
    if ! pgrep -x "nginx" > /dev/null; then
        diagnosis_result="N/A"
        status="N/A"
        inspection_summary="Nginx 웹 서버가 실행 중이 아닙니다."
        command_result="Nginx process not found"
        command_executed="pgrep -x nginx"
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

    # 웹 루트 디렉토리 찾기
    local web_roots=()
    local nginx_conf_locations=(
        "/etc/nginx/nginx.conf"
        "/etc/nginx/conf.d/*.conf"
        "/etc/nginx/sites-enabled/*.conf"
    )

    for conf_pattern in "${nginx_conf_locations[@]}"; do
        for conf_file in $conf_pattern; do
            if [ -f "${conf_file}" ]; then
                local found_root=$(grep -E "^\s*root\s+" "${conf_file}" 2>/dev/null | grep -v "^\s*#" | awk '{print $2}' | sed 's/;$//' | head -1 || true)
                if [ -n "${found_root}" ] && [ -d "${found_root}" ]; then
                    web_roots+=("${found_root}")
                fi
            fi
        done
    done

    # 중복 제거
    local unique_roots=($(echo "${web_roots[@]}" | tr ' ' '\n' | sort -u | tr '\n' ' '))

    if [ ${#unique_roots[@]} -eq 0 ]; then
        # 기본 웹 루트 사용
        unique_roots=("/var/www/html" "/usr/share/nginx/html" "/var/www")
    fi

    local suspicious_files=""
    local suspicious_count=0
    local webshell_patterns=(
        "r57*\.php" "c99*\.php" "webshell*\.php" "shell*\.php"
        "cmd*\.php" "eval*\.php" "hack*\.php" "backdoor*\.php"
        "\.php\..*" ".*\.php\.jpg" ".*\.php\.png"
    )

    for web_root in "${unique_roots[@]}"; do
        if [ -d "${web_root}" ]; then
            for pattern in "${webshell_patterns[@]}"; do
                local found=$(find "${web_root}" -type f -iname "${pattern}" 2>/dev/null | head -3 || true)
                if [ -n "${found}" ]; then
                    suspicious_files="${suspicious_files}"$'\n'"${found}"
                    suspicious_count=$((suspicious_count + 1))
                fi
            done
        fi
    done

    command_executed="find /var/www/html /usr/share/nginx/html -type f \( -iname '*shell*.php' -o -iname '*r57*.php' -o -iname '*c99*.php' -o -iname '*cmd*.php' \) 2>/dev/null | head -5"
    command_result="${suspicious_files:-No suspicious files found}"

    if [ ${suspicious_count} -eq 0 ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="웹쉘 의심 파일이 발견되지 않았습니다. 정기적인 검사 권장."
    else
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="${suspicious_count}개의 웹쉘 의심 파일이 발견되었습니다. 즉시 삭제하고 출처를 추적하세요. 파일 목록: ${suspicious_files}"
    fi

    # Run-all 모드 확인
    # 결과 저장 (run_all 모드는 라이브러리에서 판단)
    save_dual_result "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" "${inspection_summary}" "${command_result}" "${command_executed}" "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
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
