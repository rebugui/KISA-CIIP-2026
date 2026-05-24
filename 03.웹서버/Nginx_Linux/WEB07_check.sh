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
# @Platform    : Nginx
# @Severity    : 상
# @Title       : 웹서비스경로내불필요한파일제거
# @Description : 웹 서버 경로 내의 불필요한 백업 파일, 샘플 파일, 테스트 파일 제거 여부 점검
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

    local diagnosis_result="MANUAL"
    local status="수동진단"
    local inspection_summary=""
    local command_result=""
    local command_executed=""
    local unnecessary_files=""
    local file_count=0

    # Process check (Updated for Docker)
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

    # Find document root from nginx configuration
    local doc_roots=$(grep -rhE "^\s*root.*;" /etc/nginx/ 2>/dev/null | grep -v "^\s*#" | awk '{print $2}' | sed 's/;//' | sort -u | head -5 || true)

    if [ -z "${doc_roots}" ]; then
        doc_roots="/usr/share/nginx/html /var/www/html"
    fi

    # Check for unnecessary files in document roots
    for doc_root in ${doc_roots}; do
        if [ -d "${doc_root}" ]; then
            # Check for backup files, sample files, test files
            local found_files=$(find "${doc_root}" -type f \( -name "*.bak" -o -name "*.old" -o -name "*.tmp" -o -name "*.orig" -o -name "*sample*" -o -name "*test*" -o -name "*.backup" -o -name "*.swp" -o -name "README*" -o -name "INSTALL*" \) 2>/dev/null | head -10 || true)

            if [ -n "${found_files}" ]; then
                unnecessary_files="${unnecessary_files}"$'\n'"${found_files}"
                file_count=$(echo "${unnecessary_files}" | wc -l)
            fi
        fi
    done

    command_executed="find /usr/share/nginx/html /var/www/html -type f \\( -name '*.bak' -o -name '*.old' -o -name '*.tmp' -o -name '*sample*' \\) 2>/dev/null | head -10"
    command_result="${unnecessary_files:-No unnecessary files found}"

    if [ "${file_count}" -eq 0 ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="불필요한 파일(백업, 테스트, 샘플 파일 등)이 발견되지 않았습니다."
    else
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="${file_count}개의 불필요한 파일이 발견되었습니다. 샘플, 백업, 테스트 파일 등을 제거하세요."
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
