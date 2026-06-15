#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : WEB-07
# @Category    : Server
# @Platform    : Tomcat_Linux
# @Severity    : 중
# @Title       : 웹 서비스 경로 내 불필요한 파일 제거
# @Description : 웹 서비스 경로 내 기본 생성 불필요 파일 및 디렉터리 제거 여부 점검
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

        # Process check (Updated for Docker)
    if command -v pgrep >/dev/null; then
    if ! pgrep -f "catalina|tomcat" > /dev/null; then
        diagnosis_result="N/A"
        status="N/A"
        inspection_summary="Tomcat 웹 서버가 실행 중이 아닙니다."
        command_result="Tomcat process not found"
        command_executed="pgrep -f 'catalina|tomcat'"

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

    # 웹 서비스 경로(webapps) 내 기본 생성 불필요 파일/디렉터리 점검
    # 가이드라인 기준: 샘플/매뉴얼/임시/테스트/백업 파일 및 기본 디렉터리(docs, examples,
    # manager, host-manager) 존재 여부 점검 (criteria_bad: 기본으로 생성되는 불필요한 파일
    # 및 디렉터리가 존재하는 경우)
    local webapp_dirs=(
        "/var/lib/tomcat*/webapps"
        "/usr/share/tomcat*/webapps"
        "/opt/tomcat/webapps"
        "/opt/tomcat*/webapps"
    )

    # 기본 생성되는 불필요 디렉터리 (Tomcat 기본 배포 샘플/매뉴얼/관리 콘솔)
    local default_dirs=("docs" "examples" "manager" "host-manager")
    # 기본 생성되는 불필요 파일 (매뉴얼/릴리스 노트/안내 파일 등)
    local default_file_globs=("*.txt" "BUILDING.*" "RELEASE-NOTES*" "RUNNING.*" "*.bak" "*~" "*.orig" "*sample*" "*example*")

    local webapps_found=false
    local unnecessary_items=""
    local unnecessary_count=0

    for dir_pattern in "${webapp_dirs[@]}"; do
        for webapp_dir in $dir_pattern; do
            if [ -d "${webapp_dir}" ]; then
                webapps_found=true

                # 기본 샘플/매뉴얼/관리 디렉터리 존재 확인
                for d in "${default_dirs[@]}"; do
                    if [ -d "${webapp_dir}/${d}" ]; then
                        unnecessary_items="${unnecessary_items}"$'\n'"[DIR] ${webapp_dir}/${d}"
                        unnecessary_count=$((unnecessary_count + 1))
                    fi
                done

                # 불필요 파일(샘플/매뉴얼/백업/임시) 존재 확인 (webapps 직하위 및 ROOT/docs 내)
                local found_files=$(find "${webapp_dir}" -maxdepth 3 -type f \
                    \( -iname "*.bak" -o -iname "*~" -o -iname "*.orig" \
                       -o -iname "BUILDING.*" -o -iname "RELEASE-NOTES*" -o -iname "RUNNING.*" \
                       -o -iname "*sample*" -o -iname "*example*" \
                       -o -iname "jndi-resources-howto*" \) 2>/dev/null | head -20 || true)
                if [ -n "${found_files}" ]; then
                    unnecessary_items="${unnecessary_items}"$'\n'"${found_files}"
                    local file_hits=$(echo "${found_files}" | grep -c . || true)
                    unnecessary_count=$((unnecessary_count + file_hits))
                fi
            fi
        done
    done

    command_executed="ls -d /var/lib/tomcat*/webapps/{docs,examples,manager,host-manager} 2>/dev/null; find /var/lib/tomcat*/webapps -maxdepth 3 -type f \\( -iname '*sample*' -o -iname 'BUILDING.*' -o -iname 'RELEASE-NOTES*' \\) 2>/dev/null | head -20"
    command_result="${unnecessary_items:-No unnecessary default files or directories found}"

    if [ "${webapps_found}" = false ]; then
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="Tomcat webapps 디렉터리를 찾을 수 없습니다. 웹 서비스 경로 내 기본 생성 샘플/매뉴얼/백업 파일 및 디렉터리(docs, examples, manager, host-manager 등) 존재 여부를 수동으로 확인하세요."
    elif [ ${unnecessary_count} -gt 0 ]; then
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="웹 서비스 경로 내 기본으로 생성되는 불필요한 파일 또는 디렉터리(${unnecessary_count}개: 샘플/매뉴얼/백업/관리 콘솔 등)가 존재합니다. 제거 권장(예: rm -rf <webapps>/docs, examples, manager, host-manager)."
    else
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="웹 서비스 경로 내 기본으로 생성되는 불필요한 파일 및 디렉터리가 발견되지 않았습니다. (보안 권고사항 준수)"
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
