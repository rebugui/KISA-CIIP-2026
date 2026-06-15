#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : WEB-14
# @Category    : Server
# @Platform    : Tomcat_Linux
# @Severity    : 상
# @Title       : 웹 서비스 경로 내 파일의 접근 통제
# @Description : 웹 서비스 경로 내 주요 설정 파일의 접근 권한(일반 사용자 접근 제한) 점검
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

ITEM_ID="WEB-14"
ITEM_NAME="웹 서비스 경로 내 파일의 접근 통제"
SEVERITY="상"

GUIDELINE_PURPOSE="웹 서비스 경로의 파일들에 관리자를 제외한 일반 사용자의 파일 접근 권한을 제거함으로써 인가되지 않은 사용자가 허용되지 않는 파일에 접근하는 것을 차단하기 위함"
GUIDELINE_THREAT="웹 서비스 경로 파일에 비인가자가 접근 가능한 경우, 해당 파일의 수정 및 삭제로 인해 웹 서비스 운영 장애 및 계정 비밀번호 정보 등의 중요한 정보가 노출될 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="주요 설정 파일 및 디렉터리에 불필요한 접근 권한이 부여되지 않은 경우"
GUIDELINE_CRITERIA_BAD="주요 설정 파일 및 디렉터리에 불필요한 접근 권한이 부여된 경우"
GUIDELINE_REMEDIATION="주요 설정 파일 및 디렉터리에 불필요한 접근 권한 제거 설정"

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

    # 웹 서비스 경로 내 주요 설정 파일/디렉터리의 접근 권한 점검
    # 가이드라인 기준: 주요 설정 파일 및 디렉터리에 관리자를 제외한 일반 사용자(other)의
    # 불필요한 접근 권한(읽기/쓰기/실행)이 부여되지 않아야 함 (권고: chmod -R 750)
    # (criteria_bad: 주요 설정 파일 및 디렉터리에 불필요한 접근 권한이 부여된 경우)
    # 판단: 권한의 other(마지막 8진수) 자리가 0이 아니면 일반 사용자 접근 가능 → 취약
    local config_paths=(
        "/etc/tomcat*/server.xml"
        "/etc/tomcat*/web.xml"
        "/etc/tomcat*/context.xml"
        "/etc/tomcat*/tomcat-users.xml"
        "/var/lib/tomcat*/conf/server.xml"
        "/var/lib/tomcat*/conf/web.xml"
        "/var/lib/tomcat*/conf/context.xml"
        "/var/lib/tomcat*/conf/tomcat-users.xml"
        "/usr/share/tomcat*/conf/server.xml"
        "/usr/share/tomcat*/conf/web.xml"
        "/usr/share/tomcat*/conf/context.xml"
        "/usr/share/tomcat*/conf/tomcat-users.xml"
    )

    local perm_info=""
    local files_checked=false
    local has_insecure_perm=false

    for path_pattern in "${config_paths[@]}"; do
        for cfg_file in $path_pattern; do
            if [ -f "${cfg_file}" ]; then
                files_checked=true
                local file_perm=$(stat -c "%a" "${cfg_file}" 2>/dev/null || echo "")
                if [ -n "${file_perm}" ]; then
                    # other 권한 자리 추출 (마지막 1자리)
                    local other_perm="${file_perm: -1}"
                    perm_info="${perm_info}"$'\n'"${cfg_file}: ${file_perm}"
                    if [ "${other_perm}" != "0" ]; then
                        has_insecure_perm=true
                    fi
                fi
            fi
        done
    done

    command_executed="stat -c '%a %n' /etc/tomcat*/server.xml /etc/tomcat*/web.xml /etc/tomcat*/tomcat-users.xml /var/lib/tomcat*/conf/*.xml /usr/share/tomcat*/conf/*.xml 2>/dev/null | head -10"
    command_result="${perm_info:-No Tomcat config files found}"

    if [ "${files_checked}" = false ]; then
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="Tomcat 주요 설정 파일을 찾을 수 없습니다. server.xml, web.xml, context.xml, tomcat-users.xml 등 주요 설정 파일에 일반 사용자(other) 접근 권한이 부여되어 있는지 수동으로 확인하세요(권고: 750 이하)."
    elif [ "${has_insecure_perm}" = true ]; then
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="주요 설정 파일에 일반 사용자(other)의 접근 권한이 부여되어 있습니다. chmod로 other 권한을 제거하여 750 이하로 설정 권장(chmod o-rwx 또는 chmod -R 750)."
    else
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="주요 설정 파일에 일반 사용자(other)의 불필요한 접근 권한이 부여되어 있지 않습니다. (보안 권고사항 준수)"
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
