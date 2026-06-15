#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : WEB-12
# @Category    : Server
# @Platform    : Tomcat_Linux
# @Severity    : 중
# @Title       : 웹 서비스 링크 사용 금지
# @Description : 웹 서비스 설정 파일 노출 제한 여부 점검
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

ITEM_ID="WEB-12"
ITEM_NAME="웹 서비스 링크 사용 금지"
SEVERITY="중"

GUIDELINE_PURPOSE="무분별한 심볼 릭 링크, 별칭(aliases) 등을 제거하여 허용하지 않은 경로에서의 접근을 차단해 경로 검증을 우회한 시스템 파일 접근을 방지하기 위함"
GUIDELINE_THREAT="보안상 민감한 내용이 포함되어 있는 파일이 악의적인 사용자에게 노출될 경우 침해 사고로 이어질 위험이 존재함 접근을 허용한 웹 디렉터리 내에 서버의 다른 디렉터리나 파일들에 접근할 수 있는 심볼 릭 링크, aliases, 바로가기 등이 존재하는 경우 해당 링크를 통해 허용하지 않은 다른 디렉터리에 액세스할 수 있는 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="심볼 릭 링크,aliases, 바로가기 등의 링크 사용을 허용하지 않는 경우"
GUIDELINE_CRITERIA_BAD="심볼 릭 링크,aliases, 바로가기 등의 링크 사용을 허용하는 경우"
GUIDELINE_REMEDIATION="웹 서비스 링크 사용 제한 설정"

diagnose() {
    echo "진단 항목: ${ITEM_ID} - ${ITEM_NAME}"

    local diagnosis_result="MANUAL"
    local status="수동진단"
    local inspection_summary=""
    local command_result=""
    local command_executed=""
    local has_security_constraint=false

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

    local context_locations=(
        "${CATALINA_HOME:-/usr/local/tomcat}/conf/context.xml"
        "/usr/local/tomcat/conf/context.xml"
        "${CATALINA_HOME:-/usr/local/tomcat}/conf/server.xml"
        "/usr/local/tomcat/conf/server.xml"
        "/etc/tomcat*/context.xml"
        "/var/lib/tomcat*/conf/context.xml"
        "/usr/share/tomcat*/conf/context.xml"
    )

    local found_conf=""
    local allow_linking_hits=""

    for conf_pattern in "${context_locations[@]}"; do
        for conf_file in $conf_pattern; do
            if [ -f "${conf_file}" ]; then
                found_conf="${found_conf} ${conf_file}"
                # allowLinking="true"는 심볼릭 링크 추적을 허용 (웹루트 외부 노출 위험)
                local hit=$(grep -iE "allowLinking[[:space:]]*=[[:space:]]*\"?true" "${conf_file}" 2>/dev/null | grep -v "^\s*<!--" || true)
                if [ -n "${hit}" ]; then
                    allow_linking_hits="${allow_linking_hits}"$'\n'"${conf_file}: ${hit}"
                fi
            fi
        done
    done

    command_executed="grep -E 'security-constraint|web-resource-collection' /etc/tomcat*/web.xml 2>/dev/null | grep -v '^\\s*<!--' | head -3"
    command_result="${security_constraints:-No security constraints found}"

    if [ -z "${found_conf}" ]; then
        # 설정 파일 미발견 → 자동 판정 불가 (증거 기반 MANUAL)
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="Tomcat context.xml/server.xml을 표준 경로 및 CATALINA_HOME에서 찾을 수 없어 자동 판정이 불가합니다. allowLinking 설정 및 웹 루트 심볼릭 링크 사용을 수동 확인하세요."
        command_result="context.xml/server.xml not found"
    elif [ -n "${allow_linking_hits}" ]; then
        # docs WEB-12 criteria_bad: 링크를 제한 없이 사용하는 경우 취약
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="allowLinking=\"true\" 설정이 발견되었습니다. 심볼릭 링크를 통해 웹 루트 외부 파일이 노출될 수 있어 취약합니다. allowLinking을 제거하거나 false로 설정하세요."
        command_result="${allow_linking_hits}"
    else
        # allowLinking=true 부재 → Tomcat 기본값(심볼릭 링크 미허용)으로 링크 사용 제한
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="allowLinking=\"true\" 설정이 없어 Tomcat 기본값(심볼릭 링크 미추적)으로 링크 사용이 제한되어 있습니다. (보안 권고사항 준수)"
        command_result="No allowLinking=true found in:${found_conf}"
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
