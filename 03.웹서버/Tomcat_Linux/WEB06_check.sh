#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : WEB-06
# @Category    : Server
# @Platform    : Tomcat_Linux
# @Severity    : 상
# @Title       : 웹 서비스 상위 디렉터리 접근 제한 설정
# @Description : '..'와 같은 문자 사용 등을 통한 상위 디렉터리 접근 제한 여부 점검
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
    local has_allow_linking_true=false
    local context_config=""
    local inspected_any_xml=false

    # Tomcat 프로세스 확인
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

    # server.xml 및 context.xml 위치 찾기
    # WEB-02 와 동일한 후보 경로 + Apache Tomcat 바이너리 배포 기본 경로(/opt/tomcat*, /usr/local/tomcat*)
    # 환경변수(CATALINA_BASE/CATALINA_HOME)가 설정되어 있으면 우선 점검
    local xml_locations=(
        "/etc/tomcat*/server.xml"
        "/etc/tomcat*/context.xml"
        "/var/lib/tomcat*/conf/server.xml"
        "/var/lib/tomcat*/conf/context.xml"
        "/usr/share/tomcat*/conf/server.xml"
        "/usr/share/tomcat*/conf/context.xml"
        "/usr/local/tomcat*/conf/server.xml"
        "/usr/local/tomcat*/conf/context.xml"
        "/opt/tomcat*/conf/server.xml"
        "/opt/tomcat*/conf/context.xml"
    )
    if [ -n "${CATALINA_BASE:-}" ]; then
        xml_locations=("${CATALINA_BASE}/conf/server.xml" "${CATALINA_BASE}/conf/context.xml" "${xml_locations[@]}")
    fi
    if [ -n "${CATALINA_HOME:-}" ]; then
        xml_locations=("${CATALINA_HOME}/conf/server.xml" "${CATALINA_HOME}/conf/context.xml" "${xml_locations[@]}")
    fi

    local found_file=""

    for xml_pattern in "${xml_locations[@]}"; do
        for xml_file in $xml_pattern; do
            if [ -f "${xml_file}" ]; then
                inspected_any_xml=true
                # XML 주석(<!-- ... -->) 영역을 다중 행 포함 제거하여 활성(주석 외) 설정만 추출한다.
                # 라인 선두 <!-- 만 거르는 방식은 다중 행 주석의 내부 라인을 통과시켜
                # 비활성 allowLinking 을 오탐함.
                local strip_xml_comments='
                    {
                        line = $0; out = ""
                        while (length(line) > 0) {
                            if (incomment) {
                                p = index(line, "-->")
                                if (p == 0) { line = ""; break }
                                line = substr(line, p + 3); incomment = 0
                            } else {
                                p = index(line, "<!--")
                                if (p == 0) { out = out line; line = ""; break }
                                out = out substr(line, 1, p - 1)
                                line = substr(line, p + 4); incomment = 1
                            }
                        }
                        print out
                    }'
                local active_xml=$(awk "${strip_xml_comments}" "${xml_file}" 2>/dev/null || true)
                local allow_linking=$(printf '%s\n' "${active_xml}" | grep -i 'allowLinking' 2>/dev/null || true)

                if [ -n "${allow_linking}" ]; then
                    # allowLinking="true" 확인 (대소문자 구분 없이)
                    if echo "${allow_linking}" | grep -qi 'allowLinking[[:space:]]*=[[:space:]]*"[[:space:]]*true[[:space:]]*"'; then
                        context_config="${allow_linking}"
                        has_allow_linking_true=true
                        found_file="${xml_file}"
                        break 2
                    elif echo "${allow_linking}" | grep -qi "allowLinking[[:space:]]*=[[:space:]]*'[[:space:]]*true[[:space:]]*'"; then
                        context_config="${allow_linking}"
                        has_allow_linking_true=true
                        found_file="${xml_file}"
                        break 2
                    fi
                fi
            fi
        done
    done

    if [ -n "${found_file}" ]; then
        command_executed="strip_xml_comments ${found_file} | grep -i 'allowLinking' (다중 행 주석 제외 후 활성 설정만 점검)"
        command_result="${context_config}"
    elif [ "${inspected_any_xml}" = true ]; then
        # 모든 파일에서 allowLinking이 없거나 true가 아닌 경우
        command_executed="strip_xml_comments /etc/tomcat*/server.xml /etc/tomcat*/context.xml | grep -i 'allowLinking' (다중 행 주석 제외 후 활성 설정만 점검)"
        command_result="No allowLinking=\"true\" configuration found"
    else
        # Tomcat 프로세스는 실행 중이나 후보 경로에서 server.xml/context.xml 을 찾지 못함
        command_executed="ls ${xml_locations[*]} (none of the candidate Tomcat conf files exist)"
        command_result="Tomcat conf files not located in standard paths (/etc, /var/lib, /usr/share, /usr/local, /opt) nor via CATALINA_HOME/CATALINA_BASE"
    fi

    if [ "${has_allow_linking_true}" = true ]; then
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="Context에 allowLinking=\"true\"가 설정되어 있습니다. 상위 디렉터리 접근이 가능합니다. allowLinking 속성을 제거하거나 false로 설정하세요."
    elif [ "${inspected_any_xml}" = true ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="상위 디렉터리 접근 제한이 설정되어 있습니다(allowLinking이 true로 설정되지 않음). (보안 권고사항 준수)"
    else
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="Tomcat 프로세스는 실행 중이나 표준 후보 경로(/etc/tomcat*, /var/lib/tomcat*, /usr/share/tomcat*, /usr/local/tomcat*, /opt/tomcat*) 및 CATALINA_HOME/CATALINA_BASE 환경변수에서 server.xml/context.xml 을 찾지 못했습니다. 설치 경로의 conf/context.xml(또는 webapps의 META-INF/context.xml)에서 allowLinking 속성을 수동으로 확인하세요."
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
