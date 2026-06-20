#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : WEB-02
# @Category    : Server
# @Platform    : Tomcat_Linux
# @Severity    : 상
# @Title       : 취약한 비밀번호 사용 제한
# @Description : 관리자 계정의 취약한 비밀번호 설정 여부 점검
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

ITEM_ID="WEB-02"
ITEM_NAME="취약한 비밀번호 사용 제한"
SEVERITY="상"

GUIDELINE_PURPOSE="관리자 계정의 비밀번호가 복잡 도 기준에 맞게 적용되어 있는지 점검하여, 비인가자에 의한 비밀번호 유추 공격 및 관리자 권한 탈취 등을 방지하기 위함"
GUIDELINE_THREAT="관리자 계정의 비밀번호를 취약하게 설정하여 사용하는 경우, 비인가자의 비밀번호 유추 공격으로 관리자 권한 탈취 및 시스템 침입 등의 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="관리자 비밀번호가 암호화되어 있거나, 유추하기 어려운 비밀번호로 설정된 경우"
GUIDELINE_CRITERIA_BAD="관리자 비밀번호가 암호화되어 있지 않거나, 유추하기 쉬운 비밀번호로 설정된 경우"
GUIDELINE_REMEDIATION="복잡 도 기준에 맞는 추측하기 어려운 비밀번호 설정"

diagnose() {
    echo "진단 항목: ${ITEM_ID} - ${ITEM_NAME}"

    local diagnosis_result="MANUAL"
    local status="수동진단"
    local inspection_summary=""
    local command_result=""
    local command_executed=""

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

    # tomcat-users.xml 위치 확인
    local tomcat_users_locations=(
        "/etc/tomcat*/tomcat-users.xml"
        "/var/lib/tomcat*/conf/tomcat-users.xml"
        "/usr/share/tomcat*/conf/tomcat-users.xml"
        "/usr/local/tomcat*/conf/tomcat-users.xml"
        "/opt/tomcat*/conf/tomcat-users.xml"
    )

    local config_found=false
    local xml_file=""

    for xml_pattern in "${tomcat_users_locations[@]}"; do
        for xml_file in $xml_pattern; do
            if [ -f "${xml_file}" ]; then
                config_found=true
                break 2
            fi
        done
    done

    if [ "${config_found}" = true ]; then
        command_executed="grep -iE '<user[[:space:]]' ${xml_file}"

        # 관리자 권한(roles에 manager/admin 포함) 사용자의 username/password 추출
        # 형식: <user username="x" password="y" roles="..."/>
        local weak_passwords="admin tomcat password passwd 1234 12345 123456 root s3cret secret manager changeit qwerty test guest tomcat123 admin123"
        local found_priv_user=false
        local vulnerable_evidence=""
        local good_evidence=""

        # user 요소를 한 줄씩 정규화하여 처리 (주석 처리된 비활성 계정 제외)
        # 기본 Tomcat conf/tomcat-users.xml 은 예시 계정(tomcat 등)을 여러 줄
        # <!-- ... --> 블록 안에 비활성(주석) 상태로 배포한다. 줄 시작(^\s*<!--) 필터만으로는
        # 블록 내부의 <user username="tomcat" .../> 줄(공백+<user 로 시작)을 제거하지 못해
        # 비활성 예시 계정을 VULNERABLE 로 오판한다. 따라서 awk 로 <!-- ... --> 주석 구간을
        # 먼저 제거한 뒤 매칭하여 활성(미주석) 계정만 탐지한다.
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
        local user_lines
        user_lines="$(printf '%s\n' "${active_xml}" | grep -ioE '<user[[:space:]][^>]*>' 2>/dev/null || true)"

        while IFS= read -r line; do
            [ -z "${line}" ] && continue
            local roles uname pass
            roles="$(printf '%s' "${line}" | grep -ioE 'roles="[^"]*"' | head -n1 | sed -E 's/roles="([^"]*)"/\1/I')"
            # 관리자/매니저 권한 사용자만 평가
            if ! printf '%s' "${roles}" | grep -iqE 'manager|admin'; then
                continue
            fi
            uname="$(printf '%s' "${line}" | grep -ioE 'username="[^"]*"' | head -n1 | sed -E 's/username="([^"]*)"/\1/I')"
            pass="$(printf '%s' "${line}" | grep -ioE 'password="[^"]*"' | head -n1 | sed -E 's/password="([^"]*)"/\1/I')"
            # 빈 비밀번호(password="")는 continue로 건너뛰지 않고 평문(취약)으로 처리함
            found_priv_user=true

            # 해시 여부 판정: MD5(32)/SHA-1(40)/SHA-256(64) 16진수 다이제스트
            local is_hash=false
            local plen="${#pass}"
            if { [ "${plen}" -eq 32 ] || [ "${plen}" -eq 40 ] || [ "${plen}" -eq 64 ]; } \
               && printf '%s' "${pass}" | grep -qE '^[0-9a-fA-F]+$'; then
                is_hash=true
            fi

            # 약한/기본/유추용이 비밀번호 판정
            local is_weak=false
            local lpass lname
            lpass="$(printf '%s' "${pass}" | tr 'A-Z' 'a-z')"
            lname="$(printf '%s' "${uname}" | tr 'A-Z' 'a-z')"
            if [ "${is_hash}" = false ]; then
                # 평문이며 약한 사전/계정명동일/8자 미만이면 취약
                for w in ${weak_passwords}; do
                    if [ "${lpass}" = "${w}" ]; then is_weak=true; break; fi
                done
                if [ "${lpass}" = "${lname}" ] || [ "${plen}" -lt 8 ]; then
                    is_weak=true
                fi
            fi

            if [ "${is_hash}" = false ]; then
                # 평문 저장 자체가 "암호화되어 있지 않은" 취약 상태 (판단기준 취약)
                vulnerable_evidence+="사용자 '${uname}': 비밀번호가 평문(암호화 미적용)으로 저장됨"
                if [ "${is_weak}" = true ]; then
                    vulnerable_evidence+=" 및 유추하기 쉬운 비밀번호 사용"
                fi
                vulnerable_evidence+="\\n"
            else
                good_evidence+="사용자 '${uname}': 비밀번호가 해시(${plen}자리 16진수)로 암호화 저장됨\\n"
            fi
        done <<< "${user_lines}"

        if [ "${found_priv_user}" = false ]; then
            diagnosis_result="MANUAL"
            status="수동진단"
            command_result="tomcat-users.xml에서 관리자 권한 사용자/비밀번호를 식별할 수 없음 (CredentialHandler 기반 외부 인증 또는 주석 처리 가능)"
            inspection_summary="tomcat-users.xml(${xml_file})에서 manager/admin 권한 사용자의 비밀번호를 자동으로 식별하지 못했습니다. "
            inspection_summary+="수동으로 비밀번호 암호화(SHA-256 이상) 및 복잡도(영문/숫자/특수문자 조합 8자 이상, 계정명/연속문자/개인정보 금지) 충족 여부를 확인하세요."
        elif [ -n "${vulnerable_evidence}" ]; then
            diagnosis_result="VULNERABLE"
            status="취약"
            command_result="관리자 비밀번호가 평문(암호화 미적용)으로 저장됨"
            inspection_summary="관리자 계정 비밀번호가 암호화되어 있지 않거나 유추하기 쉬운 값으로 설정되어 있습니다 (${xml_file}):\\n${vulnerable_evidence}"
        else
            diagnosis_result="GOOD"
            status="양호"
            command_result="관리자 비밀번호가 해시(암호화)되어 저장됨"
            inspection_summary="관리자 계정 비밀번호가 암호화(해시)되어 저장되어 있습니다 (${xml_file}):\\n${good_evidence}"
        fi
    else
        command_executed="ls /etc/tomcat*/tomcat-users.xml /var/lib/tomcat*/conf/tomcat-users.xml /usr/local/tomcat*/conf/tomcat-users.xml 2>/dev/null"
        command_result="No tomcat-users.xml file found"

        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="tomcat-users.xml 파일을 찾을 수 없습니다. Tomcat 구성을 확인하세요."
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
