#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : WEB-14
# @Category    : Web Server
# @Platform    : Apache_Linux
# @Severity    : 상
# @Title       : 웹 서비스 경로 내 파일의 접근 통제
# @Description : 주요 설정 파일/디렉터리의 일반 사용자 접근 권한(파일 권한) 점검
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

    local diagnosis_result="UNKNOWN"
    local status="미진단"
    local inspection_summary=""
    local command_result=""
    local command_executed=""

        # Process check
    if command -v pgrep >/dev/null; then
        if ! pgrep -x "httpd" > /dev/null && ! pgrep -x "apache2" > /dev/null; then
            diagnosis_result="N/A"
            status="N/A"
            inspection_summary="Apache \xec\x9b\xb9 \xec\x84\x9c\xeb\xb2\x84\xea\xb0\x80 \xec\x8b\xa4\xed\x96\x89 \xec\xa4\x91\xec\x9d\xb4 \xec\x95\x84\xeb\x8b\x99\xeb\x8b\x88\xeb\x8b\xa4."
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

    # 가이드라인 판단기준: 주요 설정 파일/디렉터리에 일반 사용자(group/other)의
    # 불필요한 접근 권한(읽기/쓰기)이 부여되어 있으면 취약. (조치: chmod 750, chown)
    local target_paths=(
        "/etc/apache2/apache2.conf"
        "/etc/apache2/ports.conf"
        "/etc/apache2"
        "/etc/httpd/conf/httpd.conf"
        "/etc/httpd/conf.d"
        "/etc/httpd"
        "/usr/local/apache2/conf/httpd.conf"
    )

    local perm_report=""
    local checked_any=false
    local insecure_found=false

    for tpath in "${target_paths[@]}"; do
        if [ -e "${tpath}" ]; then
            checked_any=true
            # 8진수 권한(예: 644, 0750)과 소유자 확인
            local octal owner group
            octal=$(stat -c "%a" "${tpath}" 2>/dev/null || true)
            owner=$(stat -c "%U" "${tpath}" 2>/dev/null || true)
            group=$(stat -c "%G" "${tpath}" 2>/dev/null || true)
            if [ -z "${octal}" ]; then
                continue
            fi
            # 마지막 3자리(소유자/그룹/기타)만 평가 (setuid 등 4자리 권한 대응)
            local perm3="${octal: -3}"
            local g_perm="${perm3:1:1}"
            local o_perm="${perm3:2:1}"
            local insecure_reason=""
            # other에 어떤 권한이라도 있으면 취약 (trailing octal != 0)
            if [ "${o_perm}" != "0" ]; then
                insecure_reason="other 접근 허용(${o_perm})"
            fi
            # group 쓰기 권한(2,3,6,7)이 있으면 취약
            case "${g_perm}" in
                2|3|6|7)
                    if [ -n "${insecure_reason}" ]; then
                        insecure_reason="${insecure_reason}, group 쓰기 허용(${g_perm})"
                    else
                        insecure_reason="group 쓰기 허용(${g_perm})"
                    fi
                    ;;
            esac
            if [ -n "${insecure_reason}" ]; then
                insecure_found=true
                perm_report="${perm_report}"$'\n'"[취약] ${tpath} (${octal}, ${owner}:${group}) - ${insecure_reason}"
            else
                perm_report="${perm_report}"$'\n'"[양호] ${tpath} (${octal}, ${owner}:${group})"
            fi
        fi
    done

    command_executed="stat -c '%a %U:%G %n' /etc/apache2/apache2.conf /etc/apache2 /etc/httpd/conf/httpd.conf /etc/httpd 2>/dev/null"
    command_result="${perm_report#$'\n'}"

    if [ "${checked_any}" != true ]; then
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="Apache 주요 설정 파일/디렉터리를 찾을 수 없어 접근 권한을 확인할 수 없습니다. 설정 파일/디렉터리의 권한(chmod 750 권장)을 수동으로 확인하세요."
        command_result="No Apache config file/directory found"
    elif [ "${insecure_found}" = true ]; then
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="주요 설정 파일/디렉터리에 일반 사용자(group 쓰기 또는 other 접근)의 불필요한 접근 권한이 부여되어 있습니다. chmod 750 등으로 불필요한 권한을 제거하세요."
    else
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="주요 설정 파일/디렉터리에 일반 사용자의 불필요한 접근 권한(group 쓰기/other 접근)이 부여되어 있지 않습니다. (보안 권고사항 준수)"
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
