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
# @Platform    : Nginx_Linux
# @Severity    : 상
# @Title       : 웹 서비스 경로 내 파일의 접근 통제
# @Description : Nginx default server block 설정 적절성 여부 점검
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

    local diagnosis_result="GOOD"
    local status="양호"
    local inspection_summary=""
    local command_result=""
    local command_executed=""
    local nginx_running=true
    if command -v pgrep >/dev/null 2>&1; then
        if ! pgrep -x "nginx" > /dev/null 2>&1; then
            nginx_running=false
        fi
    else
        echo "[INFO] pgrep command missing, skipping process check."
    fi
    if [ "${nginx_running}" = false ]; then
        diagnosis_result="N/A"; status="N/A"
        inspection_summary="Nginx 웹 서버가 실행 중이 아닙니다."
        command_result="Nginx process not found"
        command_executed="pgrep -x nginx"
    else
        # 주요 설정 파일 및 웹 루트 디렉터리의 권한(타 사용자 쓰기 권한) 점검
        # 판단기준: 불필요한 접근 권한(world-writable, others-write 비트)이 부여되면 취약
        local web_root
        web_root=$(grep -rhE "^\s*root\s+" /etc/nginx/ 2>/dev/null | grep -v "^\s*#" \
            | sed -E 's/^\s*root\s+//; s/;.*$//' | tr -d ' ' | head -1 || true)
        [ -z "${web_root}" ] && web_root="/usr/share/nginx/html"
        web_root="${web_root%/}"  # 후행 슬래시 제거

        local targets=(
            "/etc/nginx/nginx.conf"
            "/etc/nginx/conf.d"
            "${web_root}"
        )
        # conf.d 내 개별 설정 파일도 대상에 포함
        local f
        for f in /etc/nginx/conf.d/*.conf; do
            [ -e "${f}" ] && targets+=("${f}")
        done

        command_executed="stat -c '%a %U %n' /etc/nginx/nginx.conf /etc/nginx/conf.d ${web_root}"

        local insecure_list=""
        local webroot_manual_needed=false
        local detail=""
        local t perm operm gperm
        for t in "${targets[@]}"; do
            [ -e "${t}" ] || continue
            perm=$(stat -c '%a' "${t}" 2>/dev/null || true)
            [ -z "${perm}" ] && continue
            detail="${detail}"$'\n'"$(stat -c '%a %U:%G %n' "${t}" 2>/dev/null || true)"
            # 4자리(setuid/setgid/sticky 포함) 모드 대응: 마지막 3자리(소유자/그룹/기타)로 정규화
            local perm3="${perm: -3}"
            # others 권한 비트 (8진수 마지막 자리), group 권한 비트 (마지막에서 두 번째 자리)
            operm="${perm3:2:1}"
            gperm="${perm3:1:1}"
            [ -z "${operm}" ] && operm=0
            [ -z "${gperm}" ] && gperm=0
            # 판단기준(chmod 750): 일반 사용자(group/other)에게 불필요한 접근 권한이 부여되면 취약.
            # - others에 어떤 권한이든(r/w/x, 8진수 마지막 자리 != 0) 부여 → 민감 파일(nginx.conf 등) 읽기 노출 포함하여 취약
            # - group에 쓰기 비트(2) 부여 → 취약
            if [ "${t}" = "${web_root}" ]; then
                # 웹 루트 디렉터리: others 읽기/실행은 nginx worker에 필요하므로 쓰기 권한 검사만 수행
                if [ $(( ${operm} & 2 )) -ne 0 ] || [ $(( gperm & 2 )) -ne 0 ]; then
                    insecure_list="${insecure_list} ${t}(${perm})"
                elif [ "${operm}" -ne 0 ]; then
                    webroot_manual_needed=true
                fi
            else
                if [ "${operm}" -ne 0 ] || [ $(( gperm & 2 )) -ne 0 ]; then
                    insecure_list="${insecure_list} ${t}(${perm})"
                fi
            fi
        done

        command_result="${detail}"

        if [ -n "${insecure_list}" ]; then
            diagnosis_result="VULNERABLE"; status="취약"
            inspection_summary="주요 설정 파일/디렉터리 또는 웹 루트에 일반 사용자(group 쓰기 또는 other 읽기/쓰기/실행)의 불필요한 접근 권한이 부여되어 있습니다:${insecure_list}. 불필요한 접근 권한을 제거하세요(chmod 750 등)."
        elif [ "${webroot_manual_needed}" = true ]; then
            diagnosis_result="MANUAL"; status="수동진단"
            inspection_summary="웹 루트 디렉터리(${web_root})에 타 사용자(other) 읽기/실행 권한이 설정되어 있습니다. 웹 서비스 제공을 위해 필요한 권한일 수 있으나, 기관 정책에 따라 불필요한 접근 권한 존재 여부를 확인하세요."
        else
            diagnosis_result="GOOD"; status="양호"
            inspection_summary="주요 설정 파일/디렉터리 및 웹 루트에 타 사용자(other) 접근 권한 및 group 쓰기 권한 등 불필요한 접근 권한이 부여되어 있지 않습니다."
        fi
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
