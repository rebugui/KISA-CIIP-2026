#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : WEB-24
# @Category    : Web Server
# @Platform    : Nginx_Linux
# @Severity    : 중
# @Title       : 별도의 업로드 경로 사용 및 권한 설정
# @Description : 파일 업로드 경로의 웹 루트 분리 및 일반 사용자 접근 권한 제한 여부 점검
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

ITEM_ID="WEB-24"
ITEM_NAME="별도의 업로드 경로 사용 및 권한 설정"
SEVERITY="중"

GUIDELINE_PURPOSE="웹 서버 루트 디렉터리 내 업로드 경로가 아닌 별도의 디렉터리에서 파일을 업로드할 수 있도록하여 루트 디렉터리 내 악의적인 파일 업로드 및 실행을 방지하기 위함"
GUIDELINE_THREAT="웹 서버 내 별도의 파일 업로드 경로 사용 및 적절한 권한 설정을 하지 않을 경우, 악의적인 목적을 가진 파일을 업로드하여 시스템 침투, 중요 정보 유출 및 변조 등의 침해 사고의 가능성이 있음"
GUIDELINE_CRITERIA_GOOD="별도의 업로드 경로를 사용하고 일반 사용자의 접근 권한이 부여되지 않은 경우"
GUIDELINE_CRITERIA_BAD="별도의 업로드 경로를 사용하지 않거나, 일반 사용자의 접근 권한이 부여된 경우"
GUIDELINE_REMEDIATION="기본 경로가 아닌 별도의 업로드 경로를 지정하고, 해당 경로에 대한 일반 사용자의 접근 권한을 제한하도록 설정"

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

    local nginx_conf_locations=(
        "/etc/nginx/nginx.conf"
        "/etc/nginx/conf.d/*.conf"
        "/etc/nginx/sites-enabled/*.conf"
    )

    # WEB-24 판단기준: 별도의 업로드 경로를 사용하고(웹 루트와 분리) 일반 사용자의 접근 권한이 없는 경우 양호.
    # 1) 웹 루트(root) 경로 수집
    # 2) 업로드 관련 디렉티브(location /upload, alias/root 내 upload 경로, client_body_temp_path) 수집
    # 3) 업로드 경로가 웹 루트 하위에 있으면 취약(분리되지 않음)
    # 4) 업로드 경로가 일반 사용자(other) 접근 권한을 가지면 취약
    # 5) 업로드 디렉티브를 정적으로 확정할 수 없으면 수동진단(GOOD로 단정하지 않음)

    local web_roots=""
    local upload_lines=""
    local upload_paths=""

    for conf_pattern in "${nginx_conf_locations[@]}"; do
        for conf_file in $conf_pattern; do
            if [ -f "${conf_file}" ] && [ -r "${conf_file}" ]; then
                # 웹 루트 수집
                local found_root=$(grep -E "^\s*root\s+" "${conf_file}" 2>/dev/null | grep -v "^\s*#" \
                    | sed -E 's/^\s*root\s+//; s/;.*$//' | tr -d ' ' || true)
                if [ -n "${found_root}" ]; then
                    web_roots="${web_roots}"$'\n'"${found_root}"
                fi
                # 업로드 관련 디렉티브 수집 (location ~ /upload, client_body_temp_path, alias 내 upload)
                local found_upload=$(grep -nE "(location\s+[^;{]*upload|client_body_temp_path|alias\s+[^;]*upload|root\s+[^;]*upload)" "${conf_file}" 2>/dev/null | grep -v "^\s*#" || true)
                if [ -n "${found_upload}" ]; then
                    upload_lines="${upload_lines}"$'\n'"${conf_file}:${found_upload}"
                    # alias/root/client_body_temp_path 가 가리키는 실제 경로 추출
                    local extracted=$(echo "${found_upload}" | sed -nE 's#.*(client_body_temp_path|alias|root)\s+([^; ]+).*#\2#p' || true)
                    if [ -n "${extracted}" ]; then
                        upload_paths="${upload_paths}"$'\n'"${extracted}"
                    fi
                fi
            fi
        done
    done

    # 기본 웹 루트 보강
    if [ -z "$(echo "${web_roots}" | tr -d '[:space:]')" ]; then
        web_roots=$'\n'"/usr/share/nginx/html"$'\n'"/var/www/html"
    fi

    command_executed="grep -nE '(location.*upload|client_body_temp_path|alias.*upload|root.*upload)' /etc/nginx/nginx.conf /etc/nginx/conf.d/*.conf /etc/nginx/sites-enabled/*.conf 2>/dev/null | grep -v '^\\s*#'"

    # 업로드 디렉티브 미발견 → 정적으로 별도 업로드 경로 사용/권한 여부를 확정할 수 없음 → 수동진단
    if [ -z "$(echo "${upload_lines}" | tr -d '[:space:]')" ]; then
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="Nginx 설정에서 업로드 전용 디렉티브(location /upload, client_body_temp_path, alias 등)를 찾지 못했습니다. 파일 업로드는 주로 애플리케이션 레벨에서 처리되므로, 실제 업로드 경로의 웹 루트 분리 여부 및 일반 사용자 접근 권한을 수동으로 확인하세요."
        command_result="No upload-specific directive found. Web roots:${web_roots}"
    else
        # 업로드 경로가 웹 루트 하위에 있는지 / 일반 사용자(other) 접근 권한이 있는지 점검
        local inside_root=""
        local world_accessible=""
        local perm_verified=""
        local p r
        for p in ${upload_paths}; do
            [ -z "${p}" ] && continue
            # 웹 루트 하위 여부
            for r in ${web_roots}; do
                [ -z "${r}" ] && continue
                case "${p}" in
                    "${r}"|"${r}"/*)
                        inside_root="${inside_root} ${p}(root:${r})"
                        ;;
                esac
            done
            # other 접근 권한 점검 (디렉터리가 실제 존재하는 경우)
            if [ -d "${p}" ]; then
                local perm operm
                perm=$(stat -c '%a' "${p}" 2>/dev/null || true)
                if [ -n "${perm}" ]; then
                    perm_verified="${perm_verified} ${p}"
                    operm="${perm: -1}"
                    if [ "${operm}" -ne 0 ]; then
                        world_accessible="${world_accessible} ${p}(${perm})"
                    fi
                fi
            fi
        done

        command_result="Upload directives:${upload_lines}"$'\n'"Resolved upload paths:${upload_paths}"$'\n'"Web roots:${web_roots}"

        if [ -n "${inside_root}" ] || [ -n "${world_accessible}" ]; then
            diagnosis_result="VULNERABLE"
            status="취약"
            inspection_summary="업로드 경로가 웹 루트 내부에 위치하거나 일반 사용자(other) 접근 권한이 부여되어 있습니다."
            [ -n "${inside_root}" ] && inspection_summary="${inspection_summary} [웹 루트 하위 업로드 경로:${inside_root}]"
            [ -n "${world_accessible}" ] && inspection_summary="${inspection_summary} [other 접근 권한 부여:${world_accessible}]"
            inspection_summary="${inspection_summary} 웹 루트 외부 별도 경로 사용 및 chmod 750(일반 사용자 접근 제거)을 설정하세요."
        elif [ -z "$(echo "${upload_paths}" | tr -d '[:space:]')" ]; then
            # 업로드 디렉티브는 있으나 경로를 정적으로 확정할 수 없음 → 수동진단
            diagnosis_result="MANUAL"
            status="수동진단"
            inspection_summary="업로드 관련 디렉티브가 발견되었으나 실제 업로드 저장 경로를 정적으로 확정할 수 없습니다. 업로드 경로의 웹 루트 분리 여부와 일반 사용자 접근 권한을 수동으로 확인하세요. 발견된 디렉티브:${upload_lines}"
        elif [ -z "$(echo "${perm_verified}" | tr -d '[:space:]')" ]; then
            # 업로드 경로는 웹 루트 외부로 확인되었으나, 해당 디렉터리가 점검 호스트에 존재하지 않거나 읽을 수 없어 일반 사용자(other) 접근 권한을 실제로 확인하지 못함 → GOOD로 단정 불가, 수동진단
            diagnosis_result="MANUAL"
            status="수동진단"
            inspection_summary="업로드 경로가 웹 루트 외부로 확인되었으나, 해당 디렉터리가 점검 호스트에 존재하지 않거나 접근할 수 없어 일반 사용자(other) 접근 권한을 확인하지 못했습니다. 실제 업로드 디렉터리의 파일시스템 권한(chmod 750 등 일반 사용자 접근 제한 여부)을 수동으로 확인하세요. 업로드 경로:${upload_paths}"
        else
            diagnosis_result="GOOD"
            status="양호"
            inspection_summary="업로드 경로가 웹 루트 외부의 별도 경로로 설정되어 있으며 일반 사용자(other) 접근 권한이 부여되어 있지 않습니다. (보안 권고사항 준수) 업로드 경로:${upload_paths}"
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
