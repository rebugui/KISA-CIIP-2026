#!/bin/bash

# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : D-14
# @Category    : DBMS (Database Management System)
# @Platform    : postgresql_Linux
# @Severity    : 중
# @Title       : 데이터베이스의 주요 설정 파일, 비밀번호 파일 등과 같은 주요 파일들의 접근 권한이 적절하게 설정
# @Description : 과도한 권한 부여 방지 및 최소 권한 원칙 적용
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/command_validator.sh"
source "${LIB_DIR}/timeout_handler.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/db_connection_helpers.sh"

ITEM_ID="D-14"
ITEM_NAME="데이터베이스의 주요 설정 파일, 비밀번호 파일 등과 같은 주요 파일들의 접근 권한이 적절하게 설정"
SEVERITY="중"

GUIDELINE_PURPOSE="데이터베이스의 주요 파일에 관리자를 제외한 일반 사용자의 파일 수정 권한을 제거함으로써 비인가자에 의한 DBMS 주요 파일 변경이나 삭제를 방지하고 주요 정보 유출을 방지할 수 있음"
GUIDELINE_THREAT="데이터베이스 주요 파일에 비인가자가 접근하여 수정 및 삭제 시 데이터베이스 운영에 장애가 발생할 수 있으며 계정 비밀번호 정보 등 중요 정보의 유출 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="주요 설정 파일 및 디렉터리의 권한 설정 시 일반 사용자의 수정 권한을 제거한 경우"
GUIDELINE_CRITERIA_BAD="주요 설정 파일 및 디렉터리의 권한 설정 시 일반 사용자의 수정 권한을 제거하지 않은 경우"
GUIDELINE_REMEDIATION="주요 설정 파일 및 디렉터리의 권한 설정 변경"

diagnose() {
    echo "진단 항목: ${ITEM_ID} - ${ITEM_NAME}"

    # D-14는 OS 파일 권한 항목이므로 psql 도구나 DB 연결이 필요하지 않음.
    # stat 만으로 설정 파일 권한을 점검함.

    local diagnosis_result="GOOD"
    local status="양호"
    local inspection_summary=""
    local command_result=""
    local command_executed=""

    # D-14는 DBMS grant 항목이 아니라 OS 파일 접근 권한 항목임.
    # PostgreSQL 주요 설정 파일(postgresql.conf, pg_hba.conf, pg_ident.conf)의
    # 권한이 640 이하이고 소유자가 postgres 또는 root 인지 stat 으로 점검.
    # 기준(docs/09_DBMS.md): 설정 파일은 일반 사용자의 수정 권한이 없어야 함(600/640).

    # 데이터 디렉터리 후보 탐색
    local data_dir=""
    local candidate
    for candidate in \
        "${PGDATA:-}" \
        "/var/lib/postgresql/data" \
        /var/lib/postgresql/*/main \
        /var/lib/pgsql/data \
        /var/lib/pgsql/*/data \
        /usr/local/pgsql/data; do
        [ -n "${candidate}" ] || continue
        if [ -f "${candidate}/postgresql.conf" ]; then
            data_dir="${candidate}"
            break
        fi
    done

    command_executed="stat -c '%a %U:%G %n' <postgresql.conf|pg_hba.conf|pg_ident.conf>"

    local config_files=()
    if [ -n "${data_dir}" ]; then
        for candidate in "postgresql.conf" "pg_hba.conf" "pg_ident.conf"; do
            [ -f "${data_dir}/${candidate}" ] && config_files+=("${data_dir}/${candidate}")
        done
    fi

    if [ "${#config_files[@]}" -eq 0 ]; then
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="PostgreSQL 설정 파일을 자동으로 찾지 못했습니다. postgresql.conf/pg_hba.conf/pg_ident.conf 권한을 수동으로 점검하세요(자동 점검 불가)."
        command_result="data_dir not found"
        save_dual_result "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" "${inspection_summary}" "${command_result}" "${command_executed}" "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
        verify_result_saved "${ITEM_ID}"
        return 0
    fi

    local bad_files=""
    local checked=""
    local target
    local file_stat
    local mode
    local owner
    local group_digit
    local other_digit
    for target in "${config_files[@]}"; do
        file_stat="$(stat -c '%a %U:%G %n' "${target}" 2>/dev/null || true)"
        [ -n "${file_stat}" ] || continue
        checked+="${file_stat}"$'\n'
        mode="${file_stat%% *}"
        owner="$(stat -c '%U' "${target}" 2>/dev/null || echo "")"
        # 소유자가 postgres/root 가 아니면 취약
        if [ "${owner}" != "postgres" ] && [ "${owner}" != "root" ] && [ "${owner}" != "enterprisedb" ]; then
            bad_files+="${file_stat} (소유자 비정상: ${owner})"$'\n'
            continue
        fi
        # 3자리 8진 권한에서 group/other 자릿수 검사
        # 640 초과(그룹 write 또는 other 임의 권한)면 취약
        group_digit="${mode: -2:1}"
        other_digit="${mode: -1}"
        # group: 4(r),0 허용 / 6,7,2,3(w 포함) 취약
        case "${group_digit}" in
            *[2367]) bad_files+="${file_stat} (그룹 쓰기 권한)"$'\n' ; continue ;;
        esac
        # other: 0 이외(r/w/x 모두)면 취약 (640 기준 other=0)
        if [ "${other_digit}" != "0" ]; then
            bad_files+="${file_stat} (other 권한 존재)"$'\n'
        fi
    done

    command_result="${checked}"

    if [ -n "${bad_files}" ]; then
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="과도한 권한(640 초과 또는 비인가 소유자)이 설정된 PostgreSQL 설정 파일 발견:"$'\n'"${bad_files}"
    else
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="PostgreSQL 주요 설정 파일 권한 양호(640 이하, 소유자 postgres/root/enterprisedb):"$'\n'"${checked}"
    fi

    save_dual_result "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" "${inspection_summary}" "${command_result}" "${command_executed}" "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
    verify_result_saved "${ITEM_ID}"

    return 0
}

main() {
    diagnose
}

if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi
