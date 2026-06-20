#!/bin/bash

# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : D-03
# @Category    : DBMS (Database Management System)
# @Platform    : postgresql_Linux
# @Severity    : 상
# @Title       : 비밀번호 사용 기간 및 복잡 도를 기관의 정책에 맞도록 설정
# @Description : 비밀번호 정책 및 설정 관리를 통한 무단 접근 방지
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

ITEM_ID="D-03"
ITEM_NAME="비밀번호 사용 기간 및 복잡 도를 기관의 정책에 맞도록 설정"
SEVERITY="상"

GUIDELINE_PURPOSE="비밀번호 사용 기간 및 복잡 도 설정 유무를 점검하여 비인가자의 비밀번호 추측 공격(무차별 대입 공격, 사전 대입 공격 등)에 대한 대비가 되어 있는지 확인하기 위함"
GUIDELINE_THREAT="비밀번호 사용 기간 및 복잡 도 설정이 되어 있지 않으면 비인가자가 비밀번호 추측 공격을 통해 획득한 계정의 비밀번호를 이용하여 DB에 접근할 수 있는 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="기관 정책에 맞게 비밀번호 사용 기간 및 복잡 도 설정이 적용된 경우"
GUIDELINE_CRITERIA_BAD="기관 정책에 맞게 비밀번호 사용 기간 및 복잡 도 설정이 적용되지 않은 경우"
GUIDELINE_REMEDIATION="기관 정책에 맞게 비밀번호 사용 기간 및 복잡 도 정책 설정"

diagnose() {
    echo "진단 항목: ${ITEM_ID} - ${ITEM_NAME}"

    # FR-022: Check required tools
    if ! check_postgresql_tools; then
        handle_missing_tools "postgresql" "${ITEM_ID}" "${ITEM_NAME}" \
            "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" \
            "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
        return 0
    fi


    local diagnosis_result="GOOD"
    local status="양호"
    local inspection_summary=""
    local command_result=""
    local command_executed=""
    local vulnerabilities_found=0
    local encryption_indeterminate=0
    local expiry_indeterminate=0
    local complexity_indeterminate=0

    # Initialize PostgreSQL connection variables
    init_postgresql_vars

    # PostgreSQL 서비스 확인
    if ! check_postgresql_service; then
        handle_dbms_not_running "postgresql" "${ITEM_ID}" "${ITEM_NAME}" \
            "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" \
            "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
        return 0
    fi

    # PostgreSQL 연결 시도 (FR-018)
    if ! prompt_postgresql_connection; then
        handle_dbms_connection_failed "postgresql" "${ITEM_ID}" "${ITEM_NAME}" \
            "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" \
            "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
        return 0
    fi

    # 비밀번호 암호화 방식 확인
    # SHOW password_encryption 실패/빈 결과 시 양호로도 취약으로도 단정할 수 없으므로
    # 만료/복잡도 검사와 동일하게 indeterminate 플래그를 세워 수동진단으로 강등한다
    # (거짓 양호 방지와 동시에 일시 오류로 인한 거짓 취약 방지).
    local password_enc_query="SHOW password_encryption;"
    command_result=$(PGPASSWORD="${DB_ADMIN_PASS}" psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_ADMIN_USER}" -d postgres -t -c "${password_enc_query}" 2>/dev/null | xargs || echo "")

    if [ -n "$command_result" ]; then
        if [ "$command_result" = "scram-sha-256" ] || [ "$command_result" = "md5" ]; then
            inspection_summary+="양호: 비밀번호 암호화 ${command_result} 사용; "
        else
            ((vulnerabilities_found++)) || true
            inspection_summary+="취약: 비밀번호 암호화가 ${command_result}로 설정됨; "
        fi
    else
        # 암호화 설정 조회 결과가 비어 있음(권한 오류/일시 장애 등):
        # 양호/취약 어느 쪽으로도 단정할 수 없으므로 수동진단으로 강등
        encryption_indeterminate=1
        inspection_summary+="수동확인 필요: 비밀번호 암호화 설정 조회 불가(결과 불명확); "
    fi

    # 비밀번호 만료 정책 확인
    # rolvaliduntil 이 NULL 이거나 'infinity' 이면 만료 정책이 없는 것(취약)이다.
    # NULL 은 psql -t 출력에서 빈 문자열로 렌더되어 'infinity' 문자열 검색만으로는
    # 만료 미설정을 탐지할 수 없으므로(거짓 양호), 서버측에서 불리언으로 평가한다.
    local password_expiry_query="SELECT CASE WHEN rolvaliduntil IS NULL OR rolvaliduntil = 'infinity' THEN 'NO_EXPIRY' ELSE 'HAS_EXPIRY' END FROM pg_authid WHERE rolname='postgres';"
    local expiry_result=$(PGPASSWORD="${DB_ADMIN_PASS}" psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_ADMIN_USER}" -d postgres -t -A -c "${password_expiry_query}" 2>/dev/null | xargs || echo "")

    if [ "$expiry_result" = "NO_EXPIRY" ]; then
        ((vulnerabilities_found++)) || true
        inspection_summary+="취약: postgres 계정 비밀번호 만료 기간 없음(rolvaliduntil NULL/infinity); "
    elif [ "$expiry_result" = "HAS_EXPIRY" ]; then
        inspection_summary+="양호: 비밀번호 만료 정책 설정됨; "
    else
        # 만료 조회 결과가 비어 있거나 예상치 못한 값(접속 후 권한 오류 등):
        # 만료 여부를 검증할 수 없으므로 양호로 단정할 수 없음 -> 수동진단으로 강등
        expiry_indeterminate=1
        inspection_summary+="수동확인 필요: 비밀번호 만료 정책 조회 불가(결과 불명확); "
    fi

    # 비밀번호 복잡도 확인 (passwordcheck)
    # passwordcheck 는 shared_preload_libraries 에 미리 로드(preload)된 경우에만
    # 실제로 복잡도를 강제한다. pg_available_extensions 는 contrib 패키지가 설치되어
    # 디스크에 control 파일이 존재하는지(=가용 여부)만 나타내므로, 가용/설치만으로
    # 복잡도가 강제된다고 단정하면 거짓 양호가 발생한다.
    # 따라서 shared_preload_libraries 에 'passwordcheck' 가 실제로 로드되어 있는지로
    # 강제 여부를 판단한다.
    local preload_query="SHOW shared_preload_libraries;"
    local preload_result=$(PGPASSWORD="${DB_ADMIN_PASS}" psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_ADMIN_USER}" -d postgres -t -A -c "${preload_query}" 2>/dev/null | xargs || echo "__QUERY_FAILED__")

    if [ "$preload_result" = "__QUERY_FAILED__" ]; then
        # 로드 라이브러리 조회 실패: 강제 여부 검증 불가 -> 자동 양호 단정 불가
        complexity_indeterminate=1
        inspection_summary+="수동확인 필요: shared_preload_libraries 조회 불가(복잡도 강제 여부 불명확); "
    elif printf '%s' "$preload_result" | grep -qw "passwordcheck"; then
        inspection_summary+="양호: passwordcheck 가 shared_preload_libraries 에 로드되어 복잡도 강제됨; "
    else
        ((vulnerabilities_found++)) || true
        inspection_summary+="취약: passwordcheck 가 shared_preload_libraries 에 로드되지 않아 복잡도 미강제; "
    fi

    if [ $vulnerabilities_found -gt 0 ]; then
        diagnosis_result="VULNERABLE"
        status="취약"
    elif [ $encryption_indeterminate -gt 0 ] || [ $expiry_indeterminate -gt 0 ] || [ $complexity_indeterminate -gt 0 ]; then
        # 암호화/만료 정책/복잡도 강제 여부를 검증할 수 없으면 양호로 단정 불가 -> 수동진단 (거짓 양호 방지)
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary+="비밀번호 암호화/만료 정책 또는 복잡도 강제 여부 검증 불가로 자동 양호 판단 불가 (수동진단 필요); "
    else
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="비밀번호 정책이 적절히 설정됨"
    fi
    command_executed="psql -h ${DB_HOST} -p ${DB_PORT} -U ${DB_ADMIN_USER} -d postgres -c \"SHOW password_encryption; SHOW shared_preload_libraries;\""

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
