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
# @Platform    : Oracle_Linux
# @Severity    : 중
# @Title       : 데이터베이스의 주요 설정 파일, 비밀번호 파일 등과 같은 주요 파일들의 접근 권한이 적절하게 설정
# @Description : Oracle 주요 설정파일 및 비밀번호 파일 접근권한 확인
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
source "${LIB_DIR}/dbms_connector.sh"
source "${LIB_DIR}/db_connection_helpers.sh"

# Oracle 연결 정보 초기화 (fallback if library not loaded)
ORACLE_USER="${ORACLE_USER:-system}"
ORACLE_PASSWORD="${ORACLE_PASSWORD:-manager}"
ORACLE_HOST="${ORACLE_HOST:-localhost}"
ORACLE_PORT="${ORACLE_PORT:-1521}"
ORACLE_SID="${ORACLE_SID:-ORCL}"
ORACLE_SYSDBA="${ORACLE_SYSDBA:-sys as sysdba}"

ITEM_ID="D-14"
ITEM_NAME="데이터베이스의 주요 설정 파일, 비밀번호 파일 등과 같은 주요 파일들의 접근 권한이 적절하게 설정"
SEVERITY="중"

GUIDELINE_PURPOSE="데이터베이스의 주요 파일에 관리자를 제외한 일반 사용자의 파일 수정 권한을 제거함으로써 비인가자에 의한 DBMS 주요 파일 변경이나 삭제를 방지하고 주요 정보 유출을 방지할 수 있음"
GUIDELINE_THREAT="데이터베이스 주요 파일에 비인가자가 접근하여 수정 및 삭제 시 데이터베이스 운영에 장애가 발생할 수 있으며 계정 비밀번호 정보 등 중요 정보의 유출 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="주요 설정 파일 및 디렉터리의 권한 설정 시 일반 사용자의 수정 권한을 제거한 경우"
GUIDELINE_CRITERIA_BAD="주요 설정 파일 및 디렉터리의 권한 설정 시 일반 사용자의 수정 권한을 제거하지 않은 경우"
GUIDELINE_REMEDIATION="주요 설정 파일 및 디렉터리의 권한 설정 변경"

diagnose() {
    diagnosis_result="unknown"  # Global variable (not local)
    local status="수동진단"
    local inspection_summary=""
    local command_result=""
    local command_executed=""

    # Initialize Oracle connection variables (only if library function exists)
    if declare -f init_oracle_vars >/dev/null 2>&1; then
        init_oracle_vars
    fi

    echo "진단 항목: ${ITEM_ID} - ${ITEM_NAME}"

    # FR-022: Check required tools (only if library function exists)
    if declare -f check_oracle_tools >/dev/null 2>&1; then
        if ! check_oracle_tools; then
            if declare -f handle_missing_tools >/dev/null 2>&1; then
                handle_missing_tools "oracle" "${ITEM_ID}" "${ITEM_NAME}" \
                    "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" \
                    "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
            fi
            return 0
        fi
    fi

    local diagnosis_result="MANUAL" status="수동진단" inspection_summary="" command_result="" command_executed=""

    if ! systemctl is-active oracle &>/dev/null && ! pgrep -f "ora_pmon" &>/dev/null; then
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="서비스 미실행으로 자동 점검 불가 (수동진단 필요). 서비스 시작 후 주요 설정/비밀번호 파일의 접근 권한을 수동으로 확인하세요."
        command_result="Oracle process not found"
        command_executed="systemctl is-active oracle; pgrep -f ora_pmon"
        if declare -f save_dual_result >/dev/null 2>&1; then
            save_dual_result "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" "${inspection_summary}" "${command_result}" "${command_executed}" "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
        fi
        if declare -f verify_result_saved >/dev/null 2>&1; then
            verify_result_saved "${ITEM_ID}"
        fi
        return 0
    fi

    # Oracle 홈 디렉토리 찾기
    local oracle_home=""
    if [ -n "${ORACLE_HOME:-}" ]; then
        oracle_home="$ORACLE_HOME"
    else
        oracle_home=$(pgrep -f "ora_pmon" | head -1 | xargs -I{} readlink -f /proc/{}/cwd 2>/dev/null | sed 's|/dbs$||' || echo "")
    fi

    if [ -z "$oracle_home" ]; then
        inspection_summary="Oracle 홈 디렉토리를 찾을 수 없습니다. ORACLE_HOME 환경변수를 설정하거나 Oracle이 실행 중인지 확인하세요."
        diagnosis_result="MANUAL"
        status="수동진단"
        command_executed="echo \$ORACLE_HOME; pgrep -f ora_pmon"
        if declare -f save_dual_result >/dev/null 2>&1; then
            save_dual_result "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" "${inspection_summary}" "${command_result}" "${command_executed}" "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
        fi
        if declare -f verify_result_saved >/dev/null 2>&1; then
            verify_result_saved "${ITEM_ID}"
        fi
        return 0
    fi

    # 주요 Oracle 파일들 확인
    local vulnerable_files=()
    local good_files=()
    local checked_files=()

    # 확인할 파일 목록
    local config_files=(
        "$oracle_home/network/admin/listener.ora"
        "$oracle_home/network/admin/tnsnames.ora"
        "$oracle_home/network/admin/sqlnet.ora"
    )

    # 비밀번호 파일 찾기 (orapw<SID>)
    if [ -d "$oracle_home/dbs" ]; then
        while IFS= read -r -d '' pw_file; do
            config_files+=("$pw_file")
        done < <(find "$oracle_home/dbs" -name "orapw*" -type f -print0 2>/dev/null || true)
    fi

    # 파라미터 파일 찾기 (spfile<SID>.ora)
    if [ -d "$oracle_home/dbs" ]; then
        while IFS= read -r -d '' sp_file; do
            config_files+=("$sp_file")
        done < <(find "$oracle_home/dbs" -name "spfile*.ora" -type f -print0 2>/dev/null || true)
    fi

    command_executed="ls -la ${oracle_home}/network/admin/*.ora 2>/dev/null; ls -la ${oracle_home}/dbs/orapw* ${oracle_home}/dbs/spfile*.ora 2>/dev/null"

    for file in "${config_files[@]}"; do
        if [ ! -f "$file" ]; then
            continue
        fi

        checked_files+=("$file")

        # 파일 권한 확인
        local perms=$(stat -c "%a" "$file" 2>/dev/null || echo "000")
        local owner=$(stat -c "%U" "$file" 2>/dev/null || echo "unknown")
        local group=$(stat -c "%G" "$file" 2>/dev/null || echo "unknown")

        # 파일 정보 수집
        local file_info="$file: perms=$perms, owner=$owner, group=$group"
        command_result+="$file_info\n"

        # 취약성 판단
        # oracle/root 소유가 아니거나, 640 을 초과하는 권한 비트가 있는 경우 취약
        # (8진수 권한을 비트 연산으로 비교: 640 이하면 ~640 마스크에 걸리는 비트가 없어야 함)
        if [ "$owner" != "oracle" ] && [ "$owner" != "root" ]; then
            vulnerable_files+=("$file (owner=$owner)")
        elif ! [[ "$perms" =~ ^[0-7]{3,4}$ ]] || [ "$(( 8#$perms & ~8#640 & 07777 ))" -ne 0 ]; then
            vulnerable_files+=("$file (perms=$perms)")
        else
            good_files+=("$file")
        fi
    done

    # 결과 판정
    if [ ${#vulnerable_files[@]} -gt 0 ]; then
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="Oracle 주요 파일의 접근권한이 취약합니다.\n\n"
        inspection_summary+="취약한 파일 (${#vulnerable_files[@]}개):\n"
        for file in "${vulnerable_files[@]}"; do
            inspection_summary+="  - $file\n"
        done
        if [ ${#good_files[@]} -gt 0 ]; then
            inspection_summary+="\n양호한 파일 (${#good_files[@]}개):\n"
            for file in "${good_files[@]}"; do
                inspection_summary+="  - $file\n"
            done
        fi
        inspection_summary+="\n조치: chown oracle:oinstall file && chmod 640 file"
    elif [ ${#checked_files[@]} -eq 0 ]; then
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="Oracle 주요 파일을 찾을 수 없습니다. Oracle이 설치된 경로를 확인하세요.\n\n확인한 경로: $oracle_home\n\n수동으로 다음 파일들을 확인하세요:\n"
        inspection_summary+="- \$ORACLE_HOME/network/admin/listener.ora\n"
        inspection_summary+="- \$ORACLE_HOME/network/admin/tnsnames.ora\n"
        inspection_summary+="- \$ORACLE_HOME/network/admin/sqlnet.ora\n"
        inspection_summary+="- \$ORACLE_HOME/dbs/orapw<SID>\n"
        inspection_summary+="- \$ORACLE_HOME/dbs/spfile<SID>.ora"
    else
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="Oracle 주요 파일의 접근권한이 적절하게 설정되어 있습니다.\n\n확인한 파일 (${#checked_files[@]}개):\n"
        for file in "${checked_files[@]}"; do
            inspection_summary+="  - $file\n"
        done
        inspection_summary+="\n모든 파일이 oracle 소유이며 600/640 권한입니다."
    fi

        if declare -f save_dual_result >/dev/null 2>&1; then
            save_dual_result "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" "${inspection_summary}" "${command_result}" "${command_executed}" "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
        fi
    if declare -f verify_result_saved >/dev/null 2>&1; then
        verify_result_saved "${ITEM_ID}"
    fi
    return 0
}

main() {
    diagnose
}

if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi
