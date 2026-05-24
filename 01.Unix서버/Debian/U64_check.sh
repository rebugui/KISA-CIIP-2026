#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : U-64
# @Category    : Unix Server
# @Platform    : Debian
# @Severity    : 상
# @Title       : 주기적 보안 패치 및 벤더 권고 사항 적용
# @Description : 커널 및 패키지 버전 확인
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

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


ITEM_ID="U-64"
ITEM_NAME="주기적 보안 패치 및 벤더 권고 사항 적용"
SEVERITY="상"

# 가이드라인 정보
GUIDELINE_PURPOSE="주기적인 패치 적용을 통해 시스템 안정성 및 보안성을 확보하기 위함"
GUIDELINE_THREAT="최신 보안 패치가 적용되지 않을 경우, 이미 알려진 취약점을 통하여 공격자에 의해 시스템 침해 사고 발생할 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="패치 적용 정책을 수립하여 주기적으로 패치 관리를 하고 있으며, 패치 관련 내용을 확인하고 적용하였을 경우"
GUIDELINE_CRITERIA_BAD="패치 적용 정책이 미수립되었거나 주기적으로 패치 관리를 하지 않는 경우"
GUIDELINE_REMEDIATION="OS 관리자, 서비스 개발자가 패치 적용에 따른 서비스 영향 정도를 파악하여 OS 관리자 및 벤더에서 적용하도록 설정 ※ OS 패치의 경우 지속해서 취약점이 발표되고 있으므로 O/S 관리자, 서비스 개발자가 패치 적용에 따른 서비스 영향 정도를 정확히 파악하여 주기적인 패치 적용 정책을 수립하여 적용해야 함"

# ============================================================================
# 진단 함수
# ============================================================================

# 진단 수행
diagnose() {


    diagnosis_result="unknown"
    local status="미진단"
    local inspection_summary=""
    local command_result=""
    local command_executed=""
    local newline=$'\n'

    # 진단 로직 구현
    # 주기적 보안 패치 및 벤더 권고 사항 적용 확인

    local kernel_version=""
    local package_updates=0
    local security_updates=0
    local last_update_info=""
    local details=""
    local raw_output=""

    # 1) 커널 버전 확인
    kernel_version=$(uname -r 2>/dev/null)

    # 2) 업데이트 가능한 패키지 확인 (Debian/Ubuntu)
    if command -v apt >/dev/null 2>&1; then
        # apt list --upgradable로 업데이트 가능한 패키지 확인
        local update_list=$(apt list --upgradable 2>/dev/null | grep -v "^Listing")

        if [ -n "$update_list" ]; then
            package_updates=$(echo "$update_list" | wc -l)

            # 보안 업데이트만 필터링
            security_updates=$(echo "$update_list" | grep -i "security" | wc -l)
        fi

        # Capture raw output for apt
        raw_output=$(echo "=== Kernel Version ===" && uname -r && echo -e "\n=== Upgradable Packages ===" && apt list --upgradable 2>/dev/null | head -20)

        # 마지막 업데이트 시간 확인 (/var/cache/apt/archives/의 최신 파일)
        if [ -d /var/cache/apt/archives/ ]; then
            local last_update_file=$(ls -lt /var/cache/apt/archives/*.deb 2>/dev/null | head -1 | awk '{print $NF}')
            if [ -n "$last_update_file" ]; then
                last_update_info=$(stat -c "%y" "$last_update_file" 2>/dev/null | cut -d'.' -f1)
            fi
        fi

        details="커널: ${kernel_version}, 업데이트 가능한 패키지: ${package_updates}개"
        [ "$security_updates" -gt 0 ] && details="${details} (보안: ${security_updates}개)"
        [ -n "$last_update_info" ] && details="${details}, 마지막 업데이트: ${last_update_info}"

    elif command -v yum >/dev/null 2>&1; then
        # RHEL/CentOS의 경우
        local update_list=$(yum check-update 2>/dev/null | grep -v "^$" | grep -v "Loaded plugins" | grep -v "^$" | tail -n +2)

        if [ -n "$update_list" ]; then
            package_updates=$(echo "$update_list" | wc -l)
            security_updates=$(echo "$update_list" | grep -i "security" | wc -l)
        fi

        # Capture raw output for yum
        raw_output=$(echo "=== Kernel Version ===" && uname -r && echo -e "\n=== Yum Check Update ===" && yum check-update 2>/dev/null | head -20)

        # 마지막 yum history 확인
        local last_yum=$(yum history list 2>/dev/null | head -5 | tail -1 | awk '{print $1" "$3" "$4" "$5" "$6" "$7}')
        [ -n "$last_yum" ] && last_update_info="$last_yum"

        details="커널: ${kernel_version}, 업데이트 가능: ${package_updates}개"
        [ "$security_updates" -gt 0 ] && details="${details} (보안: ${security_updates}개)"
        [ -n "$last_update_info" ] && details="${details}, 마지막 업데이트: ${last_update_info}"

    else
        # 다른 배포판의 경우 커널 버전만 확인
        raw_output=$(echo "=== Kernel Version ===" && uname -r)
        details="커널: ${kernel_version}, 패키지 매니저: 확인 불가"
    fi

    # 3) 판정
    if [ "$security_updates" -gt 0 ]; then
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="보안 업데이트 ${security_updates}개 적용 필요: ${details}"
        command_result="${raw_output}"
        command_executed="uname -r; apt list --upgradable 2>/dev/null | head -20"
    elif [ "$package_updates" -gt 10 ]; then
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="일반 업데이트 ${package_updates}개 미적용 (시스템 업데이트 권장): ${details}"
        command_result="${raw_output}"
        command_executed="uname -r; apt list --upgradable 2>/dev/null | wc -l"
    else
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="시스템이 최신 상태임: ${details}"
        command_result="${raw_output}"
        command_executed="uname -r; apt list --upgradable 2>/dev/null | wc -l"
    fi

    # echo ""
    # echo "진단 결과: ${status}"
    # echo "판정: ${diagnosis_result}"
    # echo "설명: ${inspection_summary}"
    # echo ""

    # 결과 생성 (PC 패턴: 스크립트에서 모드 확인 후 처리)
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

# ============================================================================
# 메인 실행
# ============================================================================

main() {
    # 진단 시작 표시
    show_diagnosis_start "${ITEM_ID}" "${ITEM_NAME}"

    # 디스크 공간 확인
    check_disk_space

    # 진단 수행
    diagnose

    # 진단 완료 표시
    show_diagnosis_complete "${ITEM_ID}" "${diagnosis_result:-UNKNOWN}"

    return 0
}

# 스크립트 직접 실행 시에만 진단 수행
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi
