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
    # 패치 정책 수립/최신성 여부는 벤더 공지 대비 수동 판단이 필요하므로 항상 수동진단으로 판정

    local kernel_version=""
    local os_version=""
    local upgradable_list=""
    local last_update_info=""
    local details=""
    local raw_output=""

    # 1) 커널/OS 버전 확인
    kernel_version=$(uname -r 2>/dev/null || true)
    if command -v lsb_release >/dev/null 2>&1; then
        os_version=$(lsb_release -d 2>/dev/null | cut -f2- || true)
    fi
    if [ -z "$os_version" ] && [ -r /etc/os-release ]; then
        os_version=$(grep '^PRETTY_NAME=' /etc/os-release 2>/dev/null | cut -d'"' -f2 || true)
    fi
    [ -z "$os_version" ] && os_version="알 수 없음"

    # 2) 업그레이드 가능 패키지 목록 수집 (apt 캐시 기준 — 최신성 보장 안 됨)
    if command -v apt >/dev/null 2>&1; then
        upgradable_list=$(apt list --upgradable 2>/dev/null | head -20 || true)
    fi
    [ -z "$upgradable_list" ] && upgradable_list="확인 불가 (apt 미존재 또는 캐시 비어 있음)"

    # 3) 마지막 apt-get update 시점 확인 (가능한 경우)
    if [ -f /var/lib/apt/periodic/update-success-stamp ]; then
        last_update_info=$(stat -c "%y" /var/lib/apt/periodic/update-success-stamp 2>/dev/null | cut -d'.' -f1 || true)
    elif [ -f /var/cache/apt/pkgcache.bin ]; then
        last_update_info=$(stat -c "%y" /var/cache/apt/pkgcache.bin 2>/dev/null | cut -d'.' -f1 || true)
    fi
    [ -z "$last_update_info" ] && last_update_info="확인 불가"

    raw_output="=== OS Version ===${newline}${os_version}${newline}=== Kernel Version ===${newline}${kernel_version}${newline}=== Upgradable Packages (apt 캐시 기준 — 최신성 보장 안 됨) ===${newline}${upgradable_list}${newline}=== Last apt-get update ===${newline}${last_update_info}"

    details="OS: ${os_version}, 커널: ${kernel_version}, 마지막 apt-get update: ${last_update_info}"

    # 4) 판정 (Debian): 패치 정책/최신성은 자동 판정 불가 — 항상 수동진단
    diagnosis_result="MANUAL"
    status="수동진단"
    inspection_summary="패치 적용 현황 수동 확인 필요 (최신 보안패치 적용 여부는 벤더 공지 대비 수동 판단). ${details}. 업그레이드 가능 목록은 apt 캐시 기준 — 최신성 보장 안 됨."
    command_result="${raw_output}"
    command_executed="lsb_release -d; uname -r; apt list --upgradable 2>/dev/null | head -20; stat -c %y /var/lib/apt/periodic/update-success-stamp"

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
