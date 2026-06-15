#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : U-23
# @Category    : Unix Server
# @Platform    : Debian
# @Severity    : 상
# @Title       : SUID, SGID, Sticky bit 설정 파일 점검
# @Description : 불필요하거나 의심스러운 파일에 SUID, SGID 설정 여부 점검
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


ITEM_ID="U-23"
ITEM_NAME="SUID, SGID, Sticky bit 설정 파일 점검"
SEVERITY="상"

# 가이드라인 정보
GUIDELINE_PURPOSE="불필요한 SUID, SGID, Stickybit 설정 제거로 악의적인 사용자의 권한 상승을 방지하기 위함"
GUIDELINE_THREAT="SUID, SGID, Sticky bit 설정이 적절하지 않을 경우, SUID, SGID, Sticky bit가 설정된 파일로 특정 명령어를 실행하여 root 권한 획득이 가능한 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="주요 실행 파일의 권한에 SUID와 SGID에 대한 설정이 부여되어 있지 않은 경우"
GUIDELINE_CRITERIA_BAD="주요 실행 파일의 권한에 SUID와 SGID에 대한 설정이 부여된 경우"
GUIDELINE_REMEDIATION="불필요한 SUID,SGID 권한 또는 해당 파일 제거하도록 설정 애플리케이션에서 생성한 파일이나 사용자가 임의로 생성한 파일 등 의심스럽거나 특이한 파일에 SUID 권한이 부여된 경우 제거하도록 설정"

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
    # SUID/SGID 설정 파일 탐색 후 표준 허용 목록과 비교 점검

    # 표준 시스템 SUID/SGID 바이너리 허용 목록 (basename 완전 일치 비교)
    local suid_allowlist=(
        ping ping6 traceroute traceroute6 tracepath
        su sudo doas passwd gpasswd chsh chfn chage expiry newgrp
        mount umount fusermount fusermount3
        pkexec at crontab ssh-keysign ssh-agent unix_chkpwd Xorg
        wall write bsd-write dotlockfile locate mlocate sperl uptime
        chown chmod rsh rcp rlogin rshd telnet ftp ftpd nc tcpdump wbem expire
    )

    local raw_find_output=""
    local find_rc=0
    raw_find_output=$(find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null) || find_rc=$?

    local total_count=0
    local evidence_output=""
    if [ -n "$raw_find_output" ]; then
        total_count=$(printf '%s\n' "$raw_find_output" | wc -l | tr -d ' ')
        evidence_output=$(printf '%s\n' "$raw_find_output" | head -30)
    fi

    local find_cmd="find / -xdev \\( -perm -4000 -o -perm -2000 \\) -type f 2>/dev/null"

    # 허용 목록 비교 (basename 완전 일치 - 부분 일치 허용 안 함)
    local vulnerable_count=0
    local vulnerable_files=""
    if [ -n "$raw_find_output" ]; then
        while IFS= read -r file; do
            [ -n "$file" ] || continue
            local fname
            fname=$(basename "$file")
            local allowed=false
            local allowed_name=""
            for allowed_name in "${suid_allowlist[@]}"; do
                if [ "$fname" = "$allowed_name" ]; then
                    allowed=true
                    break
                fi
            done
            if [ "$allowed" = false ]; then
                ((vulnerable_count++)) || true
                if [ "$vulnerable_count" -le 30 ]; then
                    vulnerable_files="${vulnerable_files}${file}${newline}"
                fi
            fi
        done <<< "$raw_find_output" || true
    fi

    # 결과 판정
    if [ "$find_rc" -ne 0 ] && [ -z "$raw_find_output" ]; then
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="find 명령으로 SUID/SGID 파일을 탐색할 수 없습니다(종료코드: ${find_rc}). SUID/SGID 설정 파일을 수동으로 점검하시기 바랍니다."
        command_result="[Command: ${find_cmd}]${newline}find 실행 실패 또는 결과 없음 (종료코드: ${find_rc})"
        command_executed="${find_cmd}"
    elif [ "$total_count" -eq 0 ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="SUID/SGID 설정 파일이 발견되지 않았습니다."
        command_result="[Command: ${find_cmd}]${newline}SUID/SGID 설정 파일 없음"
        command_executed="${find_cmd}"
    elif [ "$vulnerable_count" -gt 0 ]; then
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="허용 목록에 없는 SUID/SGID 설정 파일이 발견되었습니다. (전체 ${total_count}개 중 ${vulnerable_count}개 의심) 불필요한 SUID/SGID 권한을 제거하시기 바랍니다."
        command_result="[Command: ${find_cmd}]${newline}${evidence_output}${newline}${newline}[허용 목록 외 SUID/SGID 파일 (${vulnerable_count}개)]${newline}${vulnerable_files}"
        command_executed="${find_cmd}"
    else
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="SUID/SGID 설정 파일 ${total_count}개가 발견되었으며 모두 표준 시스템 바이너리입니다. 불필요한 파일인지 수동으로 확인하시기 바랍니다."
        command_result="[Command: ${find_cmd}]${newline}${evidence_output}"
        command_executed="${find_cmd}"
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
