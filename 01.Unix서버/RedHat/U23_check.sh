#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-04-20
# ============================================================================
# [점검 항목 상세]
# @ID          : U-23
# @Category    : UNIX > 2. 파일 및 디렉토리 관리
# @Platform    : RedHat
# @Severity    : 상
# @Title       : SUID, SGID, Sticky bit 설정 파일 점검
# @Description : 불필요하거나 악의적인 파일에 SUID, SGID, Sticky bit 설정 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

set -euo pipefail

# 스크립트 디렉토리 설정
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../../lib"

# 필수 라이브러리 로드
source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/metadata_parser.sh"

ITEM_ID="U-23"
ITEM_NAME="SUID, SGID, Sticky bit 설정 파일 점검"
SEVERITY="상"

# 가이드라인 정보 (PDF 50페이지 내용 반영)
GUIDELINE_PURPOSE="불필요한 SUID, SGID, Stickybit 설정 제거로 악의적인 사용자의 권한 상승을 방지하기 위함"
GUIDELINE_THREAT="SUID, SGID, Sticky bit 설정이 적절하지 않을 경우, SUID, SGID, Sticky bit가 설정된 파일로 특정 명령어를 실행하여 root 권한 획득이 가능한 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="주요 실행 파일의 권한에 SUID와 SGID에 대한 설정이 부여되어 있지 않은 경우"
GUIDELINE_CRITERIA_BAD="주요 실행 파일의 권한에 SUID와 SGID에 대한 설정이 부여된 경우"
GUIDELINE_REMEDIATION="불필요한 SUID,SGID 권한 또는 해당 파일 제거하도록 설정 애플리케이션에서 생성한 파일이나 사용자가 임의로 생성한 파일 등 의심스럽거나 특이한 파일에 SUID 권한이 부여된 경우 제거하도록 설정"

diagnose() {
    local status="미진단"
    diagnosis_result="unknown"
    local inspection_summary=""
    local command_result=""
    local command_executed=""
    local newline=$'\n'

    # 진단 로직 구현
    # SUID, SGID, Sticky bit 설정 파일 점검

    local suid_sgids=""
    local found_count=0
    local vulnerable_count=0
    local manual_count=0
    local details=""

    # 표준 시스템 SUID/SGID 바이너리 허용 목록 (basename 완전 일치 비교)
    # 형제 플랫폼(Debian 등)과 정렬: RHEL 기본 설치 시 항상 존재하는 정당한
    # SUID/SGID 바이너리를 취약으로 오판하지 않도록 충분히 포함함
    local suid_allowlist=" ping ping6 traceroute traceroute6 tracepath mount umount fusermount fusermount3 su sudo passwd gpasswd chsh chfn chage expiry newgrp chown chmod uptime crontab at sperl rsh rcp rlogin rshd telnet ftp ftpd nc tcpdump pkexec ssh-keysign ssh-agent unix_chkpwd pam_timestamp_check mount.nfs mount.nfs4 umount.nfs umount.nfs4 write wall bsd-write Xorg utempter netreport locate mlocate dbus-daemon-launch-helper polkit-agent-helper-1 "

    # 주요 실행 디렉토리 탐색
    # 표준 시스템 경로뿐 아니라 SUID/SGID 바이너리가 위치할 수 있는 비표준 경로
    # (/usr/local, /opt, /usr/libexec 등)와 사용자/임시 영역까지 포함하여
    # 좁은 경로 탐색으로 실제 SUID 바이너리를 놓쳐 GOOD으로 오판하는 것을 방지함
    local search_dirs="/usr/bin /usr/sbin /sbin /bin /usr/local/bin /usr/local/sbin /usr/libexec /usr/lib /opt /home /root /tmp /var/tmp"
    local raw_find_output=""

    for dir in $search_dirs; do
        if [ -d "$dir" ]; then
            local dir_output=$(find "$dir" -user root -type f \( -perm -04000 -o -perm -02000 \) -xdev 2>/dev/null || true)
            if [ -n "$dir_output" ]; then
                raw_find_output="${raw_find_output}${dir_output}"$'\n'
            fi
        fi
    done || true

    # 중복 경로(심볼릭 링크 등으로 동일 파일이 여러 경로에 노출) 제거
    if [ -n "$raw_find_output" ]; then
        raw_find_output=$(printf '%s' "$raw_find_output" | grep -v '^$' | sort -u)
    fi

    # 발견된 파일 분석
    while IFS= read -r file; do
        if [ -n "$file" ] && [ -f "$file" ]; then
            ((found_count++)) || true
            local perms=$(stat -c "%a" "$file" 2>/dev/null)
            local owner=$(stat -c "%U" "$file" 2>/dev/null)
            suid_sgids="${suid_sgids}${file} (권한: ${perms}, 소유자: ${owner})${newline}"

            # 일반적인 SUID/SGID 파일 중 취약한 것 확인
            # 대부분의 시스템 실행 파일은 SUID/SGID가 필요하므로,
            # 허용 목록에 있으면 정상으로 간주함.
            # 허용 목록에 없는 파일은 필요성을 정적으로 단정할 수 없으므로
            # 명백히 의심스러운 경우(스크립트 확장자 또는 그룹/기타 쓰기 가능)만
            # 취약으로 판정하고, 그 외에는 수동 점검(MANUAL)으로 라우팅함
            local fname=$(basename "$file")
            case " ${suid_allowlist} " in
                *" ${fname} "*)
                    # 허용 목록에 포함된 필수 바이너리 - 취약 아님
                    ;;
                *)
                    # 허용 목록 외 파일: 명백한 위험 신호만 취약으로 판정
                    local is_suspicious=0
                    case "$fname" in
                        *.sh|*.pl|*.py|*.rb)
                            is_suspicious=1 ;;
                    esac
                    # 그룹/기타 쓰기 가능 여부 확인 (8진수 권한 하위 2자리)
                    if [ "$is_suspicious" -eq 0 ] && [ -n "$perms" ]; then
                        local last2="${perms: -2}"
                        local gperm="${last2:0:1}"
                        local operm="${last2:1:1}"
                        case "$gperm" in 2|3|6|7) is_suspicious=1 ;; esac
                        case "$operm" in 2|3|6|7) is_suspicious=1 ;; esac
                    fi
                    if [ "$is_suspicious" -eq 1 ]; then
                        ((vulnerable_count++)) || true
                        details="${details}${file} (불필요/의심스러운 SUID/SGID 설정), "
                    else
                        ((manual_count++)) || true
                        details="${details}${file} (허용 목록 외 SUID/SGID - 필요성 수동 점검 필요), "
                    fi
                    ;;
            esac
        fi
    done <<< "$raw_find_output" || true

    # 최종 판정
    if [ "$found_count" -eq 0 ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="SUID/SGID 설정 파일이 발견되지 않았습니다."
        command_result="[Command: find SUID/SGID files]${newline}${raw_find_output:-특이 SUID/SGID 파일 없음}"
        command_executed="find /usr/bin /usr/sbin /sbin /bin -user root -type f \( -perm -04000 -o -perm -02000 \) -xdev"
    else
        if [ "$vulnerable_count" -eq 0 ]; then
            # 명백히 취약한 파일은 없으나, 허용 목록 외 파일의 필요성은
            # 정적으로 단정할 수 없으므로(또는 모두 필수 파일이므로) - MANUAL
            diagnosis_result="MANUAL"
            status="수동진단"
            inspection_summary="SUID/SGID 설정 파일이 발견되었습니다. (총 ${found_count}개, 허용 목록 외 ${manual_count}개) 불필요한 파일인지 수동으로 확인 필요.${details:+${newline}${details}}"
            command_result="[Command: find SUID/SGID files]${newline}${raw_find_output}${newline}${newline}[발견된 파일 분석]${newline}${suid_sgids}"
            command_executed="find /usr/bin /usr/sbin /sbin /bin /usr/local/bin /usr/local/sbin /usr/libexec /usr/lib /opt /home /root /tmp /var/tmp -user root -type f \( -perm -04000 -o -perm -02000 \) -xdev"
        else
            # 불필요한 SUID/SGID 파일이 있는 경우 - VULNERABLE
            diagnosis_result="VULNERABLE"
            status="취약"
            inspection_summary="불필요한 SUID/SGID 설정 파일 발견됨. (총 ${found_count}개 중 ${vulnerable_count}개 취약)${newline}${details}"
            command_result="[Command: find SUID/SGID files]${newline}${raw_find_output}${newline}${newline}[취약 파일 분석]${newline}${suid_sgids}"
            command_executed="find /usr/bin /usr/sbin /sbin /bin /usr/local/bin /usr/local/sbin /usr/libexec /usr/lib /opt /home /root /tmp /var/tmp -user root -type f \( -perm -04000 -o -perm -02000 \) -xdev"
        fi
    fi

    save_dual_result \
        "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" \
        "${inspection_summary}" "${command_result}" "${command_executed}" \
        "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" \
        "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" \
        "${GUIDELINE_REMEDIATION}"

    verify_result_saved "${ITEM_ID}"
    return 0
}

main() {
    show_diagnosis_start "${ITEM_ID}" "${ITEM_NAME}"
    [ "$EUID" -ne 0 ] && { echo "root 권한이 필요합니다."; exit 1; }
    diagnose
    show_diagnosis_complete "${ITEM_ID}" "${diagnosis_result}"
    exit 0
}

main "$@"
