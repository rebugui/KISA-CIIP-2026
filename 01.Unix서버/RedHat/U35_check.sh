#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-28
# ============================================================================
# [점검 항목 상세]
# @ID          : U-35
# @Category    : UNIX > 3. 서비스 관리
# @Platform    : RedHat
# @Severity    : 상
# @Title       : 공유 서비스에 대한 익명 접근 제한 설정
# @Description : 익명 사용자(Anonymous)의 공유 서비스 접근 제한 여부 점검
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

ITEM_ID="U-35"
ITEM_NAME="공유 서비스에 대한 익명 접근 제한 설정"
SEVERITY="상"

# 가이드라인 정보 (제시된 리스트 기준 반영)
GUIDELINE_PURPOSE="공유 서비스의 익명 접근을 제한하여 중요 정보의 노출을 방지하기 위함"
GUIDELINE_THREAT="공유 서비스의 익명 접근을 허용할 경우, 비인가자의 무단 접근으로 인한 중요 정보 탈취 또는 변조, 악성 코드 유포 등의 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="공유 서비스에 대해 익명 접근을 제한한 경우"
GUIDELINE_CRITERIA_BAD="공유 서비스에 대해 익명 접근을 허용한 경우"
GUIDELINE_REMEDIATION="공유 서비스의 익명 접근 제한 설정"

diagnose() {
    # [중요] 파싱 에러 방지를 위한 기존 변수 초기값 유지
    local status="양호"
    diagnosis_result="GOOD"
    local inspection_summary="공유 서비스의 익명 접근 제한 설정이 적절합니다."
    local command_result=""
    local command_executed="grep -E '^(ftp|anonymous):' /etc/passwd; grep -i anonymous_enable /etc/vsftpd/vsftpd.conf /etc/vsftpd.conf; grep -i '<Anonymous' /etc/proftpd/proftpd.conf /etc/proftpd.conf; grep -v '^#' /etc/exports; grep -iE 'guest ok|map to guest' /etc/samba/smb.conf"
    local newline=$'\n'

    # 공유 서비스(FTP/NFS/Samba) 익명 접근 점검
    local vuln_issues=""
    local manual_issues=""
    local evidence=""

    # ==================== 1) FTP 익명 접근 ====================
    local ftp_running=false
    local ftp_config_found=false

    # 1-1) 기본 FTP 계정(ftp/anonymous) 확인
    local passwd_ftp=""
    passwd_ftp=$(grep -E '^(ftp|anonymous):' /etc/passwd 2>/dev/null || true)
    evidence="${evidence}[/etc/passwd ftp/anonymous 계정]${newline}${passwd_ftp:-계정 없음}${newline}"
    if [ -n "$passwd_ftp" ]; then
        local ftp_shell_acct=""
        ftp_shell_acct=$(printf '%s\n' "$passwd_ftp" | awk -F: '$7 !~ /(nologin|false)$/ {print $1}' || true)
        if [ -n "$ftp_shell_acct" ]; then
            vuln_issues="${vuln_issues:+${vuln_issues}; }기본 FTP 계정(${ftp_shell_acct//$'\n'/,})이 유효한 쉘로 존재함"
        fi
    fi

    # 1-2) FTP 서비스 동작 확인
    if systemctl is-active vsftpd &>/dev/null || systemctl is-active proftpd &>/dev/null || systemctl is-active pure-ftpd &>/dev/null; then
        ftp_running=true
        evidence="${evidence}[FTP 서비스] 실행 중${newline}"
    fi
    if command -v ss &>/dev/null; then
        local ftp_port=""
        ftp_port=$(ss -tuln 2>/dev/null | grep ":21 " || true)
        if [ -n "$ftp_port" ]; then
            ftp_running=true
            evidence="${evidence}[FTP 포트 21]${newline}${ftp_port}${newline}"
        fi
    fi

    # 1-3) vsftpd 설정 확인 (서비스 감지 여부와 무관하게 설정 파일 존재 시 점검)
    local vs_conf=""
    for vs_conf in /etc/vsftpd/vsftpd.conf /etc/vsftpd.conf; do
        if [ -f "$vs_conf" ]; then
            ftp_config_found=true
            local vs_anon=""
            vs_anon=$(grep -iE '^[[:space:]]*(anonymous_enable|anon_enable)[[:space:]]*=' "$vs_conf" 2>/dev/null || true)
            evidence="${evidence}[${vs_conf}]${newline}${vs_anon:-anonymous_enable 설정 없음}${newline}"
            if printf '%s\n' "$vs_anon" | grep -iq '=[[:space:]]*YES'; then
                vuln_issues="${vuln_issues:+${vuln_issues}; }vsftpd 익명 접근 허용(${vs_conf})"
            elif [ -z "$vs_anon" ]; then
                # anonymous_enable 미설정 시 vsftpd 컴파일 기본값(YES)이 적용될 수
                # 있으므로 양호로 단정하지 않고 수동 진단으로 처리 (false-good 방지)
                manual_issues="${manual_issues:+${manual_issues}; }vsftpd anonymous_enable 미설정(${vs_conf}) - 빌드 기본값(YES 가능) 적용 여부 수동 확인 필요"
            fi
        fi
    done

    # 1-4) ProFTPD 설정 확인
    local pro_conf=""
    for pro_conf in /etc/proftpd/proftpd.conf /etc/proftpd.conf; do
        if [ -f "$pro_conf" ]; then
            ftp_config_found=true
            local pro_anon=""
            pro_anon=$(grep -iE '^[[:space:]]*<Anonymous' "$pro_conf" 2>/dev/null || true)
            evidence="${evidence}[${pro_conf}]${newline}${pro_anon:-<Anonymous> 블록 없음}${newline}"
            if [ -n "$pro_anon" ]; then
                vuln_issues="${vuln_issues:+${vuln_issues}; }ProFTPD <Anonymous> 블록 활성화(${pro_conf})"
            fi
        fi
    done

    # 1-5) Pure-FTPD 설정 확인
    if [ -f /etc/pure-ftpd/conf/NoAnonymous ]; then
        ftp_config_found=true
        local no_anonymous=""
        no_anonymous=$(tr -d '[:space:]' < /etc/pure-ftpd/conf/NoAnonymous 2>/dev/null || true)
        evidence="${evidence}[Pure-FTPD] NoAnonymous=${no_anonymous}${newline}"
        case "$no_anonymous" in
            1|[Yy][Ee][Ss]) : ;;
            *) vuln_issues="${vuln_issues:+${vuln_issues}; }Pure-FTPD 익명 접근 허용" ;;
        esac
    fi

    # 1-6) FTP 서비스 동작 중이나 설정 파일 미확인 → 수동 진단
    if [ "$ftp_running" = true ] && [ "$ftp_config_found" = false ]; then
        manual_issues="${manual_issues:+${manual_issues}; }FTP 서비스가 실행 중이나 설정 파일을 확인할 수 없음"
        evidence="${evidence}[FTP] 서비스 실행 감지되었으나 설정 파일 미발견${newline}"
    fi

    # ==================== 2) NFS 익명/전체 공유 ====================
    if [ -f /etc/exports ]; then
        if [ -r /etc/exports ]; then
            local nfs_shares=""
            nfs_shares=$(grep -vE '^[[:space:]]*(#|$)' /etc/exports 2>/dev/null || true)
            evidence="${evidence}[/etc/exports]${newline}${nfs_shares:-공유 설정 없음}${newline}"
            local nfs_anon=""
            nfs_anon=$(printf '%s\n' "$nfs_shares" | grep -E 'insecure|anon(uid|gid)?=0([^0-9]|$)' || true)
            local nfs_world=""
            nfs_world=$(printf '%s\n' "$nfs_shares" | grep -F '*' | grep -E '[(,[:space:]]rw' || true)
            if [ -n "$nfs_anon" ]; then
                vuln_issues="${vuln_issues:+${vuln_issues}; }NFS 익명 공유 설정(insecure/anon=0): ${nfs_anon//$'\n'/ | }"
            fi
            if [ -n "$nfs_world" ]; then
                vuln_issues="${vuln_issues:+${vuln_issues}; }NFS 전체 공개(rw) 공유: ${nfs_world//$'\n'/ | }"
            fi
        else
            manual_issues="${manual_issues:+${manual_issues}; }/etc/exports 읽기 불가"
            evidence="${evidence}[/etc/exports] 읽기 권한 없음${newline}"
        fi
    else
        evidence="${evidence}[/etc/exports] 파일 없음(NFS 공유 미사용)${newline}"
    fi

    # ==================== 3) Samba 익명(guest) 접근 ====================
    local smb_conf=""
    for smb_conf in /etc/samba/smb.conf; do
        if [ -f "$smb_conf" ]; then
            if [ -r "$smb_conf" ]; then
                local smb_guest=""
                smb_guest=$(grep -iE '^[[:space:]]*guest[[:space:]]+ok[[:space:]]*=[[:space:]]*yes' "$smb_conf" 2>/dev/null || true)
                local smb_map=""
                smb_map=$(grep -iE '^[[:space:]]*map[[:space:]]+to[[:space:]]+guest[[:space:]]*=[[:space:]]*(bad[[:space:]]+user|bad[[:space:]]+password|always)' "$smb_conf" 2>/dev/null || true)
                evidence="${evidence}[${smb_conf}]${newline}${smb_guest:-guest ok=yes 설정 없음}${newline}${smb_map:-map to guest 허용 설정 없음}${newline}"
                if [ -n "$smb_guest" ]; then
                    vuln_issues="${vuln_issues:+${vuln_issues}; }Samba guest ok=yes(${smb_conf})"
                fi
                if [ -n "$smb_map" ]; then
                    vuln_issues="${vuln_issues:+${vuln_issues}; }Samba map to guest 허용(${smb_conf})"
                fi
            else
                manual_issues="${manual_issues:+${manual_issues}; }${smb_conf} 읽기 불가"
                evidence="${evidence}[${smb_conf}] 읽기 권한 없음${newline}"
            fi
        else
            evidence="${evidence}[${smb_conf}] 파일 없음(Samba 미사용)${newline}"
        fi
    done

    # ==================== 최종 판정 (leg 병합) ====================
    if [ -n "$vuln_issues" ]; then
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="공유 서비스 익명 접근 허용됨: ${vuln_issues}"
    elif [ -n "$manual_issues" ]; then
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="공유 서비스 익명 접근 설정 자동 판정 불가: ${manual_issues}"
    else
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="FTP/NFS/Samba 공유 서비스의 익명 접근이 제한되어 있음(또는 해당 서비스 미사용)"
    fi
    command_result="${evidence}"

    save_dual_result \
        "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" \
        "${inspection_summary}" "${command_result}" "${command_executed}" \
        "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" \
        "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
    
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
