

# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : W-18
# @Category    : Windows Server
# @Platform    : Windows Server
# @Severity    : 상
# @Title       : 불필요한 서비스 제거
# @Description : 불필요한 서비스 실행 여부 점검으로 시스템 자원 낭비 방지 및 공격 표면 감소
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================
$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\lib"
. "${LIB_DIR}\result_manager.ps1"

# Parameters
$ITEM_ID = "W-18"
$ITEM_NAME = "불필요한 서비스 제거"
$SEVERITY = "상"
$CATEGORY = "2.서비스관리"

# run_all 모드가 아닐 때만 진단 정보 출력
if (-not (Test-RunallMode)) {
    Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"
    Write-Host "카테고리: $CATEGORY"
}

# 1. Check unnecessary services
# 가이드 '일반적으로 불필요한 서비스' 표 전체(18+종)를 점검.
# Windows 서비스명(Name)과 표시 이름(DisplayName)이 다른 경우가 있어 두 기준으로 모두 매칭한다.
# (OS 버전에 따라 미제공 서비스는 자연히 미발견 처리됨)
try {
    # @{ Name = '가이드 항목명'; Match = @('서비스명/표시이름 후보들') }
    $unnecessaryServices = @(
        @{ Name = 'Alerter';                                  Match = @('Alerter') },
        @{ Name = 'Automatic Updates';                        Match = @('wuauserv', 'Automatic Updates', 'Windows Update') },
        @{ Name = 'Clipbook';                                 Match = @('ClipSrv', 'Clipbook') },
        @{ Name = 'Computer Browser';                         Match = @('Browser', 'Computer Browser') },
        @{ Name = 'Cryptographic Services';                   Match = @('CryptSvc', 'Cryptographic Services') },
        @{ Name = 'DHCP Client';                              Match = @('Dhcp', 'DHCP Client') },
        @{ Name = 'Distributed Link Tracking Client';         Match = @('TrkWks', 'Distributed Link Tracking Client') },
        @{ Name = 'Distributed Link Tracking Server';         Match = @('TrkSvr', 'Distributed Link Tracking Server') },
        @{ Name = 'DNS Client';                               Match = @('Dnscache', 'DNS Client') },
        @{ Name = 'Error Reporting Service';                  Match = @('ERSvc', 'WerSvc', 'Error Reporting Service', 'Windows Error Reporting Service') },
        @{ Name = 'Human Interface Device Access';            Match = @('HidServ', 'hidserv', 'Human Interface Device Access', 'Human Interface Device Service') },
        @{ Name = 'IMAPI CD-Burning COM Service';             Match = @('ImapiService', 'IMAPI CD-Burning COM Service') },
        @{ Name = 'Infrared Monitor';                         Match = @('Irmon', 'Infrared Monitor') },
        @{ Name = 'Messenger';                                Match = @('Messenger') },
        @{ Name = 'NetMeeting Remote Desktop Sharing';        Match = @('mnmsrvc', 'NetMeeting Remote Desktop Sharing') },
        @{ Name = 'Portable Media Serial Number';             Match = @('WmdmPmSN', 'Portable Media Serial Number Service') },
        @{ Name = 'Print Spooler';                            Match = @('Spooler', 'Print Spooler') },
        @{ Name = 'Remote Registry';                          Match = @('RemoteRegistry', 'Remote Registry') },
        @{ Name = 'Simple TCP/IP Services';                   Match = @('SimpTcp', 'Simple TCP/IP Services') },
        @{ Name = 'Universal Plug and Play Device Host';      Match = @('upnphost', 'Universal Plug and Play Device Host') },
        @{ Name = 'Wireless Zero Configuration';              Match = @('WZCSVC', 'Wzcsvc', 'Wireless Zero Configuration') }
    )

    $allServices = Get-Service -ErrorAction SilentlyContinue
    $runningServices = @()

    foreach ($entry in $unnecessaryServices) {
        $svc = $allServices | Where-Object {
            ($entry.Match -contains $_.Name) -or ($entry.Match -contains $_.DisplayName)
        } | Select-Object -First 1

        if ($svc -and $svc.Status -eq 'Running') {
            $runningServices += $entry.Name
        }
    }

    if ($runningServices.Count -eq 0) {
        $finalResult = "GOOD"
        $summary = "일반적으로 불필요한 서비스가 모두 중지되었거나 설치되지 않음"
        $status = "양호"
        $commandOutput = "All unnecessary services are stopped or not installed"
    } else {
        $finalResult = "VULNERABLE"
        $runningList = $runningServices -join ', '
        $summary = "일반적으로 불필요한 서비스가 구동 중임: $runningList"
        $status = "취약"
        $commandOutput = "Running unnecessary services: $runningList"
    }

    $commandExecuted = "Get-Service | 일반적으로 불필요한 서비스(가이드 표 전체) 구동 여부 확인"

} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandExecuted = "Get-Service -Name '...'"
    $commandOutput = "진단 실패: $_"
}

# 2. lib를 통한 결과 저장
$purpose = "사용자 환경에 필요하지 않은 서비스 및 실행 파일을 제거하거나 비활성화 처리하여 이를 통한 악의적인 공격을 차단하기 위함"
$threat = "시스템에 기본적으로 설치되는 불필요한 취약 서비스들이 제거되지 않은 경우, 해당 서비스의 취약점으로 인한 공격이 가능하며, 네트워크 서비스의 경우 열린 Port를 통한 외부 침입 위험이 존재함"
$criteria_good = "일반적으로 불필요한 서비스(아래 목록 참조)가 중지된 경우"
$criteria_bad = "일반적으로 불필요한 서비스(아래 목록 참조)가 구동 중인 경우"
$remediation = "서비스 중지 후'사용 안 함'설정"

Save-DualResult -ItemId $ITEM_ID `
    -ItemName $ITEM_NAME `
    -Status $status `
    -FinalResult $finalResult `
    -InspectionSummary $summary `
    -CommandResult $commandOutput `
    -CommandExecuted $commandExecuted `
    -GuidelinePurpose $purpose `
    -GuidelineThreat $threat `
    -GuidelineCriteriaGood $criteria_good `
    -GuidelineCriteriaBad $criteria_bad `
    -GuidelineRemediation $remediation

# run_all 모드가 아닐 때만 완료 메시지 출력
if (-not (Test-RunallMode)) {
    Write-Host ""
    Write-Host "진단 완료: $ITEM_ID ($finalResult)"
}

exit 0
