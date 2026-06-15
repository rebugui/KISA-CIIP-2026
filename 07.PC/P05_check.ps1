

# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : PC-05
# @Category    : PC (Personal Computer)
# @Platform    : Windows 10, 11
# @Severity    : 상
# @Title       : 항목의 불필요한 서비스 제거
# @Description : 시스템에서 불필요한 서비스를 제거하여 공격면을 축소
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\lib"
. "${LIB_DIR}\result_manager.ps1"

# Parameters
$ITEM_ID = "PC-05"
$ITEM_NAME = "항목의 불필요한 서비스 제거"
$SEVERITY = "상"
$CATEGORY = "2.서비스관리"

# run_all 모드가 아닐 때만 진단 정보 출력
if (-not (Test-RunallMode)) {
    Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"
    Write-Host "카테고리: $CATEGORY"
}

# 1. Run diagnostic
$commandExecuted = 'Get-Service | Where-Object { $_.Status -eq "Running" }'
$commandOutput = ""
try {
    # KISA 가이드라인 "일반적으로 불필요한 서비스" 표 기반 목록.
    # 주의:
    #  - "Schedule"(Task Scheduler)는 KISA 불필요 서비스 표에 없으며 Win10/11에서 OS 필수
    #    상시 실행 서비스이므로 목록에서 제거함 (제거 전: 거의 모든 PC에서 오탐 false-VULNERABLE 발생).
    #  - 서비스명은 ServiceName(키) 기준 매칭. 관리자가 서비스명을 변경한 경우(드묾) 문자열 매칭이
    #    실패하여 미탐될 수 있으나, 표준 환경에서는 ServiceName이 고정이므로 가이드 기준 그대로 사용.
    $unnecessaryServices = @(
        "TlntSvr",           # Telnet
        "MSFTPSVC",          # FTP Publishing Service
        "SMTPSVC",           # Simple Mail Transfer Protocol (SMTP)
        "RemoteRegistry",    # Remote Registry Service
        "Simptcp",           # Simple TCP/IP Services
        "Browser",           # Computer Browser
        "WZCSVC",            # Wireless Zero Configuration
        "upnphost",          # Universal Plug and Play Device Host
        "SSDPSRV",           # SSDP Discovery (UPnP)
        "RemoteAccess",      # Routing and Remote Access (NetMeeting Remote Desktop 계열)
        "Messenger",         # Messenger (netsend/경고 메시지)
        "alerter",           # Alerter Service
        "Clipsrv",           # ClipBook Service
        "fax"                # Fax Service
    )

    $runningServices = Get-Service | Where-Object { $_.Status -eq "Running" -and $_.StartType -ne "Disabled" }
    $foundServices = @()

    foreach ($svc in $runningServices) {
        if ($unnecessaryServices -contains $svc.Name) {
            $foundServices += "$($svc.Name) ($($svc.DisplayName))"
        }
    }

    $serviceOutput = Get-Service | Where-Object { $_.Status -eq "Running" } | Out-String
    $commandOutput = $serviceOutput

    if ($foundServices.Count -gt 0) {
        $finalResult = "VULNERABLE"
        $foundList = $foundServices -join ', '
        $summary = "불필요한 서비스 실행 중 ($($foundServices.Count)개): $foundList"
        $status = "취약"
    } else {
        $finalResult = "GOOD"
        $summary = "불필요한 서비스 실행 중 아님 (KISA 권고 서비스 $($unnecessaryServices.Count)개 점검 완료)"
        $status = "양호"
    }
} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandOutput = "진단 실패: $_"
}

# 2. lib를 통한 결과 저장
$purpose = '사용하지 않는 서비스나 기본으로 설치된 서비스들을 제거하여 시스템 자원의 낭비를 막고 해당 서비스 포트를 통한 침입을 방지하기 위함'
$threat = '실질적 사용하지 않는 서비스들이 실행되어 시스템에 과부하가 발생하는 위험이 존재함 불필요한 서비스의 경우 사용자가 알지도 못한 서비스들이 실행되고 있는 경우가 대부분, 이 경우 해당 서비스가 이미 취약한 버전의 서비스인지도 인지하지 못하고 사용하는 위험이 존재함'
$criteria_good = '일반적으로 불필요한 서비스(아래 목록 참조)가 중지된 경우'
$criteria_bad = '일반적으로 불필요한 서비스(아래 목록 참조)가 중지되지 않은 경우'
$remediation = '불필요한 서비스 중지 설정'

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
    -GuidelineRemediation $remediation `
    -ScriptDir $SCRIPT_DIR

Write-Host ""
Write-Host "진단 완료: $ITEM_ID ($finalResult)"

exit 0
