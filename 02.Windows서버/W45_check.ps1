# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : W-45
# @Category    : Windows Server
# @Platform    : Windows Server
# @Severity    : 상
# @Title       : 백신 프로그램 설치
# @Description : 백신 프로그램 설치로 바이러스 감염 및 악성코드 실행 방지
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# Parameters
$ITEM_ID = "W-45"
$ITEM_NAME = "백신 프로그램 설치"
$SEVERITY = "상"
$CATEGORY = "5.보안관리"

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\lib"
. "${LIB_DIR}\result_manager.ps1"

# run_all 모드가 아닐 때만 진단 정보 출력
if (-not (Test-RunallMode)) {
    Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"
    Write-Host "카테고리: $CATEGORY"
}

# 1. Check antivirus software installation
try {
    # root/SecurityCenter2 is a client-OS-only namespace and is empty on Server OS.
    # Presence alone (a stopped/disabled service, or any service whose name merely
    # contains 'anti'/'virus') is NOT proof of an active AV; require a RUNNING AV.
    $avProducts = Get-WmiObject -Namespace 'root/SecurityCenter2' -Class 'AntiVirusProduct' -ErrorAction SilentlyContinue
    $detectionDetails = @()
    $avRunning = $false

    if ($avProducts) {
        foreach ($av in $avProducts) {
            $detectionDetails += "WMI AntiVirusProduct: $($av.displayName)"
        }
        $avRunning = $true
    } else {
        # Server OS path: check Microsoft Defender real-time status, then fall back
        # to a RUNNING antivirus-named service.
        $mp = $null
        try {
            $mp = Get-MpComputerStatus -ErrorAction Stop
        } catch {
            $mp = $null
        }

        if ($mp -and ($mp.AntivirusEnabled -eq $true)) {
            $detectionDetails += "Microsoft Defender: AntivirusEnabled=$($mp.AntivirusEnabled), RealTimeProtection=$($mp.RealTimeProtectionEnabled)"
            $avRunning = $true
        } else {
            $avServices = Get-Service -ErrorAction SilentlyContinue | Where-Object {
                $_.Name -like '*anti*' -or
                $_.Name -like '*virus*' -or
                $_.DisplayName -like '*anti*' -or
                $_.DisplayName -like '*virus*'
            }

            if ($avServices) {
                foreach ($svc in $avServices) {
                    $detectionDetails += "Service: $($svc.Name) - $($svc.DisplayName) [$($svc.Status)]"
                    if ($svc.Status -eq 'Running') {
                        $avRunning = $true
                    }
                }
            }
        }
    }

    if ($avRunning) {
        $finalResult = "GOOD"
        $summary = "바이러스 백신 프로그램이 설치되어 실행 중임"
        $status = "양호"
        $commandOutput = $detectionDetails -join "`n"
    } elseif ($detectionDetails.Count -gt 0) {
        # AV-named service present but not running -> not effectively protected
        $finalResult = "VULNERABLE"
        $summary = "백신 관련 항목이 감지되었으나 실행 중인 백신이 없음"
        $status = "취약"
        $commandOutput = $detectionDetails -join "`n"
    } else {
        $finalResult = "VULNERABLE"
        $summary = "바이러스 백신 프로그램이 설치되어 있지 않음"
        $status = "취약"
        $commandOutput = "백신 프로그램을 찾을 수 없음 (SecurityCenter2/Defender/서비스 검색)"
    }

    $commandExecuted = "Get-WmiObject -Namespace 'root/SecurityCenter2' -Class 'AntiVirusProduct'; Get-MpComputerStatus; Get-Service (실행 상태 확인)"

} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandExecuted = "Get-WmiObject -Namespace 'root/SecurityCenter2' -Class 'AntiVirusProduct'; Get-Service | Where-Object { `$_.Name -like '*anti*' -or `$_.Name -like '*virus*' }"
    $commandOutput = "진단 실패: $_"
}

# Define guideline variables
$purpose = "적절한 백신 프로그램을 설치하여 바이러스 감염 여부 진단, 치료 및 파일 보호를 통해 보안 사고를 예방하기 위함"
$threat = "백신 프로그램이 설치되지 않으면 웜, 트로이 목마 등의 악성 바이러스로 인한 시스템 피해 위험이 존재함"
$criteria_good = "바이러스 백신 프로그램이 설치된 경우"
$criteria_bad = "바이러스 백신 프로그램이 설치되어 있지 않은 경우"
$remediation = "백신 프로그램 설치"

# Save results using lib
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

exit 0
