

# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-05-20
# ============================================================================
# [점검 항목 상세]
# @ID          : PC-06
# @Category    : PC (Personal Computer)
# @Platform    : Windows 10, 11
# @Severity    : 상
# @Title       : 비인가 상용 메신저 사용 금지
# @Description : 비인가 상용 메신저 프로그램의 사용을 금지하여 정보 유출 방지
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\lib"
. "${LIB_DIR}\result_manager.ps1"

# Parameters
$ITEM_ID = "PC-06"
$ITEM_NAME = "비인가 상용 메신저 사용 금지"
$SEVERITY = "상"
$CATEGORY = "2.서비스관리"

# run_all 모드가 아닐 때만 진단 정보 출력
if (-not (Test-RunallMode)) {
    Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"
    Write-Host "카테고리: $CATEGORY"
}

# 1. Run diagnostic
$commandExecuted = "Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Messenger\Client -Name Disabled; Get-Service Messenger; uninstall registry messenger scan; Get-Process messenger scan"
$commandOutput = ""
try {
    # Check registry policy for Windows Messenger disable status
    $policyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Messenger\Client"
    $policyValue = Get-ItemProperty -Path $policyPath -Name Disabled -ErrorAction SilentlyContinue
    $outputLines = @()

    # Check if policy exists and is set to disable (Disabled = 1)
    $policyDisabled = $false
    $policyExplicitEnabled = $false
    if ($null -ne $policyValue) {
        $disabledValue = [int]$policyValue.Disabled
        $outputLines += "Disabled policy: $disabledValue"
        if ($disabledValue -eq 1) {
            $policyDisabled = $true
        } elseif ($disabledValue -eq 0) {
            $policyExplicitEnabled = $true
        }
    } else {
        $outputLines += "Disabled policy: Not set"
    }

    # Also check Windows Messenger service status
    $messengerService = Get-Service -Name "Messenger" -ErrorAction SilentlyContinue
    $serviceRunning = $false
    if ($messengerService -ne $null -and $messengerService.Status -eq "Running") {
        $serviceRunning = $true
    }
    if ($null -ne $messengerService) {
        $outputLines += "Messenger service: $($messengerService.Status), StartType: $($messengerService.StartType)"
    } else {
        $outputLines += "Messenger service: Not installed"
    }

    # 주요 상용 메신저 설치/실행 흔적 확인
    $messengerCandidates = @(
        @{ Name = "KakaoTalk"; DisplayPatterns = @("KakaoTalk", "카카오톡"); ProcessNames = @("KakaoTalk") },
        @{ Name = "LINE"; DisplayPatterns = @("LINE"); ProcessNames = @("LINE") },
        @{ Name = "Telegram"; DisplayPatterns = @("Telegram"); ProcessNames = @("Telegram") },
        @{ Name = "WhatsApp"; DisplayPatterns = @("WhatsApp"); ProcessNames = @("WhatsApp") },
        @{ Name = "Slack"; DisplayPatterns = @("Slack"); ProcessNames = @("slack") },
        @{ Name = "Discord"; DisplayPatterns = @("Discord"); ProcessNames = @("Discord") },
        @{ Name = "Skype"; DisplayPatterns = @("Skype"); ProcessNames = @("Skype", "SkypeApp") },
        @{ Name = "Microsoft Teams"; DisplayPatterns = @("Microsoft Teams", "Teams Machine-Wide Installer"); ProcessNames = @("Teams", "ms-teams", "msteams") },
        @{ Name = "Zoom"; DisplayPatterns = @("Zoom", "Zoom Workplace"); ProcessNames = @("Zoom") },
        @{ Name = "NateOn"; DisplayPatterns = @("NateOn", "네이트온"); ProcessNames = @("NateOn", "NateOnMain") },
        @{ Name = "WeChat"; DisplayPatterns = @("WeChat", "微信"); ProcessNames = @("WeChat", "WeChatAppEx") }
    )

    $candidateNames = $messengerCandidates | ForEach-Object { $_.Name }
    $outputLines += "Commercial messenger candidate list: $($candidateNames -join ', ')"

    $uninstallPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )

    $installedApps = @()
    foreach ($uninstallPath in $uninstallPaths) {
        $installedApps += @(Get-ItemProperty -Path $uninstallPath -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName })
    }
    $runningProcesses = @(Get-Process -ErrorAction SilentlyContinue)

    $detectedMessengers = @()
    foreach ($candidate in $messengerCandidates) {
        foreach ($app in $installedApps) {
            foreach ($pattern in $candidate.DisplayPatterns) {
                if ($app.DisplayName -like "*$pattern*") {
                    $versionText = if ($app.DisplayVersion) { " $($app.DisplayVersion)" } else { "" }
                    $detectedMessengers += "$($candidate.Name) installed: $($app.DisplayName)$versionText"
                    break
                }
            }
        }

        foreach ($proc in $runningProcesses) {
            if ($candidate.ProcessNames -contains $proc.ProcessName) {
                $detectedMessengers += "$($candidate.Name) running process: $($proc.ProcessName) (PID $($proc.Id))"
            }
        }
    }

    $detectedMessengers = @($detectedMessengers | Sort-Object -Unique)
    if ($detectedMessengers.Count -gt 0) {
        $outputLines += "Detected commercial messenger candidates:"
        $outputLines += $detectedMessengers
    } else {
        $outputLines += "Detected commercial messenger candidates: None"
    }
    $outputLines += "Note: 조직에서 허용한 메신저인지 여부는 기관 정책 기준으로 별도 확인 필요"

    if ($detectedMessengers.Count -gt 0) {
        $finalResult = "VULNERABLE"
        $summary = "상용 메신저 후보 탐지됨 ($($detectedMessengers.Count)건): 기관 허용 여부 확인 필요"
        $status = "취약"
    } elseif ($serviceRunning -or $policyExplicitEnabled) {
        $finalResult = "VULNERABLE"
        if ($serviceRunning) {
            $summary = "Windows Messenger 실행 중 (서비스 상태: $($messengerService.Status), 시작 유형: $($messengerService.StartType))"
        } else {
            $summary = "Windows Messenger 비활성화 정책이 사용 안 함으로 설정되지 않음 (Disabled = 0)"
        }
        $status = "취약"
    } elseif ($policyDisabled -and -not $serviceRunning) {
        $finalResult = "GOOD"
        $summary = "상용 메신저 후보 미탐지 및 Windows Messenger 실행 중지됨 (정책 비활성화 및 서비스 중지)"
        $status = "양호"
    } else {
        $finalResult = "GOOD"
        $summary = "상용 메신저 후보 미탐지 및 Windows Messenger 서비스 미설치 또는 실행 중지됨"
        $status = "양호"
    }

    $commandOutput = $outputLines -join "`r`n"
} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandOutput = "진단 실패: $_"
}

# 2. lib를 통한 결과 저장
$purpose = '상용 메신저 차단을 통하여 메신저를 이용한 개인 정보 및 내부 주요 정보 유출을 막기 위함'
$threat = '일반 사용자 PC에서 메신저 차단을 하지 않을 경우, 메신저를 통해 주요 정보가 유출되거나, 악성 코드가 유입될 위험이 존재함'
$criteria_good = 'WindowsMessenger가 실행 중지된 상태이거나 상용 메신저가 설치되지 않은 경우'
$criteria_bad = 'WindowsMessenger가 실행 중이거나 상용 메신저가 설치된 경우'
$remediation = '''WindowsMessenger를 실행하지 않음''설정 및 상용 메신저 삭제'

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
