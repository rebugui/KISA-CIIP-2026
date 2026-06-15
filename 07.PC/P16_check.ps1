

# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : PC-16
# @Category    : PC (Personal Computer)
# @Platform    : Windows 10, 11
# @Severity    : 상
# @Title       : 화면 보호기 대기 시간 설정 및 재시작 시 암호 보호 설정
# @Description : 화면 보호기 대기 시간 설정 및 재시작 시 암호 보호 기능 활성화 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\lib"
. "${LIB_DIR}\result_manager.ps1"

# Parameters
$ITEM_ID = "PC-16"
$ITEM_NAME = "화면 보호기 대기 시간 설정 및 재시작 시 암호 보호 설정"
$SEVERITY = "상"
$CATEGORY = "4.보안관리"

# run_all 모드가 아닐 때만 진단 정보 출력
if (-not (Test-RunallMode)) {
    Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"
    Write-Host "카테고리: $CATEGORY"
}

# 1. Check screensaver settings
try {
    $active = Get-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "ScreenSaveActive" -ErrorAction SilentlyContinue
    $timeout = Get-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "ScreenSaveTimeOut" -ErrorAction SilentlyContinue
    $secure = Get-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "ScreenSaverIsSecure" -ErrorAction SilentlyContinue

    $commandOutput = ""
    $activeInfo = ""
    $timeoutInfo = ""
    $secureInfo = ""

    # ScreenSaveActive: 화면보호기 작동 여부. 0이면 화면보호기 자체가 비활성(작동 안 함).
    $activeEnabled = $false
    if ($active -ne $null) {
        $activeVal = [int]$active.ScreenSaveActive
        $activeInfo = "ScreenSaveActive: $activeVal"
        if ($activeVal -eq 1) { $activeEnabled = $true }
    } else {
        $activeInfo = "ScreenSaveActive: Not set"
    }
    $commandOutput += $activeInfo + "`r`n"

    # ScreenSaveTimeOut(초). 0이면 화면보호기가 작동하지 않으므로 유효한 대기시간이 아님.
    $timeoutMinutes = 0
    $timeoutValid = $false
    if ($timeout -ne $null) {
        $timeoutSeconds = [int]$timeout.ScreenSaveTimeOut
        $timeoutMinutes = [math]::Round($timeoutSeconds / 60, 0)
        $timeoutInfo = "ScreenSaveTimeOut: $timeoutMinutes minutes ($timeoutSeconds sec)"
        if ($timeoutSeconds -gt 0 -and $timeoutMinutes -le 10) { $timeoutValid = $true }
    } else {
        $timeoutInfo = "ScreenSaveTimeOut: Not set"
    }
    $commandOutput += $timeoutInfo + "`r`n"

    $secureEnabled = $false
    if ($secure -ne $null) {
        $secureInfo = "ScreenSaverIsSecure: $($secure.ScreenSaverIsSecure)"
        if ([int]$secure.ScreenSaverIsSecure -eq 1) { $secureEnabled = $true }
    } else {
        $secureInfo = "ScreenSaverIsSecure: Not set"
    }
    $commandOutput += $secureInfo + "`r`n"

    # 양호 조건: 화면보호기 작동(Active=1) AND 0 < 대기시간 <= 10분 AND 암호보호(IsSecure=1) 모두 충족
    if ($activeEnabled -and $timeoutValid -and $secureEnabled) {
        $finalResult = "GOOD"
        $summary = "화면보호기 작동, 대기시간 10분 이하, 암호보호 설정됨 ($activeInfo, $timeoutInfo, $secureInfo)"
        $status = "양호"
    } else {
        $finalResult = "VULNERABLE"
        $reasons = @()
        if (-not $activeEnabled) { $reasons += "화면보호기 비활성(ScreenSaveActive≠1)" }
        if ($timeout -eq $null) {
            $reasons += "대기시간 미설정"
        } elseif ([int]$timeout.ScreenSaveTimeOut -le 0) {
            $reasons += "대기시간 0(화면보호기 작동 안 함)"
        } elseif ($timeoutMinutes -gt 10) {
            $reasons += "대기시간 10분 초과($timeoutMinutes분)"
        }
        if (-not $secureEnabled) { $reasons += "암호보호 미설정(ScreenSaverIsSecure≠1)" }
        $summary = "화면보호기 설정 미흡: " + ($reasons -join ", ") + " ($activeInfo, $timeoutInfo, $secureInfo)"
        $status = "취약"
    }

    $commandExecuted = "reg query 'HKCU\Control Panel\Desktop' /v ScreenSaveActive /v ScreenSaveTimeOut /v ScreenSaverIsSecure"

} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandOutput = "진단 실패: $_"
    $commandExecuted = "reg query HKCU\Control Panel\Desktop"
}

# 2. Define guideline variables
$purpose = '사용자가 일정 시간 동안 아무런 작업을 수행하지 않을 경우, 자동으로 로그오프되거나 워크스테이션이 잠기도록하기 위함'
$threat = '화면 보호기가 작동하지 않거나 재시작 시 비밀번호를 설정하지 않는다면, 사용자가 자리를 비운 사이 임의의 사용자가 해당 시스템에 접근하여 중요 정보를 유출하거나, 악의적인 행위를 통해 시스템 운영에 악영향을 미칠 수 있는 위험이 존재함'
$criteria_good = '화면 보호기 설정(대기 시간 10분 이하)및 비밀번호로 보호가 설정된 경우'
$criteria_bad = '화면 보호기 설정(대기 시간 10분 초과)및 비밀번호로 보호가 설정되지 않은 경우'
$remediation = '화면 보호기 설정 및 비밀번호 보호 설정'

# 3. Save results using Save-DualResult
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

Write-Host "진단 완료: $ITEM_ID ($finalResult)"

exit 0
