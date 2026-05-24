

# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-05-20
# ============================================================================
# [점검 항목 상세]
# @ID          : PC-18
# @Category    : PC (Personal Computer)
# @Platform    : Windows 10, 11
# @Severity    : 중
# @Title       : 원격 지원을 금지하도록 정책이 설정
# @Description : 원격 지원 기능에 대한 금지 정책 설정 확인을 통해 외부 접근 차단
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\lib"
. "${LIB_DIR}\result_manager.ps1"

# Parameters
$ITEM_ID = "PC-18"
$ITEM_NAME = "원격 지원을 금지하도록 정책이 설정"
$SEVERITY = "중"
$CATEGORY = "4.보안관리"

# run_all 모드가 아닐 때만 진단 정보 출력
if (-not (Test-RunallMode)) {
    Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"
    Write-Host "카테고리: $CATEGORY"
}

# 1. Check remote assistance policy (fAllowToGetHelp, fAllowUnsolicited)
try {
    $policyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
    $actualPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance"
    $regNames = @("fAllowToGetHelp", "fAllowUnsolicited")
    $commandOutputLines = @()
    $enabledSettings = @()
    $disabledSettings = @()
    $missingSettings = @()
    $unexpectedSettings = @()

    foreach ($regName in $regNames) {
        $effectiveValue = $null
        $effectiveSource = $null

        $policyValue = Get-ItemProperty -Path $policyPath -Name $regName -ErrorAction SilentlyContinue
        if ($policyValue -ne $null -and $policyValue.PSObject.Properties.Name -contains $regName) {
            $effectiveValue = [int]$policyValue.$regName
            $effectiveSource = "Policy: $policyPath"
        } else {
            $commandOutputLines += "$regName : Policy not set ($policyPath)"

            # 정책이 없으면 실제 원격 지원 설정 경로 확인
            $actualValue = Get-ItemProperty -Path $actualPath -Name $regName -ErrorAction SilentlyContinue
            if ($actualValue -ne $null -and $actualValue.PSObject.Properties.Name -contains $regName) {
                $effectiveValue = [int]$actualValue.$regName
                $effectiveSource = "Actual: $actualPath"
            }
        }

        if ($null -eq $effectiveValue) {
            $missingSettings += $regName
            $commandOutputLines += "$regName : Not set (actual path: $actualPath)"
        } else {
            $commandOutputLines += "$regName : $effectiveValue ($effectiveSource)"
            if ($effectiveValue -eq 0) {
                $disabledSettings += $regName
            } elseif ($effectiveValue -eq 1) {
                $enabledSettings += $regName
            } else {
                $unexpectedSettings += "$regName=$effectiveValue"
            }
        }
    }

    if ($enabledSettings.Count -gt 0) {
        $finalResult = "VULNERABLE"
        $summary = "원격 지원 기능 허용 설정 감지: $($enabledSettings -join ', ') = 1"
        $status = "취약"
    } elseif ($unexpectedSettings.Count -gt 0) {
        $finalResult = "MANUAL"
        $summary = "원격 지원 설정값이 예상 범위를 벗어남 ($($unexpectedSettings -join ', ')): 수동 확인 필요"
        $status = "수동진단"
    } elseif ($missingSettings.Count -gt 0) {
        $finalResult = "MANUAL"
        $summary = "원격 지원 일부 설정값 없음 ($($missingSettings -join ', ')): 수동 확인 필요"
        $status = "수동진단"
    } else {
        $finalResult = "GOOD"
        $summary = "원격 지원 요청 및 원격 지원 제안 모두 금지됨 (fAllowToGetHelp=0, fAllowUnsolicited=0)"
        $status = "양호"
    }

    $commandOutput = $commandOutputLines -join "`r`n"
    $commandExecuted = "Get-ItemProperty '$policyPath' -Name fAllowToGetHelp,fAllowUnsolicited; Get-ItemProperty '$actualPath' -Name fAllowToGetHelp,fAllowUnsolicited"

} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandOutput = "진단 실패: $_"
    $commandExecuted = "reg query HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
}

# 2. Define guideline variables
$purpose = '원격 지원 기능을 비활성화하여 비인가자가 원격에서 접근을 방지하기 위함'
$threat = '원격 지원 기능이 활성화되어 비인가자에게 원격에서의 접근이 허용될 경우, 시스템 제어 권한이 악용될 수 있는 위험이 존재함'
$criteria_good = '원격 지원이''사용 안 함''으로 설정된 경우'
$criteria_bad = '원격 지원이''사용''으로 설정된 경우'
$remediation = '원격 지원 서비스 비활성화'

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
