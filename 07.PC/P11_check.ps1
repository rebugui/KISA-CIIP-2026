

# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-05-20
# ============================================================================
# [점검 항목 상세]
# @ID          : PC-11
# @Category    : PC (Personal Computer)
# @Platform    : Windows 10, 11
# @Severity    : 상
# @Title       : 지원이 종료되지 않은 WindowsOSBuild 적용
# @Description : 최신 보안 패치 및 벤더 권고 사항 적용 및 Windows OS Build 버전 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\lib"
. "${LIB_DIR}\result_manager.ps1"

# Parameters
$ITEM_ID = "PC-11"
$ITEM_NAME = "지원이 종료되지 않은 WindowsOSBuild 적용"
$SEVERITY = "상"
$CATEGORY = "3.패치관리"

# run_all 모드가 아닐 때만 진단 정보 출력
if (-not (Test-RunallMode)) {
    Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"
    Write-Host "카테고리: $CATEGORY"
}

# 1. Run diagnostic
try {
    $command = 'Get-CimInstance Win32_OperatingSystem; Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $os = Get-CimInstance Win32_OperatingSystem
    $caption = $os.Caption
    $build = [int]$os.BuildNumber

    $currentVersion = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue
    $displayVersion = $currentVersion.DisplayVersion
    $releaseId = $currentVersion.ReleaseId
    $ubr = $currentVersion.UBR

    $localBuild = if ($null -ne $ubr) { "$build.$ubr" } else { "$build.0" }

    $commandDetails = @()
    $commandDetails += "OS: $caption | Build: $localBuild"
    if ($displayVersion) { $commandDetails += "DisplayVersion: $displayVersion" }
    if ($releaseId) { $commandDetails += "ReleaseId: $releaseId" }
    if ($currentVersion.CurrentBuild) { $commandDetails += "CurrentBuild: $($currentVersion.CurrentBuild)" }
    if ($null -ne $ubr) { $commandDetails += "UBR: $ubr" }
    $commandDetails += "FullBuild: $localBuild"

    $finalResult = "MANUAL"
    $summary = "현재 OS 버전/빌드 확인 완료: 최신 보안 패치 적용 여부 수동 확인 필요 (현재 빌드: $localBuild)"
    $status = "수동진단"
    $commandResult = $commandDetails -join "`r`n"
} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandResult = $_.Exception.Message
}

# 2. Define guideline variables
$purpose = '최신 서비스 팩이 적용되어 있는지 점검하여 시스템 취약점을 이용한 공격(익스플로잇)에 대비가 되어 있는지 확인하기 위함'
$threat = '최신 서비스 팩이 적용되지 않았을 경우 비인가자의 시스템 취약점을 이용한 공격(익스플로잇)에 노출될 수 있는 위험이 존재함'
$criteria_good = '최신빌드가 적용되어 있고 내부적으로 관리 절차를 수립하여 이행한 경우'
$criteria_bad = '최신빌드가 적용되어 있지 않거나 내부적으로 관리 절차가 수립되지 않은 경우'
$remediation = 'WindowsUpdate 사이트에 접속하여 최신 서비스 팩 여부 확인 및 적용'

# 3. Save results using Save-DualResult
Save-DualResult -ItemId $ITEM_ID `
    -ItemName $ITEM_NAME `
    -Status $status `
    -FinalResult $finalResult `
    -InspectionSummary $summary `
    -CommandResult $commandResult `
    -CommandExecuted $command `
    -GuidelinePurpose $purpose `
    -GuidelineThreat $threat `
    -GuidelineCriteriaGood $criteria_good `
    -GuidelineCriteriaBad $criteria_bad `
    -GuidelineRemediation $remediation

Write-Host "진단 완료: $ITEM_ID ($finalResult)"

exit 0
