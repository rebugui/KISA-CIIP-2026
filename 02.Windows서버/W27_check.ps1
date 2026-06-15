# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : W-27
# @Category    : Windows Server
# @Platform    : Windows Server
# @Severity    : 상
# @Title       : 최신 Windows OS Build 버전 적용
# @Description : 최신 Windows OS Build 버전 적용으로 알려진 보안 취약점 방지
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# Parameters
$ITEM_ID = "W-27"
$ITEM_NAME = "최신 Windows OS Build 버전 적용"
$SEVERITY = "상"
$CATEGORY = "2.서비스관리"

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\lib"
. "${LIB_DIR}\result_manager.ps1"

# run_all 모드가 아닐 때만 진단 정보 출력
if (-not (Test-RunallMode)) {
    Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"
    Write-Host "카테고리: $CATEGORY"
}

# 1. Run diagnostic
# 패치 최신성(최신 누적 업데이트 설치 여부)은 Microsoft Update Catalog와의 비교가 필요하며
# 로컬에서 정적으로 판단할 수 없다. 부팅 경과일은 패치 적용 여부의 대리 지표가 될 수 없으므로
# 자동 GOOD/VULNERABLE 판정을 하지 않고, 빌드/핫픽스 증적과 함께 MANUAL을 emit한다.
try {
    $osVersion = [System.Environment]::OSVersion.Version
    $build = $osVersion.Build
    $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
    $caption = if ($osInfo) { $osInfo.Caption } else { "Unknown" }
    $lastBoot = if ($osInfo) { $osInfo.LastBootUpTime } else { "Unknown" }

    # 설치된 핫픽스(QFE) 증적 수집 - 최근 항목 위주.
    $hotfixes = @(Get-HotFix -ErrorAction SilentlyContinue | Sort-Object -Property InstalledOn -Descending)
    $latestHotfix = if ($hotfixes.Count -gt 0) {
        ($hotfixes | Select-Object -First 5 | ForEach-Object { "$($_.HotFixID)($($_.InstalledOn))" }) -join ', '
    } else {
        "No hotfix records available"
    }

    $finalResult = "MANUAL"
    $status = "수동진단"
    $summary = "최신 Build 적용 여부는 Microsoft Update Catalog와의 비교가 필요하여 자동 판단 불가. 아래 빌드/핫픽스 증적으로 수동 확인 필요"
    $commandOutput = "OS: $caption`r`nOS Version: $($osVersion.ToString())`r`nOS Build: $build`r`nLast Boot: $lastBoot`r`nRecent Hotfixes: $latestHotfix"
} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandOutput = $_.Exception.Message
}

$commandExecuted = "[System.Environment]::OSVersion.Version; Get-CimInstance Win32_OperatingSystem; Get-HotFix"

# 2. lib를 통한 결과 저장
$purpose = "시스템을 최신 버전으로 유지하여 새로운 위협 및 진행 중인 위협으로부터 중요 정보와 시스템을 보호하기 위함"
$threat = "보안 업데이트를 적용하지 않으면 시스템 및 응용 프로그램의 취약성으로 인해 권한 상승, 원격 코드 실행, 보안 기능 우회 등의 위험이 존재함"
$criteria_good = "최신 Build가 설치되어 있으며 적용 절차 및 방법이 수립된 경우"
$criteria_bad = "최신 Build가 설치되지 않거나, 적용 절차 및 방법이 수립되지 않은 경우"
$remediation = "설치에 따른 영향도 확인 후 최신 Build 설치(설치 후 시스템 재시작 필요)"

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
