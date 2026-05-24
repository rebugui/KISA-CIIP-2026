

# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : W-19
# @Category    : Windows Server
# @Platform    : Windows Server
# @Severity    : 상
# @Title       : 불필요한 IIS 서비스 구동 점검
# @Description : 불필요한 IIS 서비스 구동 여부 점검으로 웹 서비스 취약점 방지
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================
$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\lib"
. "${LIB_DIR}\result_manager.ps1"

# Parameters
$ITEM_ID = "W-19"
$ITEM_NAME = "불필요한 IIS 서비스 구동 점검"
$SEVERITY = "상"
$CATEGORY = "2.서비스관리"

# run_all 모드가 아닐 때만 진단 정보 출력
if (-not (Test-RunallMode)) {
    Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"
    Write-Host "카테고리: $CATEGORY"
}

# 1. Check IIS service status
try {
    $iisInstalled = $false
    $w3svc = $null

    $w3svc = Get-Service -Name 'W3SVC' -ErrorAction SilentlyContinue
    if ($w3svc) {
        $iisInstalled = $true
    }

    if (-not $iisInstalled) {
        $finalResult = "GOOD"
        $summary = "IIS 서비스가 설치되지 않음"
        $status = "양호"
        $commandOutput = "IIS (W3SVC) not installed"
    } elseif ($w3svc.Status -eq 'Stopped' -or $w3svc.StartType -eq 'Disabled') {
        $finalResult = "GOOD"
        $summary = "IIS 서비스가 비활성화되어 있거나 중지됨"
        $status = "양호"
        $commandOutput = "IIS (W3SVC) Status: $($w3svc.Status), StartType: $($w3svc.StartType)"
    } else {
        $finalResult = "MANUAL"
        $summary = "IIS 서비스가 구동 중임 - 불필요한 사용인지 수동 확인 필요"
        $status = "수동진단"
        $commandOutput = "IIS (W3SVC) Status: $($w3svc.Status), StartType: $($w3svc.StartType) - 수동 판단 필요"
    }

    $commandExecuted = "Get-Service -Name 'W3SVC'"

} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandExecuted = "Get-Service -Name 'W3SVC'"
    $commandOutput = "진단 실패: $_"
}

# 2. lib를 통한 결과 저장
$purpose = "불필요한 IIS 서비스가 구동 상태인지를 점검하여 제거하고, 해당 서비스가 취약점이 제거되지 않은 상태로 외부 위협에 노출되지 않도록하기 위함"
$threat = "IIS 서비스의 WEB, FTP 등 기능이 보편적으로 사용되나, 프로파일링, 서비스 거부, 불법적인 접근, 임의의 코드 실행, 정보 공개, 바이러스, 웜, 트로이 목마 등의 공격 위험이 존재함"
$criteria_good = "IIS 서비스를 사용하지 않는 경우 또는 필요에 의해 IIS 서비스를 사용하는 경우"
$criteria_bad = "IIS 서비스를 불필요하게 사용하는 경우"
$remediation = "IIS 서비스가 불필요한 경우 IIS 서비스 중지"

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
