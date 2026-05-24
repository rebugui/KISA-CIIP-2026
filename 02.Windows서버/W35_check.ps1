# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : W-35
# @Category    : Windows Server
# @Platform    : Windows Server
# @Severity    : 중
# @Title       : 불필요한 ODBC/OLE-DB 데이터 소스와 드라이브 제거
# @Description : 불필요한 ODBC/OLE-DB 데이터 소스 제거로 비인가 데이터베이스 접속 차단
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# Parameters
$ITEM_ID = "W-35"
$ITEM_NAME = "불필요한 ODBC/OLE-DB 데이터 소스와 드라이브 제거"
$SEVERITY = "중"
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
Write-Host ""

# Diagnostic Logic
try {
    $ErrorActionPreference = 'SilentlyContinue'
    $regPath = 'HKLM:\SOFTWARE\ODBC\ODBC.INI\ODBC Data Sources'
    $systemDsnPath = 'HKLM:\SOFTWARE\ODBC\ODBC.INI\ODBC Data Sources'

    if (Test-Path $regPath) {
        $dsns = Get-Item $regPath -ErrorAction SilentlyContinue

        if ($dsns) {
            $dsnCount = ($dsns.GetValueNames() | Measure-Object).Count

            if ($dsnCount -gt 0) {
                $finalResult = "MANUAL"
                $status = "수동진단"
                $summary = "시스템 DSN에 데이터 소스가 존재하므로 수동 확인 필요 (현재 사용 중인지 확인 필요)"
                $commandOutput = "Found $dsnCount DSN entries - manual verification required"
            } else {
                $finalResult = "GOOD"
                $status = "양호"
                $summary = "시스템 DSN에 등록된 데이터 소스가 없거나 현재 사용 중인 것만 존재"
                $commandOutput = "No DSN entries found"
            }
        } else {
            $finalResult = "GOOD"
            $status = "양호"
            $summary = "시스템 DSN에 등록된 데이터 소스가 없거나 현재 사용 중인 것만 존재"
            $commandOutput = "No DSN entries found"
        }
    } else {
        $finalResult = "GOOD"
        $status = "양호"
        $summary = "시스템 DSN에 등록된 데이터 소스가 없거나 현재 사용 중인 것만 존재"
        $commandOutput = "ODBC registry path not found"
    }

    $commandExecuted = "Get-Item 'HKLM:\SOFTWARE\ODBC\ODBC.INI\ODBC Data Sources'"

} catch {
    $finalResult = "MANUAL"
    $status = "수동진단"
    $summary = "진단 실패: 수동 확인 필요"
    $commandExecuted = "Get-Item 'HKLM:\SOFTWARE\ODBC\ODBC.INI\ODBC Data Sources'"
    $commandOutput = "진단 실패: $_"
}

# Define guideline variables
$purpose = "불필요한 데이터 소스 및 드라이버를 ODBC 데이터 소스 관리자 도구를 이용해 제거하여 비인가자에 의한 데이터베이스 접속 및 자료 유출을 차단하기 위함"
$threat = "불필요한 ODBC/OLE-DB 데이터 소스를 통한 비인가자에 의한 데이터베이스 접속 및 자료 유출이 존재함"
$criteria_good = "시스템 DSN 부분의 데이터 소스를 현재 사용하고 있는 경우"
$criteria_bad = "시스템 DSN 부분의 데이터 소스를 현재 사용하고 있지 않은 경우"
$remediation = "사용하지 않는 불필요한 ODBC 데이터 소스 제거"

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
