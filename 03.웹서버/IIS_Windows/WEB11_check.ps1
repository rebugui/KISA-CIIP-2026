# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : WEB-11
# @Category    : Web Server
# @Platform    : IIS (Windows Server)
# @Severity    : 하
# @Title       : 웹서비스경로설정
# @Description : 웹 서비스 경로를 기본 경로(C:\inetpub\wwwroot)가 아닌 별도의 분리된 경로로 설정하여 보안을 강화합니다. 기본 경로 사용 시 공격자가 웹 서버 구조를 쉽게 파악하고 공격 경로를 예측할 수 있는 위험이 있습니다.
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\..\lib"
. "${LIB_DIR}\result_manager.ps1"

$ITEM_ID = "WEB-11"
$ITEM_NAME = "웹 서비스 경로 설정"
$SEVERITY = "중"

Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"

try {
    # IIS 웹사이트 경로 확인
    $sites = Get-Website
    $defaultPaths = @()

    foreach ($site in $sites) {
        $path = $site.PhysicalPath
        # 기본 경로 확인 (C:\inetpub\wwwroot, C:\inetpub\wwwroot\mysite 등)
        if ($path -like "C:\inetpub\wwwroot*" -or $path -eq "C:\inetpub\wwwroot") {
            $defaultPaths += "Site: $($site.Name), Path: $path (기본 경로 사용)"
        }
    }

    $commandExecuted = "Get-Website | Select-Object Name, PhysicalPath"

    if ($defaultPaths.Count -gt 0) {
        $finalResult = "VULNERABLE"
        $summary = "기본 경로(C:\inetpub\wwwroot)를 사용하는 웹사이트가 있습니다: " + ($defaultPaths -join ", ")
        $status = "취약"
        $commandOutput = $defaultPaths -join "`n"
    } else {
        $finalResult = "GOOD"
        $summary = "모든 웹사이트가 기본 경로가 아닌 별도의 분리된 경로를 사용합니다. (보안 권고사항 준수)"
        $status = "양호"
        $commandOutput = ($sites | ForEach-Object { "Site: $($_.Name), Path: $($_.PhysicalPath)" }) -join "`n"
    }

} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandExecuted = "Get-Website | Select-Object Name, PhysicalPath"
    $commandOutput = "진단 실패: $_"
}

# 가이드라인 변수
$purpose = '웹 서비스 영역 내 불필요한 경로를 분리해 웹 서비스의 침해가 시스템 영역으로 확장될 가능성을 최소화하기 위함'
$threat = '웹 서비스 경로를 기타 업무와 영역이 분리되지 않은 경로로 설정하거나, 불필요한 경로가 존재할 경우 외부에서 시스템 중요 파일이나 기능에 비인가 접근이 발생할 위험이 존재함'
$criteria_good = '웹 서버 경로를 기타 업무와 영역이 분리된 경로로 설정 및 불필요한 경로가 존재하지 않는 경우'
$criteria_bad = '웹 서버 경로를 기타 업무와 영역이 분리되지 않은 경로로 설정하거나 불필요한 경로가 있는 경우'
$remediation = '웹 서버의 경로를 별도의 경로로 변경 및 불필요한 경로 제거 설정'

# 결과 저장
Save-DualResult -ItemId "${ITEM_ID}" `
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
