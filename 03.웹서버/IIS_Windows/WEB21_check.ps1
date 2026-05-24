# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : WEB-21
# @Category    : Web Server
# @Platform    : IIS (Windows Server)
# @Severity    : 중
# @Title       : 동적페이지요청및응답값검증
# @Description : 동적 페이지의 요청 및 응답값을 검증하여 SQL Injection, XSS(Command Injection) 등 공격을 방지합니다. IIS Request Filtering 활성화 및 애플리케이션 레벨의 입력값 검증 로직 구현이 필요합니다.
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\..\lib"
. "${LIB_DIR}\result_manager.ps1"

$ITEM_ID = "WEB-21"
$ITEM_NAME = "HTTP 리디렉션"

Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"

try {
    # IIS Request Filtering 및 입력값 검증 확인
    $sites = Get-Website
    $filteringEnabled = $false
    $siteInfo = @()

    foreach ($site in $sites) {
        $siteName = $site.Name

        # Request Filtering 확인
        $requestFiltering = Get-WebConfiguration -Filter "/system.webServer/security/requestFiltering" -Location $siteName -ErrorAction SilentlyContinue
        if ($requestFiltering) {
            $filteringEnabled = $true
            $maxURL = $requestFiltering.requestLimits.maxUrl
            $maxQueryString = $requestFiltering.requestLimits.maxQueryString
            $siteInfo += "Site: $siteName, Request Filtering: Enabled, MaxURL: $maxURL, MaxQueryString: $maxQueryString"
        } else {
            $siteInfo += "Site: $siteName, Request Filtering: Not configured"
        }
    }

    $commandExecuted = "Get-Website; Get-WebConfiguration -Filter '/system.webServer/security/requestFiltering'"

    if ($filteringEnabled) {
        $finalResult = "MANUAL"
        $summary = "Request Filtering이 구성되어 있지만, 애플리케이션 레벨의 입력값 검증도 필요합니다: " + ($siteInfo[0] + " 외 " + ($siteInfo.Count - 1) + "개")
        $status = "수동진단"
        $commandOutput = $siteInfo -join "`n"
    } else {
        $finalResult = "MANUAL"
        $summary = "Request Filtering이 구성되지 않았습니다. 애플리케이션 레벨의 입력값 검증이 필요합니다."
        $status = "수동진단"
        $commandOutput = "Request Filtering: Not configured on any site"
    }

} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandExecuted = "Get-Website; Get-WebConfiguration -Filter '/system.webServer/security/requestFiltering'"
    $commandOutput = "진단 실패: $_"
}

# 2. lib를 통한 결과 저장
$purpose = 'HTTP 차단 및 HTTPS로 Redirection 활성화를 통해 평 문으로 전송되는 데이터를 암호화하여 공격자의 데이터 스니 핑에 대비하기 위함'
$threat = 'HTTP 통신은 암호화 전송이 아닌 평 문 전송을 하므로 공격자가 스니핑을 시도할 경우 관리자의 ID, 비밀번호가 노출되어 악의적 사용자가 관리자 계정을 탈취할 수 있는 위험이 존재함'
$criteria_good = 'HTTP 접근 시 HTTPSRedirection이 활성화된 경우'
$criteria_bad = 'HTTP 접근 시 HTTPSRedirection이 비활성화된 경우'
$remediation = 'HTTP Redirection 활성화 설정'

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
