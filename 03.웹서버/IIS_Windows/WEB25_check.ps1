# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : WEB-25
# @Category    : Web Server
# @Platform    : IIS_Windows
# @Severity    : 상
# @Title       : 주기적 보안 패치 및 벤더 권고 사항 적용
# @Description : X-XSS-Protection HTTP 헤더를 설정하여 XSS(Cross-Site Scripting) 공격을 방지합니다. X-XSS-Protection 헤더 미설정 시 브라우저의 XSS 필터가 비활성화되어 XSS 공격에 취약합니다.
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\..\lib"
. "${LIB_DIR}\result_manager.ps1"

$ITEM_ID = "WEB-25"
$ITEM_NAME = "주기적 보안 패치 및 벤더 권고 사항 적용"

Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"

try {
    # IIS X-XSS-Protection 헤더 확인
    $sites = Get-Website
    $sitesWithoutHeader = @()
    $sitesWithHeader = @()

    foreach ($site in $sites) {
        $siteName = $site.Name
        $path = $site.PhysicalPath

        # web.config에서 customHeaders 확인
        $webConfig = Join-Path $path "web.config"
        $headerFound = $false

        if (Test-Path $webConfig) {
            [xml]$config = Get-Content $webConfig
            $httpProtocol = $config.configuration.'system.webServer'.httpProtocol
            if ($httpProtocol) {
                foreach ($header in $httpProtocol.customHeaders.Collection) {
                    if ($header.name -eq "X-XSS-Protection") {
                        $headerFound = $true
                        $sitesWithHeader += "Site: $siteName, X-XSS-Protection: $($header.value)"
                        break
                    }
                }
            }
        }

        # IIS 전체 설정 확인
        if (-not $headerFound) {
            $iisConfig = Get-WebConfiguration -Filter "/system.webServer/httpProtocol/customHeaders/add[@name='X-XSS-Protection']" -Location $siteName -ErrorAction SilentlyContinue
            if ($iisConfig) {
                $headerFound = $true
                $sitesWithHeader += "Site: $siteName, X-XSS-Protection: $($iisConfig.value)"
            }
        }

        if (-not $headerFound) {
            $sitesWithoutHeader += "Site: $siteName, X-XSS-Protection: Not configured"
        }
    }

    $commandExecuted = "Get-Website; Get-WebConfiguration -Filter '/system.webServer/httpProtocol/customHeaders'"

    if ($sitesWithoutHeader.Count -gt 0) {
        $finalResult = "VULNERABLE"
        $summary = "X-XSS-Protection 헤더가 설정되지 않은 사이트가 있습니다: " + ($sitesWithoutHeader[0] + " 외 " + ($sitesWithoutHeader.Count - 1) + "개")
        $status = "취약"
        $commandOutput = (($sitesWithHeader + $sitesWithoutHeader) -join "`n")
    } else {
        $finalResult = "GOOD"
        $summary = "모든 웹사이트에 X-XSS-Protection 헤더가 설정되어 있습니다. (보안 권고사항 준수)"
        $status = "양호"
        $commandOutput = $sitesWithHeader -join "`n"
    }

} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandExecuted = "Get-Website; Get-WebConfiguration -Filter '/system.webServer/httpProtocol/customHeaders'"
    $commandOutput = "진단 실패: $_"
}

# 2. lib를 통한 결과 저장
$purpose = '주기적인 최신 보안 패치를 통해 보안성 및 시스템 안정성을 확보하기 위함'
$threat = '주기적으로 최신 보안 패치를 적용하지 않을 경우, 알려진 취약점을 이용한 공격 또는 새로운 공격에 대한 침해 사고 발생 위험이 존재함'
$criteria_good = '최신 보안 패치가 적용되어 있으며, 패치 적용 정책을 수립하여 주기적인 패치 관리를 하는 경우'
$criteria_bad = '최신 보안 패치가 적용되어 있지 않거나 패치 적용 정책을 수립 및 주기적인 패치 관리를 하지'
$remediation = '패치 적용에 따른 서비스 영향 정도를 정확히 파악하여 주기적인 패치 적용 정책 수립 및 적용하도록 설정'

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
