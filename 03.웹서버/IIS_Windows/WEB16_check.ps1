# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : WEB-16
# @Category    : Web Server
# @Platform    : IIS_Windows
# @Severity    : 중
# @Title       : 웹 서비스 헤더 정보 노출 제한
# @Description : HTTP 응답 헤더에서 Server, X-Powered-By 등 서버 정보를 제거하거나 제한하여 정보 유출을 방지합니다. 서버 버전 정보 노출 시 공격자가 해당 버전의 취약점을 악용한 공격이 가능해집니다.
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\..\lib"
. "${LIB_DIR}\result_manager.ps1"

$ITEM_ID = "WEB-16"
$ITEM_NAME = "웹 서비스 헤더 정보 노출 제한"
$SEVERITY = "중"

Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"

try {
    # IIS Server Header 및 Version 정보 확인
    # 주의: Server 헤더는 web.config의 customHeaders 외에도 여러 방법으로 제거할 수 있다.
    #  - system.webServer/security/requestFiltering @removeServerHeader="true" (IIS 10/2016+)
    #  - URL-Rewrite outboundRules 의 RESPONSE_SERVER 제거 규칙
    #  - 레지스트리 HKLM\SYSTEM\...\HTTP\Parameters DisableServerHeader (서버 전역)
    # 실제 응답 헤더를 직접 읽지 않는 한, 위 정적 설정 어디에도 제거 근거가 없을 때
    # "노출됨"이라고 단정할 수 없으므로 해당(증명 불가) 경우는 VULNERABLE이 아닌
    # MANUAL로 분류한다. (unknowable -> MANUAL, 오탐 방지)
    $sites = Get-Website
    $siteInfo = @()
    $headerRemovedCount = 0
    $headerUnknownCount = 0

    # 서버 전역 레지스트리 제거 설정(있으면 모든 사이트에 적용)
    $registryHeaderRemoved = $false
    try {
        $httpParams = "HKLM:\SYSTEM\CurrentControlSet\Services\HTTP\Parameters"
        $disableHeader = (Get-ItemProperty -Path $httpParams -Name "DisableServerHeader" -ErrorAction SilentlyContinue).DisableServerHeader
        if ($null -ne $disableHeader -and [int]$disableHeader -ge 1) {
            $registryHeaderRemoved = $true
        }
    } catch {
        $registryHeaderRemoved = $false
    }

    foreach ($site in $sites) {
        $siteName = $site.Name
        $path = $site.PhysicalPath
        $serverHeaderRemoved = $registryHeaderRemoved

        # web.config에서 제거 근거 확인 (customHeaders / requestFiltering / outboundRules)
        $webConfig = Join-Path $path "web.config"
        if (-not $serverHeaderRemoved -and (Test-Path $webConfig)) {
            [xml]$config = Get-Content $webConfig
            $systemWebServer = $config.configuration.'system.webServer'

            # 1) httpProtocol/customHeaders 에서 Server 값 제거
            $httpProtocol = $systemWebServer.httpProtocol
            if ($httpProtocol) {
                foreach ($header in $httpProtocol.customHeaders.Collection) {
                    if ($header.name -eq "Server" -and $header.value -eq "") {
                        $serverHeaderRemoved = $true
                        break
                    }
                }
            }

            # 2) security/requestFiltering @removeServerHeader="true"
            if (-not $serverHeaderRemoved) {
                $removeServerHeader = $systemWebServer.security.requestFiltering.removeServerHeader
                if ($removeServerHeader -and $removeServerHeader.ToString().ToLower() -eq "true") {
                    $serverHeaderRemoved = $true
                }
            }

            # 3) rewrite/outboundRules 의 RESPONSE_SERVER 제거 규칙
            if (-not $serverHeaderRemoved) {
                foreach ($rule in $systemWebServer.rewrite.outboundRules.rule) {
                    if ($rule.match.serverVariable -and $rule.match.serverVariable.ToString().ToUpper() -eq "RESPONSE_SERVER" -and $rule.action.value -eq "") {
                        $serverHeaderRemoved = $true
                        break
                    }
                }
            }
        }

        if ($serverHeaderRemoved) {
            $headerRemovedCount++
            $siteInfo += "Site: $siteName, Server Header: Removed"
        } else {
            # 정적 설정에서 제거 근거를 찾지 못함 => 실제 노출 여부는 응답 헤더를
            # 직접 확인해야 하므로 증명 불가(MANUAL) 상태로 분류
            $headerUnknownCount++
            $siteInfo += "Site: $siteName, Server Header: Removal not confirmed in static config (manual verification required)"
        }
    }

    # URL Rewrite 모듈 설치 확인
    $rewriteInstalled = Get-WebModule -Name "RewriteModule" -ErrorAction SilentlyContinue

    $commandExecuted = "Get-Website; Get-WebConfiguration -Filter '/system.webServer/httpProtocol/customHeaders'; Get-WebConfiguration -Filter '/system.webServer/security/requestFiltering' @removeServerHeader; Get-WebConfiguration -Filter '/system.webServer/rewrite/outboundRules'; Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\HTTP\Parameters' -Name DisableServerHeader"

    if ($headerUnknownCount -gt 0) {
        # 일부 사이트에서 정적 설정만으로 제거 여부를 단정할 수 없음 -> 수동 확인 필요
        $finalResult = "MANUAL"
        $summary = "정적 설정(customHeaders/requestFiltering/outboundRules/레지스트리)에서 Server 헤더 제거 근거를 확인하지 못한 사이트가 있습니다. HTTP 응답 헤더를 직접 확인하여 노출 여부를 판단하십시오: " + ($siteInfo -join ", ")
        $status = "수동진단"
        $commandOutput = $siteInfo -join "`n"
    } else {
        $finalResult = "GOOD"
        $summary = "모든 사이트에서 Server 헤더 정보가 제한되어 있습니다. (보안 권고사항 준수)"
        $status = "양호"
        $commandOutput = "Server Header: Removed or restricted on all sites"
    }

} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandExecuted = "Get-Website; Get-WebConfiguration -Filter '/system.webServer/httpProtocol/customHeaders'"
    $commandOutput = "진단 실패: $_"
}

# 가이드라인 변수
$purpose = 'HTTP 응답 헤더에서 웹 서버 버전 및 종류,OS 정보 등 웹 서버와 관련된 정보가 불필요하게 노출되는 것을 최소화하기 위함'
$threat = '웹 서버 및 OS 정보가 노출될 경우 공격자에 의해 해당 버전의 알려진 취약점을 이용하여 시스템 구조와 특성 노출 및 해당 취약점을 통한 공격의 위험이 존재함'
$criteria_good = 'HTTP 응답 헤더에서 웹 서버 정보가 노출되지 않는 경우'
$criteria_bad = 'HTTP 응답 헤더에서 웹 서버 정보가 노출되는 경우'
$remediation = '응답 헤더에 표시되는 정보를 최소한으로 제한하여 설정'

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
