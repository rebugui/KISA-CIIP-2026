# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : WEB-20
# @Category    : Web Server
# @Platform    : IIS_Windows
# @Severity    : 상
# @Title       : SSL/TLS 활성화
# @Description : 웹 서비스에 SSL/TLS(HTTPS)를 활성화하여 통신 데이터를 암호화하고 중간자 공격(Man-in-the-Middle)을 방지합니다. SSL/TLS 미사용 시 평문 통화으로 인한 정보 탈취 및 도청 위험이 있습니다.
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\..\lib"
. "${LIB_DIR}\result_manager.ps1"

$ITEM_ID = "WEB-20"
$ITEM_NAME = "SSL/TLS 활성화"

Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"

try {
    # IIS SSL/TLS 바인딩 확인
    $sites = Get-Website
    $sitesWithoutSSL = @()
    $sitesWithSSL = @()

    foreach ($site in $sites) {
        $siteName = $site.Name
        $bindings = Get-WebBinding -Name $siteName

        $hasHTTPS = $false
        foreach ($binding in $bindings) {
            if ($binding.Protocol -eq "https") {
                $hasHTTPS = $true
                $sitesWithSSL += "Site: $siteName, Port: $($binding.port), Certificate: Present"
                break
            }
        }

        if (-not $hasHTTPS) {
            $sitesWithoutSSL += "Site: $siteName, SSL: Not configured"
        }
    }

    $commandExecuted = "Get-Website; Get-WebBinding -Name [SiteName]"

    if ($sitesWithoutSSL.Count -gt 0) {
        $finalResult = "VULNERABLE"
        $summary = "SSL/TLS가 구성되지 않은 웹사이트가 있습니다: " + ($sitesWithoutSSL -join ", ")
        $status = "취약"
        $commandOutput = ($sitesWithSSL + $sitesWithoutSSL) -join "`n"
    } else {
        $finalResult = "GOOD"
        $summary = "모든 웹사이트에 SSL/TLS가 구성되어 있습니다. (보안 권고사항 준수)"
        $status = "양호"
        $commandOutput = $sitesWithSSL -join "`n"
    }

} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandExecuted = "Get-Website; Get-WebBinding -Name [SiteName]"
    $commandOutput = "진단 실패: $_"
}

# 2. lib를 통한 결과 저장
$purpose = '서버와 클라이언트 간 통신 시 데이터의 평 문 전송을 사용하지 않고 데이터가 암호화되는 SSL/TLS 인증 암호화 접속을 통해 스니 핑을 통한 정보 유출의 위험을 방지하기 위함'
$threat = '웹상의 데이터 통신 시 서버와 클라이언트 간에 데이터를 평 문 전송하는 경우, 간단한 도청(스니핑)을 통해 정보가 탈취 및 도용될 위험이 존재함 SSL/TLS가 활성화되어 있지 않을 경우, 데이터는 암호화되지 않아 공격자가 중간에서 데이터를 가로채거나 도청할 수 있으며, 더 나아가 평 문으로 전송되어 중간에서 변경될 우려가 있어 데이터의 정확성이 훼손될 위험이 존재함'
$criteria_good = 'SSL/TLS 설정이 활성화되어 있는 경우'
$criteria_bad = 'SSL/TLS 설정이 비활성화되어 있는 경우'
$remediation = '웹 서비스 내 SSL/TLS 활성화 설정'

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
