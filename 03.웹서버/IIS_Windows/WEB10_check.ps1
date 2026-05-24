# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : WEB-10
# @Category    : Web Server
# @Platform    : IIS (Windows Server)
# @Severity    : 상
# @Title       : 불필요한프록시설정제한
# @Description : 불필요한 프록시 설정(Reverse Proxy, Application Request Routing)을 제한하여 내부 네트워크 정보 노출 및 무단 접근을 방지합니다. 프록시가 활성화되면 공격자가 내부망 정보를 획득하거나 프록시 서버를 악용할 수 있는 보안 위협이 있습니다.
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\..\lib"
. "${LIB_DIR}\result_manager.ps1"

$ITEM_ID = "WEB-10"
$ITEM_NAME = "불필요한 프 록 시 설정 제한"
$SEVERITY = "상"

Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"

try {
    # IIS Reverse Proxy 설정 확인 (Application Request Routing)
    $proxyEnabled = $false
    $proxyInfo = @()

    # ARR 모듈 설치 확인
    $arrInstalled = Get-WebModule -Name "ApplicationRequestRouting" -ErrorAction SilentlyContinue

    if ($arrInstalled) {
        # Proxy 규칙 확인
        $sites = Get-Website
        foreach ($site in $sites) {
            $rewriteRules = Get-WebConfiguration -Filter "/system.webServer/rewrite/rules" -Location $site.Name
            if ($rewriteRules) {
                foreach ($rule in $rewriteRules.Collection) {
                    $action = $rule.action
                    if ($action.type -eq "Rewrite" -and $action.url -like "http*") {
                        $proxyEnabled = $true
                        $proxyInfo += "Site: $($site.Name), Rule: $($rule.name), URL: $($action.url)"
                    }
                }
            }
        }
    }

    $commandExecuted = "Get-WebModule -Name 'ApplicationRequestRouting'; Get-WebConfiguration -Filter '/system.webServer/rewrite/rules'"

    if ($proxyEnabled) {
        $finalResult = "MANUAL"
        $summary = "Reverse Proxy 설정이 발견되었습니다: " + ($proxyInfo -join ", ") + " - 필요한 proxy인지 수동 확인 필요."
        $status = "수동진단"
        $commandOutput = $proxyInfo -join "`n"
    } else {
        $finalResult = "GOOD"
        $summary = "불필요한 프록시 설정이 발견되지 않았습니다. (보안 권고사항 준수)"
        $status = "양호"
        $commandOutput = "Proxy: Not configured"
    }

} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandExecuted = "Get-WebModule -Name 'ApplicationRequestRouting'; Get-WebConfiguration -Filter '/system.webServer/rewrite/rules'"
    $commandOutput = "진단 실패: $_"
}

# 가이드라인 변수
$purpose = '불필요한 Proxy 설정을 제한하여 자원 낭비 예방 및 관리의 복잡성을 감소시키며, 중간자 공격 등의 해킹 공격으로부터 시스템 관련 정보가 노출되거나 악용되는 것을 방지하기 위함'
$threat = '불필요한 Proxy 설정을 제한하지 않는 경우 공격자가 Proxy 서버를 이용하여 원래 의도되지 않은 방식으로 시스템에 접근하거나 시스템 관련 정보가 유출될 위험이 존재함'
$criteria_good = '불필요한 Proxy 설정을 제한한 경우'
$criteria_bad = '불필요한 Proxy 설정을 제한하지 않은 경우'
$remediation = '불필요한 Proxy 설정 존재 여부 점검 및 제한 설정'

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
