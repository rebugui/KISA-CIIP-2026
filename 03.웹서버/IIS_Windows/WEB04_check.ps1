
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : WEB-04
# @Category    : Web Server
# @Platform    : IIS_Windows
# @Severity    : 상
# @Title       : 웹 서비스 디렉터리 리 스팅 방지 설정
# @Description : 웹 서버의 디렉터리 리스팅(Directory Listing) 기능을 비활성화하여 중요 파일 및 디렉터리 구조 정보 노출을 방지합니다. 디렉터리 리스팅이 활성화되면 공격자가 웹 서버의 파일 구조를 쉽게 파악할 수 있어 보안 위협이 증가합니다.
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\..\lib"
. "${LIB_DIR}\result_manager.ps1"

$ITEM_ID = "WEB-04"
$ITEM_NAME = "웹 서비스 디렉터리 리 스팅 방지 설정"
$SEVERITY = "상"

Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"

try {
    # IIS Directory Listing 확인
    $sites = Get-Website
    $dirListingEnabled = $false
    $siteInfo = @()

    foreach ($site in $sites) {
        $siteName = $site.Name
        $path = $site.PhysicalPath

        # web.config에서 directoryBrowse 확인
        $webConfig = Join-Path $path "web.config"
        if (Test-Path $webConfig) {
            [xml]$config = Get-Content $webConfig
            $dirBrowse = $config.configuration.'system.webServer'.directoryBrowse
            if ($dirBrowse -and $dirBrowse.enabled -eq "true") {
                $dirListingEnabled = $true
                $siteInfo += "Site: $siteName, DirectoryBrowse: Enabled"
            }
        }

        # IIS 구성에서도 확인 (applicationHost.config/서버 노드의 상속된 유효 설정 포함)
        # Get-WebConfiguration 은 상속 병합된 유효값을 반환하므로 enabled 속성을 직접 읽는다.
        # 기존 .Attributes.value.enabled 경로는 ConfigurationAttributeCollection 을
        # member-enumerate 하여 항상 $null 이 되는 죽은 코드였다 → 서버 노드에서 디렉터리
        # 검색을 켠 경우(IIS 관리자 > 디렉터리 검색 > 사용)를 탐지하지 못했다.
        $iisConfig = Get-WebConfiguration -Filter "/system.webServer/directoryBrowse" -Location $siteName
        if ($iisConfig) {
            $iisEnabled = $iisConfig.enabled
            if ($null -eq $iisEnabled -and $iisConfig.Attributes) {
                try { $iisEnabled = $iisConfig.Attributes['enabled'].Value } catch { $iisEnabled = $null }
            }
            if ("$iisEnabled" -eq "true" -or $iisEnabled -eq $true) {
                $dirListingEnabled = $true
                $siteInfo += "Site: $siteName, IIS Config: Enabled"
            }
        }
    }

    $commandExecuted = "Get-Website; Get-WebConfiguration -Filter `"/system.webServer/directoryBrowse`""

    if ($dirListingEnabled) {
        $finalResult = "VULNERABLE"
        $summary = "디렉터리 리스팅이 활성화되어 있는 웹사이트가 있습니다: " + ($siteInfo -join ", ")
        $status = "취약"
        $commandOutput = $siteInfo -join "`n"
    } else {
        $finalResult = "GOOD"
        $summary = "모든 웹사이트에서 디렉터리 리스팅이 비활성화되어 있습니다. (보안 권고사항 준수)"
        $status = "양호"
        $commandOutput = "DirectoryBrowse: Disabled on all sites"
    }

} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandExecuted = "Get-Website; Get-WebConfiguration -Filter `"/system.webServer/directoryBrowse`""
    $commandOutput = "진단 실패: $_"
}

# 2. lib를 통한 결과 저장
$purpose = '웹 서버에 대한 디렉터리 리스 팅 기능을 차단하여 디렉터리 내의 모든 파일에 대한 접근 및 정보 노출을 차단하기 위함'
$threat = '디렉터리 리스 팅 기능이 차단되지 않은 경우, 비인가자가 해당 디렉터리 내의 모든 파일의 리스트 확인 및 접근이 가능하고, 웹 서버의 구조 및 백업 파일이나 소스 파일 등 공개되면 안 되는 중요 파일들이 노출될 위험이 존재함'
$criteria_good = '디렉터리 리스팅이 설정되지 않은 경우'
$criteria_bad = '디렉터리 리스팅이 설정된 경우'
$remediation = '디렉터리 리스팅 기능 차단 설정'

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
