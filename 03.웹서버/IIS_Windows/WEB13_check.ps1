# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : WEB-13
# @Category    : Web Server
# @Platform    : IIS_Windows
# @Severity    : 상
# @Title       : 웹 서비스 설정 파일 노출 제한
# @Description : 웹 서버의 디렉터리 리스팅(Directory Listing) 기능을 제거하여 웹 서버 디렉터리 정보 노출을 방지합니다. 이 항목은 WEB-04와 동일한 내용을 다루지만 제거를 강조합니다.
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\..\lib"
. "${LIB_DIR}\result_manager.ps1"

$ITEM_ID = "WEB-13"
$ITEM_NAME = "웹 서비스 설정 파일 노출 제한"
$SEVERITY = "상"

Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"

try {
    # IIS 디렉터리 리스팅 제거 확인 (WEB-04와 동일하지만 다름을 강조)
    $sites = Get-Website
    $dirListingEnabled = $false
    $siteInfo = @()

    foreach ($site in $sites) {
        $siteName = $site.Name
        $path = $site.PhysicalPath

        $webConfig = Join-Path $path "web.config"
        if (Test-Path $webConfig) {
            [xml]$config = Get-Content $webConfig
            $dirBrowse = $config.configuration.'system.webServer'.directoryBrowse
            if ($dirBrowse -and $dirBrowse.enabled -eq "true") {
                $dirListingEnabled = $true
                $siteInfo += "Site: $siteName, DirectoryBrowse: Enabled"
            }
        }

        $iisConfig = Get-WebConfiguration -Filter "/system.webServer/directoryBrowse" -Location $siteName
        if ($iisConfig -and $iisConfig.Attributes.value.enabled -eq "true") {
            $dirListingEnabled = $true
            $siteInfo += "Site: $siteName, IIS Config: Enabled"
        }
    }

    $commandExecuted = "Get-Website; Get-WebConfiguration -Filter `"/system.webServer/directoryBrowse`""

    if ($dirListingEnabled) {
        $finalResult = "VULNERABLE"
        $summary = "디렉터리 리스팅이 활성화되어 있습니다. 제거 필요: " + ($siteInfo -join ", ")
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

# 가이드라인 변수
$purpose = '웹 서비스에서 DB 연결 파일에 대한 접근 권한 제한 및 불필요한 스크립트 매핑을 제거하여, DB 연결 정보(사용자 이름, 비밀번호 등)가 외부에 노출되거나 공격자의 DB 접근 및 관리자 권한 획득 등의 다양한 공격을 방지하기 위함'
$threat = '웹 서비스에서 DB 연결 파일에 대한 접근 권한 제한 및 불필요한 스크립트 매핑을 제거하지 않을 경우, DB 연결 파일에 존재하는 데이터 베이스 관련 정보(IP 주소, DB 명, 비밀번호), 서버 내부 IP 주소, 웹 서비스 환경 설정 정보 등 보안상 민감한 내용이 악의적인 사용자에게 노출될 위험이 존재함'
$criteria_good = '일반 사용자의 DB 연결 파일에 대한 접근을 제한하고, 불필요한 스크립트 매핑이 제거된 경우'
$criteria_bad = '일반 사용자의 DB 연결 파일에 대한 접근을 제한하지 않거나, 불필요한 스크립트 매핑이 제거되지 않은 경우'
$remediation = 'DB 연결 파일에 대한 접근 권한 제한 또는 불필요한 스크립트 매핑 제거 등을 통한 웹 서비스 내 DB 연결 취약점 제거 설정'

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
