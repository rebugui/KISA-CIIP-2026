# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : WEB-18
# @Category    : Web Server
# @Platform    : IIS (Windows Server)
# @Severity    : 중
# @Title       : 웹서비스WebDAV비활성화
# @Description : WebDAV(Web Distributed Authoring and Versioning)를 비활성화하여 파일 무단 수정, 삭제, 업로드 등 악의적인 조작을 방지합니다. WebDAV 활성화 시 인증된 사용자가 HTTP를 통해 파일을 직접 조작할 수 있어 보안 위험이 있습니다.
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\..\lib"
. "${LIB_DIR}\result_manager.ps1"

$ITEM_ID = "WEB-18"
$ITEM_NAME = "웹 서비스 WebDAV 비활성화"

Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"

try {
    # IIS WebDAV 설치 및 활성화 확인
    $sites = Get-Website
    $webdavEnabled = $false
    $siteInfo = @()

    # WebDAV 모듈 설치 확인
    $webdavInstalled = Get-WebModule -Name "WebDAVModule" -ErrorAction SilentlyContinue

    if ($webdavInstalled) {
        foreach ($site in $sites) {
            $siteName = $site.Name

            # WebDAV 설정 확인
            $webdavSettings = Get-WebConfiguration -Filter "/system.webServer/webdav/authoring" -Location $siteName -ErrorAction SilentlyContinue
            if ($webdavSettings -and $webdavSettings.Enabled -eq "true") {
                $webdavEnabled = $true
                $siteInfo += "Site: $siteName, WebDAV: Enabled"
            }
        }
    }

    $commandExecuted = "Get-WebModule -Name 'WebDAVModule'; Get-WebConfiguration -Filter '/system.webServer/webdav/authoring'"

    if ($webdavEnabled) {
        $finalResult = "VULNERABLE"
        $summary = "WebDAV가 활성화되어 있습니다: " + ($siteInfo -join ", ")
        $status = "취약"
        $commandOutput = $siteInfo -join "`n"
    } elseif ($webdavInstalled) {
        $finalResult = "GOOD"
        $summary = "WebDAV가 설치되어 있지만 비활성화되어 있습니다. (보안 권고사항 준수)"
        $status = "양호"
        $commandOutput = "WebDAV: Installed but Disabled"
    } else {
        $finalResult = "GOOD"
        $summary = "WebDAV가 설치되어 있지 않습니다. (보안 권고사항 준수)"
        $status = "양호"
        $commandOutput = "WebDAV: Not Installed"
    }

} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandExecuted = "Get-WebModule -Name 'WebDAVModule'; Get-WebConfiguration -Filter '/system.webServer/webdav/authoring'"
    $commandOutput = "진단 실패: $_"
}

# 2. lib를 통한 결과 저장
$purpose = 'WebDAV 서비스를 비활성화하여,WebDAV에서 발견되는 다수의 인증 우회 취약점을 제거하고자함'
$threat = 'WebDAV가 활성화되어 있는 경우 웹 서비스에 악의적으로 작성된 요청을 이용하여 인증을 우회함으로써 비밀번호로 보호된 WebDAV의 자원에 접근 (디렉터리 열람, 파일 다운로드 등)이 가능하며, WebDAV에 의해 호출된 일부 구성 요소에 매개 변수를 정확하게 점검하지 않는 결함이 존재하여, 이로 인해 버퍼 오버 런이 발생할 위험이 존재함'
$criteria_good = 'WebDAV 서비스를 비활성화하고 있는 경우'
$criteria_bad = 'WebDAV 서비스를 활성화하고 있는 경우'
$remediation = 'WebDAV 서비스 비활성화 설정'

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
