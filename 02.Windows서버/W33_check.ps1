# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : W-33
# @Category    : Windows Server
# @Platform    : Windows Server
# @Severity    : 하
# @Title       : HTTP/FTP/SMTP 배너차단
# @Description : HTTP/FTP/SMTP 서비스 배너 정보 노출 차단으로 불필요한 정보 유출 방지
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# Parameters
$ITEM_ID = "W-33"
$ITEM_NAME = "HTTP/FTP/SMTP 배너차단"
$SEVERITY = "하"
$CATEGORY = "2.서비스관리"

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\lib"
. "${LIB_DIR}\result_manager.ps1"

# run_all 모드가 아닐 때만 진단 정보 출력
if (-not (Test-RunallMode)) {
    Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"
    Write-Host "카테고리: $CATEGORY"
    Write-Host ""
}

# Diagnostic Logic
try {
    $ErrorActionPreference = 'SilentlyContinue'
    $iisInstalled = Get-WindowsFeature -Name Web-Server -ErrorAction SilentlyContinue

    if ($iisInstalled -and $iisInstalled.InstallState -eq 'Installed') {
        $bannerFindings = @()
        $manualNotes = @()

        # --- HTTP: Server 응답 헤더 존재 여부 ---
        # 주의: customHeaders에 'Server' 항목이 명시되어 있으면 배너가 노출되는 것으로 본다.
        # (URL Rewrite 아웃바운드 규칙을 통한 제거는 이 컬렉션으로 확인되지 않으므로 별도 안내.)
        $httpBanner = Get-WebConfigurationProperty -Filter 'system.webServer/httpProtocol' -Name 'customHeaders' -ErrorAction SilentlyContinue
        $httpServerHeaderDeclared = $false
        if ($httpBanner) {
            foreach ($header in $httpBanner.Collection) {
                if ($header.Name -eq 'Server') {
                    $httpServerHeaderDeclared = $true
                }
            }
        }
        if ($httpServerHeaderDeclared) {
            $bannerFindings += "HTTP: Server response header is present"
        }

        # --- FTP: 설치 시 기본 배너 노출 여부는 자동 단정 불가 → MANUAL로 라우팅 ---
        # (이전 버그: 이 분기에서 $bannerFound를 무조건 $false로 재할당하여 HTTP 탐지 결과를 지웠음)
        $ftpInstalled = Get-WindowsFeature -Name Web-Ftp-Server -ErrorAction SilentlyContinue
        if ($ftpInstalled -and $ftpInstalled.InstallState -eq 'Installed') {
            $manualNotes += "FTP service installed; FTP banner exposure requires manual verification"
        }

        # --- SMTP: connectresponse 배너는 IIS6 메타베이스(adsutil)로만 확인 가능 → MANUAL로 라우팅 ---
        $smtpFeature = Get-WindowsFeature -Name SMTP-Server -ErrorAction SilentlyContinue
        $smtpService = Get-Service -Name 'SMTPSVC' -ErrorAction SilentlyContinue
        if (($smtpFeature -and $smtpFeature.InstallState -eq 'Installed') -or $smtpService) {
            $manualNotes += "SMTP service present; SMTP connectresponse banner requires manual verification"
        }

        if ($bannerFindings.Count -gt 0) {
            # 배너 노출이 확인된 경우 취약 (다른 항목의 수동 확인 필요 여부와 무관하게 우선).
            $finalResult = "VULNERABLE"
            $status = "취약"
            $summary = "HTTP/FTP/SMTP 서비스 배너 정보가 노출됨"
            $commandOutput = ($bannerFindings -join '; ')
            if ($manualNotes.Count -gt 0) { $commandOutput += "; (also: " + ($manualNotes -join '; ') + ")" }
        } elseif ($manualNotes.Count -gt 0) {
            # HTTP 배너는 미탐지지만 FTP/SMTP 배너를 자동 단정할 수 없으면 GOOD으로 단정하지 않는다.
            $finalResult = "MANUAL"
            $status = "수동진단"
            $summary = "HTTP 배너는 미탐지이나 FTP/SMTP 배너 노출 여부를 자동으로 확인할 수 없어 수동 확인 필요"
            $commandOutput = ($manualNotes -join '; ')
        } else {
            $finalResult = "GOOD"
            $status = "양호"
            $summary = "HTTP/FTP/SMTP 서비스 배너 정보가 차단됨"
            $commandOutput = "No Server response header declared; FTP/SMTP not installed"
        }

        $commandExecuted = "Get-WindowsFeature Web-Server,Web-Ftp-Server,SMTP-Server; Get-WebConfigurationProperty system.webServer/httpProtocol; Get-Service SMTPSVC"
    } else {
        $finalResult = "GOOD"
        $status = "양호"
        $summary = "IIS/FTP/SMTP 서비스가 설치되어 있지 않아 배너 노출 위험 없음"
        $commandExecuted = "Get-WindowsFeature -Name Web-Server"
        $commandOutput = "IIS/FTP/SMTP services not installed"
    }

} catch {
    $finalResult = "MANUAL"
    $status = "수동진단"
    $summary = "진단 실패: 수동 확인 필요"
    $commandExecuted = "Get-WindowsFeature -Name Web-Server; Get-WebConfigurationProperty -Filter 'system.webServer/httpProtocol'"
    $commandOutput = "진단 실패: $_"
}

# Define guideline variables
$purpose = "HTTP/FTP/SMTP 서비스 접속 배너를 통한 불필요한 정보 노출을 방지하기 위함"
$threat = "서비스 접속 배너가 차단되지 않는 경우 임의의 사용자가 HTTP, FTP, SMTP 접속 시도 시 노출되는 접속 배너 정보를 수집하여 악의적인 공격에 이용할 위험이 존재함"
$criteria_good = "HTTP,FTP,SMTP 접속 시 배너 정보가 보이지 않는 경우"
$criteria_bad = "HTTP,FTP,SMTP 접속 시 배너 정보가 보이는 경우"
$remediation = "사용하지 않는 경우 IIS 서비스 중지/ 사용 안 함, 사용 시 속성 값 수정"

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
