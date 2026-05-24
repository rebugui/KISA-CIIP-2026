# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : WEB-05
# @Category    : Web Server
# @Platform    : IIS_Windows
# @Severity    : 상
# @Title       : 지정하지 않은 CGI/ISAPI 실행 제한
# @Description : 지정하지 않은 디렉토리에서의 CGI/ISAPI 실행을 제한하여 웹쉘(Web Shell) 공격 등 악의적인 코드 실행을 방지합니다. CGI/ISAPI 프로그램의 무제한 실행은 악성 코드 업로드 및 시스템 장악으로 이어질 수 있는 심각한 보안 위협입니다.
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\..\lib"
. "${LIB_DIR}\result_manager.ps1"

$ITEM_ID = "WEB-05"
$ITEM_NAME = "지정하지 않은 CGI/ISAPI 실행 제한"
$SEVERITY = "상"

Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"

try {
    # IIS ISAPI/CGI 제한 확인
    $isapiCgiEnabled = $false
    $extensionInfo = @()

    # ISAPI 및 CGI 제한 설정 확인
    try {
        $isapiCgiRestriction = Get-WebConfiguration -Filter "/system.webServer/security/isapiCgiRestriction" -ErrorAction SilentlyContinue
        if ($isapiCgiRestriction) {
            $notAllowedExtensions = $isapiCgiRestriction.Collection | Where-Object { $_.Attributes.Allowed -eq "false" -or $_.Attributes.Allowed -eq 0 }
            $allowedExtensions = $isapiCgiRestriction.Collection | Where-Object { $_.Attributes.Allowed -eq "true" -or $_.Attributes.Allowed -eq 1 }

            if ($allowedExtensions) {
                foreach ($ext in $allowedExtensions) {
                    $extensionPath = $ext.Attributes.Path
                    $extensionInfo += "허용된 확장자: $extensionPath"
                }
                $isapiCgiEnabled = $true
            }
        }
    } catch {
        $extensionInfo += "ISAPI/CGI 제한 설정 확인 실패: $_"
    }

    # 각 사이트의 Handler Mappings 확인
    $sites = Get-Website
    foreach ($site in $sites) {
        $siteName = $site.Name

        # Handler Mappings 확인
        $handlers = Get-WebConfiguration -Filter "/system.webServer/handlers" -Location $siteName -ErrorAction SilentlyContinue
        if ($handlers) {
            $cgiHandlers = $handlers.Collection | Where-Object { $_.Name -like "*CGI*" }
            $isapiHandlers = $handlers.Collection | Where-Object { $_.Name -like "*ISAPI*" -or $_.Name -like "*isapi*" }

            if ($cgiHandlers) {
                foreach ($handler in $cgiHandlers) {
                    $isapiCgiEnabled = $true
                    $extensionInfo += "Site: $siteName, CGI Handler: $($handler.Name)"
                }
            }

            if ($isapiHandlers) {
                foreach ($handler in $isapiHandlers) {
                    $isapiCgiEnabled = $true
                    $extensionInfo += "Site: $siteName, ISAPI Handler: $($handler.Name)"
                }
            }
        }
    }

    $commandExecuted = "Get-WebConfiguration -Filter `"/system.webServer/security/isapiCgiRestriction`"; Get-WebConfiguration -Filter `"/system.webServer/handlers`""
    $commandOutput = $extensionInfo -join "`n"

    if ($isapiCgiEnabled) {
        # ISAPI/CGI가 제한된 디렉토리에서만 허용되는지 확인
        $finalResult = "MANUAL"
        $summary = "ISAPI/CGI 실행이 설정되어 있습니다. 특정 디렉토리로 제한되어 있는지 확인 필요.`n`n확인된 확장자/핸들러:`n" + ($extensionInfo -join "`n")
        $status = "수동진단"
    } else {
        $finalResult = "GOOD"
        $summary = "ISAPI/CGI 실행이 비활성화되어 있거나 제한적으로 설정되어 있습니다. (보안 권고사항 준수)"
        $status = "양호"
    }

} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandExecuted = "Get-WebConfiguration -Filter `"/system.webServer/security/isapiCgiRestriction`""
    $commandOutput = "진단 실패: $_"
}

# lib를 통한 결과 저장
$purpose = 'CGI 스크립트를 정해진 디렉터리에서만 실행되도록하여 악의적인 파일의 업로드 및 실행을 방지하기 위함'
$threat = '게시판이나 자료실과 같이 업로드되는 파일이 저장되는 디렉터리에 CGI 스크립트가 실행 가능한 경우 악의적인 파일을 업로드하고 이를 실행하여 시스템의 중요 정보가 노출될 수 있으며 침해 사고의 경로로 이용될 위험이 존재함'
$criteria_good = 'CGI 스크립트를 사용하지 않거나 CGI 스크립트가 실행 가능한 디렉터리를 제한한 경우'
$criteria_bad = 'CGI 스크립트를 사용하고 CGI 스크립트가 실행 가능한 디렉터리를 제한하지 않은 경우'
$remediation = 'CGI 스크립트를 정해진 디렉터리 내에서만 실행할 수 있도록 설정'

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
