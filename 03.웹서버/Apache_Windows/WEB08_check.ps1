# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Version: 1.0.1
# @Last Updated: 2026-05-24
# ============================================================================
# [Assessment Item]
# @ID          : WEB-08
# @Category    : 웹서비스>2.서비스관리
# @Platform    : Apache_Windows
# @Severity    : 하
# @Title       : 웹 서비스 파일 업로드 및 다운로드 용량 제한
# @Description : docs/guideline_metadata.json and docs guidelines must be applied before final automation.
# @Reference   : docs/guideline_metadata.json and docs guideline Markdown
# ============================================================================

#Requires -Version 5.1

$ErrorActionPreference = 'Stop'
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\..\lib"
. "${LIB_DIR}\result_manager.ps1"
. "${SCRIPT_DIR}\apache_windows_lib.ps1"

$ITEM_ID = "WEB-08"
$ITEM_NAME = "웹 서비스 파일 업로드 및 다운로드 용량 제한"
$SEVERITY = "하"

$purpose = "기반 시설 시스템은 원칙적으로 파일 업로드 및 다운로드를 금지하지만 불가피하게 파일의 업로드 및 다운로드 기능이 필요한 경우, 파일의 용량 제한을 설정하여 불필요한 업로드 및 다운로드를 방지해 서버의 과부하를 예방하고, 웹 서버 자원을 효율적으로 관리하기 위함"
$threat = "웹 서비스의 파일 업로드 및 다운로드의 용량을 제한하지 않은 경우, 악의적인 목적을 가진 사용자가 반복 업로드 및 웹 쉘 공격 등으로 시스템 권한을 탈취하거나 대용량 파일의 업로드 및 다운로드로 서버 자원을 고갈시켜 서비스 장애를 발생시킬 위험이 존재함"
$criteria_good = "파일 업로드 및 다운로드 용량을 제한한 경우"
$criteria_bad = "파일 업로드 및 다운로드 용량을 제한하지 않은 경우"
$remediation = "파일 업로드 및 다운로드 용량을 허용 가능한 최소 범위로 제한하여 설정"

try {
    $services = @(Get-ApacheWindowsServices)
    $configCandidates = @(Get-ApacheWindowsConfigCandidates)

    if ($services.Count -eq 0 -and $configCandidates.Count -eq 0) {
        $finalResult = "N/A"
        $status = "N/A"
        $summary = "Apache for Windows service/configuration was not found."
        $commandOutput = "No Apache service or known httpd.conf path found."
        $commandExecuted = "Get-CimInstance Win32_Service; known Apache httpd.conf paths"
    }
    elseif ($configCandidates.Count -eq 0) {
        $finalResult = "MANUAL"
        $status = "수동진단"
        $summary = "Apache service was found, but httpd.conf could not be located automatically."
        $commandOutput = ($services | Select-Object Name, DisplayName, State, PathName | Format-List | Out-String).Trim()
        $commandExecuted = "Get-CimInstance Win32_Service | Where-Object Name/DisplayName matches Apache/httpd"
    }
    else {
        $config = Get-ApacheWindowsConfigText -ConfigFiles $configCandidates
        $activeLines = @($config.Text -split "`r?`n" | Where-Object { $_.Trim() -notmatch '^#' })
        $activeText = $activeLines -join "`n"

        $limitMatches = @([regex]::Matches($activeText, '(?im)^\s*LimitRequestBody\s+(\d+)\b.*') | ForEach-Object {
            [pscustomobject]@{
                Line = $_.Value.Trim()
                Value = [int64]$_.Groups[1].Value
            }
        })

        $limited = @($limitMatches | Where-Object { $_.Value -gt 0 })
        $unlimited = @($limitMatches | Where-Object { $_.Value -eq 0 })
        $evidence = @(
            "Config files: $($config.Files -join ', ')",
            "LimitRequestBody directives: $($limitMatches.Count)",
            "Positive limits: $($limited.Count)",
            "Unlimited values: $($unlimited.Count)"
        )

        if ($unlimited.Count -gt 0) {
            $finalResult = "VULNERABLE"
            $status = "취약"
            $summary = "Apache LimitRequestBody is set to 0, which does not enforce an upload/download request body limit."
            $evidence += "Matched unlimited directives:"
            $evidence += @($unlimited | ForEach-Object { $_.Line } | Select-Object -Unique)
        }
        elseif ($limited.Count -gt 0) {
            $finalResult = "GOOD"
            $status = "양호"
            $summary = "Apache request body size is limited with LimitRequestBody."
            $evidence += "Matched limiting directives:"
            $evidence += @($limited | ForEach-Object { $_.Line } | Select-Object -Unique)
        }
        else {
            $finalResult = "VULNERABLE"
            $status = "취약"
            $summary = "Apache LimitRequestBody was not found. Configure a minimum acceptable file upload/download size limit."
            $evidence += "No active LimitRequestBody directive found."
        }

        $commandOutput = $evidence -join "`n"
        $commandExecuted = "Parse Apache httpd.conf and included *.conf files for LimitRequestBody"
    }
}
catch {
    $finalResult = "MANUAL"
    $status = "수동진단"
    $summary = "Diagnostic execution failed; manual review required."
    $commandOutput = "Diagnostic execution failed: $($_.Exception.Message)"
    $commandExecuted = "Apache Windows request body size limit discovery"
}

$resultParams = @{
    ItemId = $ITEM_ID
    ItemName = $ITEM_NAME
    Status = $status
    FinalResult = $finalResult
    InspectionSummary = $summary
    CommandResult = $commandOutput
    CommandExecuted = $commandExecuted
    GuidelinePurpose = $purpose
    GuidelineThreat = $threat
    GuidelineCriteriaGood = $criteria_good
    GuidelineCriteriaBad = $criteria_bad
    GuidelineRemediation = $remediation
    ScriptDir = $SCRIPT_DIR
}

Save-DualResult @resultParams

if (-not (Test-RunallMode)) {
    Write-Host ""
    Write-Host "Diagnostic complete: $ITEM_ID ($finalResult)"
}

exit 0
