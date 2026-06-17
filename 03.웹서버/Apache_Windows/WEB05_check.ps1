# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Version: 1.0.1
# @Last Updated: 2026-05-24
# ============================================================================
# [Assessment Item]
# @ID          : WEB-05
# @Category    : 웹서비스>2.서비스관리
# @Platform    : Apache_Windows
# @Severity    : 상
# @Title       : 지정하지 않은 CGI/ISAPI 실행 제한
# @Description : docs/guideline_metadata.json and docs guidelines must be applied before final automation.
# @Reference   : docs/guideline_metadata.json and docs guideline Markdown
# ============================================================================

#Requires -Version 5.1

$ErrorActionPreference = 'Stop'
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\..\lib"
. "${LIB_DIR}\result_manager.ps1"
. "${SCRIPT_DIR}\apache_windows_lib.ps1"

$ITEM_ID = "WEB-05"
$ITEM_NAME = "지정하지 않은 CGI/ISAPI 실행 제한"
$SEVERITY = "상"

$purpose = "CGI 스크립트를 정해진 디렉터리에서만 실행되도록하여 악의적인 파일의 업로드 및 실행을 방지하기 위함"
$threat = "게시판이나 자료실과 같이 업로드되는 파일이 저장되는 디렉터리에 CGI 스크립트가 실행 가능한 경우 악의적인 파일을 업로드하고 이를 실행하여 시스템의 중요 정보가 노출될 수 있으며 침해 사고의 경로로 이용될 위험이 존재함"
$criteria_good = "CGI 스크립트를 사용하지 않거나 CGI 스크립트가 실행 가능한 디렉터리를 제한한 경우"
$criteria_bad = "CGI 스크립트를 사용하고 CGI 스크립트가 실행 가능한 디렉터리를 제한하지 않은 경우"
$remediation = "CGI 스크립트를 정해진 디렉터리 내에서만 실행할 수 있도록 설정"

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

        $cgiModuleMatches = @([regex]::Matches($activeText, '(?im)^\s*LoadModule\s+(?:cgi|cgid)_module\b.*') | ForEach-Object { $_.Value.Trim() })
        $scriptAliasMatches = @([regex]::Matches($activeText, '(?im)^\s*ScriptAlias(?:Match)?\b.*') | ForEach-Object { $_.Value.Trim() })
        $execCgiEnabled = @([regex]::Matches($activeText, '(?im)^\s*Options\b(?=.*(?:^|\s)\+?ExecCGI(?:\s|$)).*$') | ForEach-Object { $_.Value.Trim() })
        $execCgiDisabled = @([regex]::Matches($activeText, '(?im)^\s*Options\b(?=.*(?:^|\s)-ExecCGI(?:\s|$)).*$') | ForEach-Object { $_.Value.Trim() })
        $cgiHandlerMatches = @([regex]::Matches($activeText, '(?im)^\s*(?:AddHandler|SetHandler)\b.*\bcgi-script\b.*') | ForEach-Object { $_.Value.Trim() })

        $cgiModuleMatches = @($cgiModuleMatches | Select-Object -Unique)
        $scriptAliasMatches = @($scriptAliasMatches | Select-Object -Unique)
        $execCgiEnabled = @($execCgiEnabled | Select-Object -Unique)
        $execCgiDisabled = @($execCgiDisabled | Select-Object -Unique)
        $cgiHandlerMatches = @($cgiHandlerMatches | Select-Object -Unique)

        $evidence = @(
            "Config files: $($config.Files -join ', ')",
            "CGI module directives: $($cgiModuleMatches.Count)",
            "ScriptAlias directives: $($scriptAliasMatches.Count)",
            "ExecCGI enabled directives: $($execCgiEnabled.Count)",
            "ExecCGI disabled directives: $($execCgiDisabled.Count)",
            "cgi-script handler directives: $($cgiHandlerMatches.Count)"
        )

        if ($cgiModuleMatches.Count -eq 0 -and $execCgiEnabled.Count -eq 0 -and $cgiHandlerMatches.Count -eq 0) {
            $finalResult = "GOOD"
            $status = "양호"
            $summary = "Apache CGI execution appears disabled; no active CGI module, ExecCGI, or cgi-script handler directive was found."
        }
        elseif ($execCgiEnabled.Count -gt 0 -and $scriptAliasMatches.Count -eq 0) {
            $finalResult = "VULNERABLE"
            $status = "취약"
            $summary = "Apache ExecCGI is enabled without a ScriptAlias restriction. Restrict CGI execution to designated directories or remove ExecCGI."
            $evidence += "Matched unrestricted CGI execution directives:"
            $evidence += $execCgiEnabled
            if ($cgiHandlerMatches.Count -gt 0) {
                $evidence += "Matched CGI handlers:"
                $evidence += $cgiHandlerMatches
            }
        }
        elseif ($cgiHandlerMatches.Count -gt 0 -and $scriptAliasMatches.Count -eq 0) {
            $finalResult = "VULNERABLE"
            $status = "취약"
            $summary = "Apache cgi-script handler is configured without a ScriptAlias restriction. Limit CGI execution to a designated path."
            $evidence += "Matched CGI handler directives:"
            $evidence += $cgiHandlerMatches
        }
        else {
            $finalResult = "MANUAL"
            $status = "수동진단"
            $summary = "Apache CGI may be in use with ScriptAlias present, but a flat config scan cannot prove every CGI-enabled directory is restricted (ScriptAlias is per-directory, not global). Verify all ExecCGI/cgi-script handler paths fall within ScriptAlias'd directories."
            if ($scriptAliasMatches.Count -gt 0) {
                $evidence += "Matched ScriptAlias restrictions:"
                $evidence += $scriptAliasMatches
            }
            if ($execCgiDisabled.Count -gt 0) {
                $evidence += "Matched ExecCGI disabling directives:"
                $evidence += $execCgiDisabled
            }
        }

        $commandOutput = $evidence -join "`n"
        $commandExecuted = "Parse Apache httpd.conf and included *.conf files for CGI module, ScriptAlias, ExecCGI, and cgi-script handlers"
    }
}
catch {
    $finalResult = "MANUAL"
    $status = "수동진단"
    $summary = "Diagnostic execution failed; manual review required."
    $commandOutput = "Diagnostic execution failed: $($_.Exception.Message)"
    $commandExecuted = "Apache Windows CGI execution configuration discovery"
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
