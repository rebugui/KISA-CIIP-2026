# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Version: 1.0.1
# @Last Updated: 2026-05-24
# ============================================================================
# [Assessment Item]
# @ID          : WEB-10
# @Category    : 웹서비스>2.서비스관리
# @Platform    : Apache_Windows
# @Severity    : 상
# @Title       : 불필요한 프 록 시 설정 제한
# @Description : docs/guideline_metadata.json and docs guidelines must be applied before final automation.
# @Reference   : docs/guideline_metadata.json and docs guideline Markdown
# ============================================================================

#Requires -Version 5.1

$ErrorActionPreference = 'Stop'
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\..\lib"
. "${LIB_DIR}\result_manager.ps1"
. "${SCRIPT_DIR}\apache_windows_lib.ps1"

$ITEM_ID = "WEB-10"
$ITEM_NAME = "불필요한 프 록 시 설정 제한"
$SEVERITY = "상"

$purpose = "불필요한 Proxy 설정을 제한하여 자원 낭비 예방 및 관리의 복잡성을 감소시키며, 중간자 공격 등의 해킹 공격으로부터 시스템 관련 정보가 노출되거나 악용되는 것을 방지하기 위함"
$threat = "불필요한 Proxy 설정을 제한하지 않는 경우 공격자가 Proxy 서버를 이용하여 원래 의도되지 않은 방식으로 시스템에 접근하거나 시스템 관련 정보가 유출될 위험이 존재함"
$criteria_good = "불필요한 Proxy 설정을 제한한 경우"
$criteria_bad = "불필요한 Proxy 설정을 제한하지 않은 경우"
$remediation = "불필요한 Proxy 설정 존재 여부 점검 및 제한 설정"

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

        $proxyModuleMatches = @([regex]::Matches($activeText, '(?im)^\s*LoadModule\s+proxy(?:_\w+)?_module\b.*') | ForEach-Object { $_.Value.Trim() } | Select-Object -Unique)
        $proxyRequestsOn = @([regex]::Matches($activeText, '(?im)^\s*ProxyRequests\s+On\b.*') | ForEach-Object { $_.Value.Trim() } | Select-Object -Unique)
        $proxyRequestsOff = @([regex]::Matches($activeText, '(?im)^\s*ProxyRequests\s+Off\b.*') | ForEach-Object { $_.Value.Trim() } | Select-Object -Unique)
        $reverseProxy = @([regex]::Matches($activeText, '(?im)^\s*(?:ProxyPass|ProxyPassReverse|ProxyPreserveHost)\b.*') | ForEach-Object { $_.Value.Trim() } | Select-Object -Unique)
        $proxyBlocks = @([regex]::Matches($activeText, '(?ims)<Proxy\b.*?</Proxy>') | ForEach-Object { ($_.Value -replace '\s+', ' ').Trim() } | Select-Object -Unique)

        $evidence = @(
            "Config files: $($config.Files -join ', ')",
            "Proxy module directives: $($proxyModuleMatches.Count)",
            "ProxyRequests On directives: $($proxyRequestsOn.Count)",
            "ProxyRequests Off directives: $($proxyRequestsOff.Count)",
            "Reverse proxy directives: $($reverseProxy.Count)",
            "Proxy blocks: $($proxyBlocks.Count)"
        )

        if ($proxyRequestsOn.Count -gt 0) {
            $finalResult = "VULNERABLE"
            $status = "취약"
            $summary = "Apache forward proxy is enabled with ProxyRequests On. Disable unnecessary proxy service or set ProxyRequests Off."
            $evidence += "Matched forward proxy directives:"
            $evidence += $proxyRequestsOn
        }
        elseif ($reverseProxy.Count -gt 0 -or $proxyBlocks.Count -gt 0) {
            $finalResult = "MANUAL"
            $status = "수동진단"
            $summary = "Apache proxy-related configuration exists. Forward proxy is not enabled, but verify whether reverse/proxy mappings are required by the service."
            if ($proxyRequestsOff.Count -gt 0) {
                $evidence += "Matched ProxyRequests Off directives:"
                $evidence += $proxyRequestsOff
            }
            if ($reverseProxy.Count -gt 0) {
                $evidence += "Matched reverse proxy directives:"
                $evidence += $reverseProxy
            }
            if ($proxyBlocks.Count -gt 0) {
                $evidence += "Matched Proxy blocks:"
                $evidence += $proxyBlocks
            }
        }
        else {
            $finalResult = "GOOD"
            $status = "양호"
            $summary = "No active Apache proxy directives were found."
            if ($proxyRequestsOff.Count -gt 0) {
                $evidence += "Matched ProxyRequests Off directives:"
                $evidence += $proxyRequestsOff
            }
        }

        $commandOutput = $evidence -join "`n"
        $commandExecuted = "Parse Apache httpd.conf and included *.conf files for ProxyRequests, ProxyPass, ProxyPassReverse, ProxyPreserveHost, Proxy blocks, and proxy modules"
    }
}
catch {
    $finalResult = "MANUAL"
    $status = "수동진단"
    $summary = "Diagnostic execution failed; manual review required."
    $commandOutput = "Diagnostic execution failed: $($_.Exception.Message)"
    $commandExecuted = "Apache Windows proxy configuration discovery"
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
