# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Version: 1.0.1
# @Last Updated: 2026-05-24
# ============================================================================
# [Assessment Item]
# @ID          : WEB-21
# @Category    : 웹서비스>3.보안설정
# @Platform    : Apache_Windows
# @Severity    : 중
# @Title       : HTTP 리디렉션
# @Description : docs/guideline_metadata.json and docs guidelines must be applied before final automation.
# @Reference   : docs/guideline_metadata.json and docs guideline Markdown
# ============================================================================

#Requires -Version 5.1

$ErrorActionPreference = 'Stop'
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\..\lib"
. "${LIB_DIR}\result_manager.ps1"
. "${SCRIPT_DIR}\apache_windows_lib.ps1"

$ITEM_ID = "WEB-21"
$ITEM_NAME = "HTTP 리디렉션"
$SEVERITY = "중"

$purpose = "HTTP 차단 및 HTTPS로 Redirection 활성화를 통해 평문으로 전송되는 데이터를 암호화하여 공격자의 데이터 스니 핑에 대비하기 위함"
$threat = "HTTP 통신은 암호화 전송이 아닌 평문 전송을 하므로 공격자가 스니핑을 시도할 경우 관리자의 ID, 비밀번호가 노출되어 악의적 사용자가 관리자 계정을 탈취할 수 있는 위험이 존재함"
$criteria_good = "HTTP 접근 시 HTTPSRedirection이 활성화된 경우"
$criteria_bad = "HTTP 접근 시 HTTPSRedirection이 비활성화된 경우"
$remediation = "HTTP Redirection 활성화 설정"

try {
    $services = @(Get-ApacheWindowsServices)
    $configFiles = @(Get-ApacheWindowsConfigCandidates)

    if ($services.Count -eq 0 -and $configFiles.Count -eq 0) {
        $finalResult = "N/A"
        $status = "N/A"
        $summary = "Apache for Windows service/configuration was not found."
        $commandOutput = "No Apache service or known httpd.conf path found."
        $commandExecuted = "Get-CimInstance Win32_Service; known Apache httpd.conf paths"
    }
    elseif ($configFiles.Count -eq 0) {
        $finalResult = "MANUAL"
        $status = "수동진단"
        $summary = "Apache service exists, but configuration files were not found for HTTP redirect inspection."
        $commandOutput = ($services | ForEach-Object { "$($_.Name) [$($_.State)] $($_.PathName)" }) -join "`n"
        $commandExecuted = "Get-CimInstance Win32_Service; known Apache httpd.conf paths"
    }
    else {
        $config = Get-ApacheWindowsConfigText -ConfigFiles $configFiles
        $activeLines = @($config.Text -split "`r?`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ -and $_ -notmatch '^#' })
        $httpListeners = @($activeLines | Where-Object { $_ -match '^(?i)(Listen\s+(?:0\.0\.0\.0:|\*:)?80\b|<VirtualHost\s+[^>]*:80\b)' })
        # Only an actual HTTP->HTTPS redirect counts as evidence. HSTS
        # (Strict-Transport-Security) does NOT redirect a plain HTTP request
        # from a new client over port 80, so it is intentionally excluded.
        $redirectRules = @($activeLines | Where-Object {
            $_ -match '^(?i)Redirect(?:Match)?\s+(?:permanent\s+|301\s+|seeother\s+|temp\s+|302\s+)?\S*\s+https://' -or
            $_ -match '^(?i)RewriteRule\s+.+\s+https://'
        })
        $hstsHeaders = @($activeLines | Where-Object { $_ -match '^(?i)Header\s+always\s+set\s+Strict-Transport-Security\b' })
        $rewriteEnabled = @($activeLines | Where-Object { $_ -match '^(?i)RewriteEngine\s+On\b' })
        $hasRedirectDirective = @($redirectRules | Where-Object { $_ -match '^(?i)Redirect' }).Count -gt 0
        $hasRewriteRedirect = @($redirectRules | Where-Object { $_ -match '^(?i)RewriteRule' }).Count -gt 0

        $commandExecuted = "Parse Apache Windows Listen/VirtualHost and HTTPS redirect directives"
        $commandOutput = (@(
            if ($httpListeners) { "HTTP listeners:`n" + ($httpListeners -join "`n") }
            if ($rewriteEnabled) { "Rewrite enabled:`n" + ($rewriteEnabled -join "`n") }
            if ($redirectRules) { "Redirect evidence:`n" + ($redirectRules -join "`n") }
            if ($hstsHeaders) { "HSTS header (not a redirect):`n" + ($hstsHeaders -join "`n") }
            if (-not $httpListeners -and -not $redirectRules) { "No HTTP listener or HTTPS redirect evidence found." }
        ) -join "`n`n")

        # GOOD requires a real redirect: a Redirect/RedirectMatch to https://,
        # or a RewriteRule to https:// backed by RewriteEngine On.
        if ($hasRedirectDirective -or ($hasRewriteRedirect -and $rewriteEnabled.Count -gt 0)) {
            $finalResult = "GOOD"
            $status = "양호"
            $summary = "HTTP-to-HTTPS redirection was found in Apache configuration."
        }
        elseif ($httpListeners.Count -gt 0) {
            $finalResult = "VULNERABLE"
            $status = "취약"
            if ($hstsHeaders.Count -gt 0) {
                $summary = "HTTP listener found with HSTS only and no HTTP-to-HTTPS redirect. HSTS does not redirect plain HTTP requests from new clients; configure a Redirect or RewriteRule to https://."
            }
            else {
                $summary = "HTTP listener evidence was found without HTTPS redirection evidence."
            }
        }
        else {
            $finalResult = "MANUAL"
            $status = "수동진단"
            $summary = "No port 80 listener was found in static configuration; confirm active virtual hosts and upstream redirect policy."
        }
    }
}
catch {
    $finalResult = "MANUAL"
    $status = "수동진단"
    $summary = "Diagnostic execution failed; manual review required."
    $commandOutput = "Diagnostic execution failed: $($_.Exception.Message)"
    $commandExecuted = "Apache Windows HTTP redirect configuration discovery"
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

exit 0
