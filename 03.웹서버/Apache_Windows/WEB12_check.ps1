# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Version: 1.0.1
# @Last Updated: 2026-05-24
# ============================================================================
# [Assessment Item]
# @ID          : WEB-12
# @Category    : 웹서비스>2.서비스관리
# @Platform    : Apache_Windows
# @Severity    : 중
# @Title       : 웹 서비스 링크 사용 금지
# @Description : docs/guideline_metadata.json and docs guidelines must be applied before final automation.
# @Reference   : docs/guideline_metadata.json and docs guideline Markdown
# ============================================================================

#Requires -Version 5.1

$ErrorActionPreference = 'Stop'
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\..\lib"
. "${LIB_DIR}\result_manager.ps1"
. "${SCRIPT_DIR}\apache_windows_lib.ps1"

$ITEM_ID = "WEB-12"
$ITEM_NAME = "웹 서비스 링크 사용 금지"
$SEVERITY = "중"

$purpose = "무분별한 심볼 릭 링크, 별칭(aliases) 등을 제거하여 허용하지 않은 경로에서의 접근을 차단해 경로 검증을 우회한 시스템 파일 접근을 방지하기 위함"
$threat = "보안상 민감한 내용이 포함되어 있는 파일이 악의적인 사용자에게 노출될 경우 침해 사고로 이어질 위험이 존재함 접근을 허용한 웹 디렉터리 내에 서버의 다른 디렉터리나 파일들에 접근할 수 있는 심볼 릭 링크, aliases, 바로가기 등이 존재하는 경우 해당 링크를 통해 허용하지 않은 다른 디렉터리에 액세스할 수 있는 위험이 존재함"
$criteria_good = "심볼 릭 링크,aliases, 바로가기 등의 링크 사용을 허용하지 않는 경우"
$criteria_bad = "심볼 릭 링크,aliases, 바로가기 등의 링크 사용을 허용하는 경우"
$remediation = "웹 서비스 링크 사용 제한 설정"

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

        $followEnabled = @([regex]::Matches($activeText, '(?im)^\s*Options\b(?=.*(?:^|\s)\+?FollowSymLinks(?:\s|$)).*$') | ForEach-Object { $_.Value.Trim() } | Select-Object -Unique)
        $followDisabled = @([regex]::Matches($activeText, '(?im)^\s*Options\b(?=.*(?:^|\s)-FollowSymLinks(?:\s|$)).*$') | ForEach-Object { $_.Value.Trim() } | Select-Object -Unique)
        $ownerMatch = @([regex]::Matches($activeText, '(?im)^\s*Options\b(?=.*(?:^|\s)\+?SymLinksIfOwnerMatch(?:\s|$)).*$') | ForEach-Object { $_.Value.Trim() } | Select-Object -Unique)
        $aliasDirectives = @([regex]::Matches($activeText, '(?im)^\s*(?:Alias|AliasMatch)\b.*') | ForEach-Object { $_.Value.Trim() } | Select-Object -Unique)

        $evidence = @(
            "Config files: $($config.Files -join ', ')",
            "FollowSymLinks enabled directives: $($followEnabled.Count)",
            "FollowSymLinks disabled directives: $($followDisabled.Count)",
            "SymLinksIfOwnerMatch directives: $($ownerMatch.Count)",
            "Alias directives: $($aliasDirectives.Count)"
        )

        if ($followEnabled.Count -gt 0 -and $followDisabled.Count -eq 0) {
            $finalResult = "VULNERABLE"
            $status = "취약"
            $summary = "Apache allows symbolic link traversal with Options FollowSymLinks. Remove FollowSymLinks or set -FollowSymLinks."
            $evidence += "Matched FollowSymLinks directives:"
            $evidence += $followEnabled
        }
        elseif ($followEnabled.Count -gt 0 -and $followDisabled.Count -gt 0) {
            $finalResult = "MANUAL"
            $status = "수동진단"
            $summary = "Both FollowSymLinks and -FollowSymLinks are present. Verify effective Directory scope order manually."
            $evidence += "Matched FollowSymLinks directives:"
            $evidence += $followEnabled
            $evidence += "Matched disabling directives:"
            $evidence += $followDisabled
        }
        else {
            $finalResult = "GOOD"
            $status = "양호"
            if ($followDisabled.Count -gt 0 -or $ownerMatch.Count -gt 0) {
                $summary = "Apache symbolic link usage is restricted with -FollowSymLinks or SymLinksIfOwnerMatch."
                $evidence += "Matched link restriction directives:"
                $evidence += $followDisabled
                $evidence += $ownerMatch
            }
            else {
                $summary = "No active Options FollowSymLinks directive was found."
            }
        }

        if ($aliasDirectives.Count -gt 0) {
            $evidence += "Alias directives requiring business review:"
            $evidence += $aliasDirectives
        }

        $commandOutput = $evidence -join "`n"
        $commandExecuted = "Parse Apache httpd.conf and included *.conf files for Options FollowSymLinks, -FollowSymLinks, SymLinksIfOwnerMatch, and Alias directives"
    }
}
catch {
    $finalResult = "MANUAL"
    $status = "수동진단"
    $summary = "Diagnostic execution failed; manual review required."
    $commandOutput = "Diagnostic execution failed: $($_.Exception.Message)"
    $commandExecuted = "Apache Windows symbolic link configuration discovery"
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
