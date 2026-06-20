# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Version: 1.0.1
# @Last Updated: 2026-05-24
# ============================================================================
# [Assessment Item]
# @ID          : WEB-06
# @Category    : 웹서비스>2.서비스관리
# @Platform    : Apache_Windows
# @Severity    : 상
# @Title       : 웹 서비스 상위 디렉터리 접근 제한 설정
# @Description : docs/guideline_metadata.json and docs guidelines must be applied before final automation.
# @Reference   : docs/guideline_metadata.json and docs guideline Markdown
# ============================================================================

#Requires -Version 5.1

$ErrorActionPreference = 'Stop'
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\..\lib"
. "${LIB_DIR}\result_manager.ps1"
. "${SCRIPT_DIR}\apache_windows_lib.ps1"

$ITEM_ID = "WEB-06"
$ITEM_NAME = "웹 서비스 상위 디렉터리 접근 제한 설정"
$SEVERITY = "상"

$purpose = "상위 디렉터리 접근 제한 설정을 통해 비인가자의 특정 디렉터리에 대한 접근 및 열람을 제한하여 중요 파일 및 데이터를 보호하고,Unicode 버그 및 서비스 거부 공격 등을 방지하기 위함"
$threat = "상위 디렉터리로 이동하는 것이 가능할 경우 접근하고자하는 디렉터리의 하위 경로에서 상위로 이동하며 정보 탐색이 가능하여 중요 정보가 노출될 위험이 존재함 악의적인 목적을 가진 사용자가 중요 파일 및 디렉터리의 접근이 가능하여 데이터가 유출될 위험이 존재함"
$criteria_good = "상위 디렉터리 접근 기능을 제거한 경우"
$criteria_bad = "상위 디렉터리 접근 기능을 제거하지 않은 경우"
$remediation = "상위 디렉터리 접근 기능 제거 설정"

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

        $allowOverrideAuth = @([regex]::Matches($activeText, '(?im)^\s*AllowOverride\s+.*\b(?:AuthConfig|All)\b.*') | ForEach-Object { $_.Value.Trim() } | Select-Object -Unique)
        $authDirectives = @([regex]::Matches($activeText, '(?im)^\s*(?:AuthName|AuthType|AuthUserFile|AuthGroupFile|Require\s+(?:valid-user|user|group)\b).*$') | ForEach-Object { $_.Value.Trim() } | Select-Object -Unique)
        $explicitDeny = @([regex]::Matches($activeText, '(?im)^\s*(?:Require\s+all\s+denied|Deny\s+from\s+all)\b.*') | ForEach-Object { $_.Value.Trim() } | Select-Object -Unique)
        $rootDirectoryGrants = @([regex]::Matches($activeText, '(?ims)<Directory\s+"?(?:/|[A-Za-z]:[/\\])"?\s*>.*?(?:Require\s+all\s+granted|Allow\s+from\s+all).*?</Directory>') | ForEach-Object { ($_.Value -replace '\s+', ' ').Trim() } | Select-Object -Unique)
        $directoryBlocks = @([regex]::Matches($activeText, '(?im)^\s*</?Directory\b.*') | ForEach-Object { $_.Value.Trim() } | Select-Object -Unique)

        $evidence = @(
            "Config files: $($config.Files -join ', ')",
            "Directory block markers: $($directoryBlocks.Count)",
            "AllowOverride AuthConfig/All directives: $($allowOverrideAuth.Count)",
            "Authentication directives: $($authDirectives.Count)",
            "Explicit deny directives: $($explicitDeny.Count)",
            "Root directory grant blocks: $($rootDirectoryGrants.Count)"
        )

        if ($rootDirectoryGrants.Count -gt 0) {
            $finalResult = "VULNERABLE"
            $status = "취약"
            $summary = "Apache grants access from the filesystem root or drive root. Restrict root Directory blocks and apply explicit authentication or deny rules."
            $evidence += "Matched root directory grant blocks:"
            $evidence += $rootDirectoryGrants
        }
        elseif ($authDirectives.Count -gt 0 -and ($allowOverrideAuth.Count -gt 0 -or $explicitDeny.Count -gt 0)) {
            $finalResult = "GOOD"
            $status = "양호"
            $summary = "Apache configuration contains authentication/authorization evidence for directory access control."
            $evidence += "Matched authentication/authorization directives:"
            $evidence += $allowOverrideAuth
            $evidence += $authDirectives
            $evidence += $explicitDeny
        }
        else {
            $finalResult = "MANUAL"
            $status = "수동진단"
            $summary = "Apache configuration was found, but parent-directory traversal protection cannot be proven from static config alone. Verify Directory blocks, authentication, AllowOverride scope, and runtime '..' path handling manually."
            if ($explicitDeny.Count -gt 0) {
                $evidence += "Explicit deny directives (root-only deny does not prove parent-traversal protection on served vhosts):"
                $evidence += $explicitDeny
            }
            if ($directoryBlocks.Count -gt 0) {
                $evidence += "Directory block markers:"
                $evidence += $directoryBlocks
            }
        }

        $commandOutput = $evidence -join "`n"
        $commandExecuted = "Parse Apache httpd.conf and included *.conf files for Directory access control, AllowOverride AuthConfig, authentication directives, deny rules, and root grants"
    }
}
catch {
    $finalResult = "MANUAL"
    $status = "수동진단"
    $summary = "Diagnostic execution failed; manual review required."
    $commandOutput = "Diagnostic execution failed: $($_.Exception.Message)"
    $commandExecuted = "Apache Windows parent-directory access control discovery"
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
