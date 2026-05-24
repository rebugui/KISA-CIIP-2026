# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Version: 1.0.1
# @Last Updated: 2026-05-24
# ============================================================================
# [Assessment Item]
# @ID          : WEB-17
# @Category    : 웹서비스>2.서비스관리
# @Platform    : Apache_Windows
# @Severity    : 중
# @Title       : 웹 서비스 가상 디렉터리 삭제
# @Description : docs/guideline_metadata.json and docs guidelines must be applied before final automation.
# @Reference   : docs/guideline_metadata.json and docs guideline Markdown
# ============================================================================

#Requires -Version 5.1

$ErrorActionPreference = 'Stop'
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\..\lib"
. "${LIB_DIR}\result_manager.ps1"
. "${SCRIPT_DIR}\apache_windows_lib.ps1"

$ITEM_ID = "WEB-17"
$ITEM_NAME = "웹 서비스 가상 디렉터리 삭제"
$SEVERITY = "중"

$purpose = "불필요한 가상 디렉터리를 삭제하여 공격이 가능한 영역을 최소화하고 정보 노출 방지 및 권한 상승 공격 등의 위험을 제거하기 위함"
$threat = "불필요한 가상 디렉터리를 삭제하지 않은 경우, 취약한 가상 디렉터리를 통해 시스템 권한 탈취 및 시스템 구조 등의 중요 정보가 노출될 위험이 존재함"
$criteria_good = "불필요한 가상 디렉터리가 존재하지 않는 경우"
$criteria_bad = "불필요한 가상 디렉터리가 존재하는 경우"
$remediation = "불필요한 가상 디렉터리 존재 여부 점검 및 삭제하도록 설정"

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
        $summary = "Apache service exists, but configuration files were not found for Alias inspection."
        $commandOutput = ($services | ForEach-Object { "$($_.Name) [$($_.State)] $($_.PathName)" }) -join "`n"
        $commandExecuted = "Get-CimInstance Win32_Service; known Apache httpd.conf paths"
    }
    else {
        $config = Get-ApacheWindowsConfigText -ConfigFiles $configFiles
        $aliasLines = [System.Collections.Generic.List[string]]::new()
        foreach ($line in ($config.Text -split "`r?`n")) {
            $trimmed = $line.Trim()
            if ($trimmed -match '^#') {
                continue
            }
            if ($trimmed -match '^(?i)(Alias|AliasMatch|ScriptAlias|ScriptAliasMatch)\s+') {
                $aliasLines.Add($trimmed) | Out-Null
            }
        }

        $knownUnnecessary = @($aliasLines | Where-Object {
            $_ -match '(?i)\s/(?:manual|doc|docs|icons|examples?|samples?|test|tmp|backup|old)(?:/|\s|")'
        })
        $businessAliases = @($aliasLines | Where-Object { $knownUnnecessary -notcontains $_ })

        $commandExecuted = "Parse active Alias/AliasMatch/ScriptAlias directives from Apache Windows configuration"
        $commandOutput = if ($aliasLines.Count -gt 0) {
            ($aliasLines | ForEach-Object { "Alias directive: $_" }) -join "`n"
        }
        else {
            "No active Alias, AliasMatch, ScriptAlias, or ScriptAliasMatch directives found."
        }

        if ($knownUnnecessary.Count -gt 0) {
            $finalResult = "VULNERABLE"
            $status = "취약"
            $summary = "Known unnecessary virtual directory aliases such as manual/docs/examples/test paths were found."
        }
        elseif ($businessAliases.Count -gt 0) {
            $finalResult = "MANUAL"
            $status = "수동진단"
            $summary = "Virtual directory aliases exist; confirm each alias is required and remove unnecessary mappings."
        }
        else {
            $finalResult = "GOOD"
            $status = "양호"
            $summary = "No active Apache virtual directory alias directives were found."
        }
    }
}
catch {
    $finalResult = "MANUAL"
    $status = "수동진단"
    $summary = "Diagnostic execution failed; manual review required."
    $commandOutput = "Diagnostic execution failed: $($_.Exception.Message)"
    $commandExecuted = "Apache Windows Alias configuration discovery"
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
