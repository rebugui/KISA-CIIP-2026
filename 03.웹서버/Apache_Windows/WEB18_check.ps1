# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Version: 1.0.1
# @Last Updated: 2026-05-24
# ============================================================================
# [Assessment Item]
# @ID          : WEB-18
# @Category    : 웹서비스>2.서비스관리
# @Platform    : Apache_Windows
# @Severity    : 상
# @Title       : 웹 서비스 WebDAV 비활성화
# @Description : docs/guideline_metadata.json and docs guidelines must be applied before final automation.
# @Reference   : docs/guideline_metadata.json and docs guideline Markdown
# ============================================================================

#Requires -Version 5.1

$ErrorActionPreference = 'Stop'
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\..\lib"
. "${LIB_DIR}\result_manager.ps1"
. "${SCRIPT_DIR}\apache_windows_lib.ps1"

$ITEM_ID = "WEB-18"
$ITEM_NAME = "웹 서비스 WebDAV 비활성화"
$SEVERITY = "상"

$purpose = "WebDAV 서비스를 비활성화하여,WebDAV에서 발견되는 다수의 인증 우회 취약점을 제거하고자함"
$threat = "WebDAV가 활성화되어 있는 경우 웹 서비스에 악의적으로 작성된 요청을 이용하여 인증을 우회함으로써 비밀번호로 보호된 WebDAV의 자원에 접근 (디렉터리 열람, 파일 다운로드 등)이 가능하며, WebDAV에 의해 호출된 일부 구성 요소에 매개 변수를 정확하게 점검하지 않는 결함이 존재하여, 이로 인해 버퍼 오버 런이 발생할 위험이 존재함"
$criteria_good = "WebDAV 서비스를 비활성화하고 있는 경우"
$criteria_bad = "WebDAV 서비스를 활성화하고 있는 경우"
$remediation = "WebDAV 서비스 비활성화 설정"

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

        $davModuleMatches = @([regex]::Matches($activeText, '(?im)^\s*LoadModule\s+(dav(?:_fs)?_module)\b.*$') | ForEach-Object { $_.Value.Trim() })
        $davOnMatches = @([regex]::Matches($activeText, '(?im)^\s*DAV\s+On\b.*$') | ForEach-Object { $_.Value.Trim() })
        $davOffMatches = @([regex]::Matches($activeText, '(?im)^\s*DAV\s+Off\b.*$') | ForEach-Object { $_.Value.Trim() })

        $evidence = @(
            "Config files: $($config.Files -join ', ')",
            "WebDAV module directives: $(if ($davModuleMatches.Count -gt 0) { $davModuleMatches -join '; ' } else { 'none' })",
            "DAV On directives: $(if ($davOnMatches.Count -gt 0) { $davOnMatches -join '; ' } else { 'none' })",
            "DAV Off directives: $(if ($davOffMatches.Count -gt 0) { $davOffMatches -join '; ' } else { 'none' })"
        )

        if ($davOnMatches.Count -gt 0) {
            $finalResult = "VULNERABLE"
            $status = "취약"
            $summary = "Apache WebDAV is enabled by DAV On directive. Disable WebDAV unless explicitly required."
        }
        elseif ($davModuleMatches.Count -gt 0) {
            $finalResult = "VULNERABLE"
            $status = "취약"
            $summary = "Apache WebDAV module is loaded. Disable mod_dav/mod_dav_fs unless explicitly required."
        }
        else {
            $finalResult = "GOOD"
            $status = "양호"
            $summary = "Apache WebDAV module and DAV On directive were not found."
        }

        $commandOutput = $evidence -join "`n"
        $commandExecuted = "Parse Apache httpd.conf and included *.conf files for LoadModule dav_module/dav_fs_module and DAV On"
    }
}
catch {
    $finalResult = "MANUAL"
    $status = "수동진단"
    $summary = "Diagnostic execution failed; manual review required."
    $commandOutput = "Diagnostic execution failed: $($_.Exception.Message)"
    $commandExecuted = "Apache Windows WebDAV configuration discovery"
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
