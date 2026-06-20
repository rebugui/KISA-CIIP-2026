# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Version: 1.0.1
# @Last Updated: 2026-05-24
# ============================================================================
# [Assessment Item]
# @ID          : WEB-11
# @Category    : 웹서비스>2.서비스관리
# @Platform    : Apache_Windows
# @Severity    : 중
# @Title       : 웹 서비스 경로 설정
# @Description : docs/guideline_metadata.json and docs guidelines must be applied before final automation.
# @Reference   : docs/guideline_metadata.json and docs guideline Markdown
# ============================================================================

#Requires -Version 5.1

$ErrorActionPreference = 'Stop'
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\..\lib"
. "${LIB_DIR}\result_manager.ps1"
. "${SCRIPT_DIR}\apache_windows_lib.ps1"

$ITEM_ID = "WEB-11"
$ITEM_NAME = "웹 서비스 경로 설정"
$SEVERITY = "중"

$purpose = "웹 서비스 영역 내 불필요한 경로를 분리해 웹 서비스의 침해가 시스템 영역으로 확장될 가능성을 최소화하기 위함"
$threat = "웹 서비스 경로를 기타 업무와 영역이 분리되지 않은 경로로 설정하거나, 불필요한 경로가 존재할 경우 외부에서 시스템 중요 파일이나 기능에 비인가 접근이 발생할 위험이 존재함"
$criteria_good = "웹 서버 경로를 기타 업무와 영역이 분리된 경로로 설정 및 불필요한 경로가 존재하지 않는 경우"
$criteria_bad = "웹 서버 경로를 기타 업무와 영역이 분리되지 않은 경로로 설정하거나 불필요한 경로가 있는 경우"
$remediation = "웹 서버의 경로를 별도의 경로로 변경 및 불필요한 경로 제거 설정"

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
        $documentRoots = @(
            $activeLines |
                ForEach-Object {
                    if ($_ -match '^\s*DocumentRoot\s+"?([^"#]+)"?') {
                        [Environment]::ExpandEnvironmentVariables($Matches[1].Trim())
                    }
                } |
                Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
                Select-Object -Unique
        )

        $defaultRootPatterns = @(
            '^[A-Za-z]:\\Apache\d*\\htdocs\\?$',
            '^[A-Za-z]:\\Apache24\\htdocs\\?$',
            '^[A-Za-z]:\\Program Files(?: \(x86\))?\\Apache Group\\Apache\d*\\htdocs\\?$',
            '^[A-Za-z]:\\Program Files(?: \(x86\))?\\Apache Software Foundation\\Apache\d*\\htdocs\\?$',
            '^[A-Za-z]:\\xampp\\htdocs\\?$',
            '^[A-Za-z]:\\wamp(?:64)?\\www\\?$'
        )
        $dangerousRootPatterns = @(
            '^[A-Za-z]:\\?$',
            '^[A-Za-z]:\\Windows\\?$',
            '^[A-Za-z]:\\Windows\\System32\\?$',
            '^[A-Za-z]:\\Users\\?$',
            '^[A-Za-z]:\\Program Files\\?$',
            '^[A-Za-z]:\\Program Files \(x86\)\\?$'
        )

        # 기본/시스템 웹 트리 prefix. 경로 자체뿐 아니라 그 하위(예: C:\Apache24\htdocs\app)도
        # '분리되지 않은 경로'로 간주하기 위해 prefix 비교를 추가한다.
        $defaultTreePrefixes = @(
            'C:\Apache24\htdocs',
            'C:\Apache\htdocs',
            'C:\xampp\htdocs',
            'C:\wamp\www',
            'C:\wamp64\www'
        )
        $systemTreePrefixes = @(
            'C:\Windows',
            'C:\Program Files',
            'C:\Program Files (x86)',
            'C:\Users'
        )

        $defaultRoots = @()
        $dangerousRoots = @()
        foreach ($root in $documentRoots) {
            $normalized = $root.Trim('"').TrimEnd('\')
            $matched = $false
            foreach ($pattern in $dangerousRootPatterns) {
                if ($normalized -match $pattern) {
                    $dangerousRoots += $root
                    $matched = $true
                    break
                }
            }
            if (-not $matched) {
                foreach ($p in $systemTreePrefixes) {
                    if ($normalized -ieq $p -or $normalized -like ($p + '\*')) {
                        $dangerousRoots += $root
                        $matched = $true
                        break
                    }
                }
            }
            if ($matched) { continue }
            foreach ($pattern in $defaultRootPatterns) {
                if ($normalized -match $pattern) {
                    $defaultRoots += $root
                    $matched = $true
                    break
                }
            }
            if (-not $matched) {
                foreach ($p in $defaultTreePrefixes) {
                    if ($normalized -ieq $p -or $normalized -like ($p + '\*')) {
                        $defaultRoots += $root
                        break
                    }
                }
            }
        }

        $defaultRoots = @($defaultRoots | Select-Object -Unique)
        $dangerousRoots = @($dangerousRoots | Select-Object -Unique)
        $evidence = @(
            "Config files: $($config.Files -join ', ')",
            "DocumentRoot directives: $($documentRoots.Count)",
            "Default web roots: $($defaultRoots.Count)",
            "System/root paths: $($dangerousRoots.Count)"
        )

        if ($documentRoots.Count -eq 0) {
            $finalResult = "MANUAL"
            $status = "수동진단"
            $summary = "Apache configuration was found, but DocumentRoot could not be determined automatically."
            $evidence += "No active DocumentRoot directive found."
        }
        elseif ($dangerousRoots.Count -gt 0) {
            $finalResult = "VULNERABLE"
            $status = "취약"
            $summary = "Apache DocumentRoot points to a broad system path. Move the web service root to a dedicated separated directory."
            $evidence += "Matched system/root DocumentRoot paths:"
            $evidence += $dangerousRoots
        }
        elseif ($defaultRoots.Count -gt 0) {
            $finalResult = "VULNERABLE"
            $status = "취약"
            $summary = "Apache DocumentRoot uses a default web root path. Configure a separated service-specific path."
            $evidence += "Matched default DocumentRoot paths:"
            $evidence += $defaultRoots
        }
        else {
            $finalResult = "GOOD"
            $status = "양호"
            $summary = "Apache DocumentRoot appears to use a separated non-default path."
            $evidence += "DocumentRoot paths:"
            $evidence += $documentRoots
        }

        $commandOutput = $evidence -join "`n"
        $commandExecuted = "Parse Apache httpd.conf and included *.conf files for DocumentRoot and compare against default/system paths"
    }
}
catch {
    $finalResult = "MANUAL"
    $status = "수동진단"
    $summary = "Diagnostic execution failed; manual review required."
    $commandOutput = "Diagnostic execution failed: $($_.Exception.Message)"
    $commandExecuted = "Apache Windows DocumentRoot path discovery"
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
