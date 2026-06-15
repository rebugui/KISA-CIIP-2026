# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Version: 1.0.1
# @Last Updated: 2026-05-24
# ============================================================================
# [Assessment Item]
# @ID          : WEB-07
# @Category    : 웹서비스>2.서비스관리
# @Platform    : Apache_Windows
# @Severity    : 중
# @Title       : 웹 서비스 경로 내 불필요한 파일 제거
# @Description : docs/guideline_metadata.json and docs guidelines must be applied before final automation.
# @Reference   : docs/guideline_metadata.json and docs guideline Markdown
# ============================================================================

#Requires -Version 5.1

$ErrorActionPreference = 'Stop'
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\..\lib"
. "${LIB_DIR}\result_manager.ps1"
. "${SCRIPT_DIR}\apache_windows_lib.ps1"

$ITEM_ID = "WEB-07"
$ITEM_NAME = "웹 서비스 경로 내 불필요한 파일 제거"
$SEVERITY = "중"

$purpose = "웹 서비스 설치 시 기본으로 생성되는 샘플, 매뉴얼 파일 등 서비스에 불필요한 파일을 제거하여 불필요한 공격 대상으로 이용되는 것을 방지하기 위함"
$threat = "웹 서비스 설치 시 기본으로 생성되는 파일 및 디렉터리나 백 업, 테스트 파일 등을 제거하지 않은 경우, 비인가자에게 시스템 관련 정보 및 웹 서버 정보가 노출되거나 해킹에 악용될 수 있음"
$criteria_good = "기본으로 생성되는 불필요한 파일 및 디렉터리가 존재하지 않을 경우"
$criteria_bad = "기본으로 생성되는 불필요한 파일 및 디렉터리가 존재하는 경우"
$remediation = "불필요한 파일 및 디렉터리를 제거하도록 설정"

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
    else {
        $rootCandidates = New-Object System.Collections.Generic.List[string]

        if ($configCandidates.Count -gt 0) {
            $config = Get-ApacheWindowsConfigText -ConfigFiles $configCandidates
            $activeLines = @($config.Text -split "`r?`n" | Where-Object { $_.Trim() -notmatch '^#' })
            foreach ($line in $activeLines) {
                if ($line -match '^\s*DocumentRoot\s+"?([^"]+)"?') {
                    $rootCandidates.Add($Matches[1].Trim())
                }
            }

            foreach ($configFile in $config.Files) {
                $confDir = Split-Path -Parent $configFile
                foreach ($relative in @("..\htdocs", "..\manual", "..\docs", "..\conf\original")) {
                    $candidate = Join-Path $confDir $relative
                    $rootCandidates.Add($candidate)
                }
            }
        }

        foreach ($candidate in @(
            "C:\Apache24\htdocs",
            "C:\Apache24\manual",
            "C:\Apache24\docs",
            "C:\Apache2\htdocs",
            "C:\Apache2\manual",
            "C:\Program Files\Apache Group\Apache2\htdocs",
            "C:\Program Files\Apache Group\Apache2\manual",
            "C:\Program Files\Apache Software Foundation\Apache24\htdocs",
            "C:\Program Files\Apache Software Foundation\Apache24\manual",
            "C:\Program Files (x86)\Apache Software Foundation\Apache24\htdocs",
            "C:\Program Files (x86)\Apache Software Foundation\Apache24\manual"
        )) {
            $rootCandidates.Add($candidate)
        }

        $existingRoots = @(
            $rootCandidates |
                Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
                ForEach-Object { [Environment]::ExpandEnvironmentVariables($_.Trim('"')) } |
                Where-Object { Test-Path -LiteralPath $_ } |
                ForEach-Object { (Resolve-Path -LiteralPath $_).Path } |
                Select-Object -Unique
        )

        if ($existingRoots.Count -eq 0) {
            $finalResult = "MANUAL"
            $status = "수동진단"
            $summary = "Apache service/configuration evidence was found, but no web root or manual/sample directory could be resolved automatically."
            $commandOutput = "Config candidates: $($configCandidates -join ', ')`nChecked known Apache Windows htdocs/manual/docs locations."
            $commandExecuted = "Parse DocumentRoot and check known Apache Windows web/manual/sample paths"
        }
        else {
            # Definite default/backup artifacts: backup/temp/dump extensions that are
            # not normal application content -> VULNERABLE.
            $definitePatterns = @(
                "*.bak", "*.backup", "*.old", "*.orig", "*.save", "*~",
                "*.swp", "*.tmp", "*.temp", "*.dump"
            )
            # Ambiguous substring/extension matches: these also match legitimate
            # application/library files (e.g. latest.js, readme.html, uninstall.js,
            # app.log, export.sql), so their origin (install-default vs app asset)
            # cannot be determined statically -> route to MANUAL, not VULNERABLE.
            $ambiguousPatterns = @(
                "*sample*", "*example*", "*test*", "*install*", "*setup*", "*readme*",
                "*.sql", "*.log"
            )
            $dirNames = @("manual", "manuals", "docs", "doc", "samples", "sample", "examples", "example", "test", "tests")
            $findings = New-Object System.Collections.Generic.List[string]
            $ambiguousFindings = New-Object System.Collections.Generic.List[string]

            foreach ($root in $existingRoots) {
                $leaf = Split-Path -Leaf $root
                if ($dirNames -contains $leaf.ToLowerInvariant()) {
                    $findings.Add("Directory: $root")
                }

                foreach ($dirName in $dirNames) {
                    $directChild = Join-Path $root $dirName
                    if (Test-Path -LiteralPath $directChild) {
                        $findings.Add("Directory: $directChild")
                    }
                }

                foreach ($pattern in $definitePatterns) {
                    $matched = @(Get-ChildItem -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue -File -Filter $pattern | Select-Object -First 5)
                    foreach ($item in $matched) {
                        $findings.Add("File: $($item.FullName)")
                    }
                    if ($findings.Count -ge 30) {
                        break
                    }
                }

                foreach ($pattern in $ambiguousPatterns) {
                    $matched = @(Get-ChildItem -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue -File -Filter $pattern | Select-Object -First 5)
                    foreach ($item in $matched) {
                        $ambiguousFindings.Add("File: $($item.FullName)")
                    }
                    if ($ambiguousFindings.Count -ge 30) {
                        break
                    }
                }

                if ($findings.Count -ge 30 -and $ambiguousFindings.Count -ge 30) {
                    break
                }
            }

            $findings = @($findings | Select-Object -Unique)
            $ambiguousFindings = @($ambiguousFindings | Select-Object -Unique)
            $evidence = @(
                "Checked roots: $($existingRoots -join ', ')",
                "Default/backup artifact evidence count: $($findings.Count)",
                "Ambiguous (manual-review) file evidence count: $($ambiguousFindings.Count)"
            )

            if ($findings.Count -gt 0) {
                $finalResult = "VULNERABLE"
                $status = "취약"
                $summary = "Apache web path contains default, sample, manual, or backup/temporary files/directories that should be removed."
                $evidence += "Matched unnecessary files/directories:"
                $evidence += $findings
                if ($ambiguousFindings.Count -gt 0) {
                    $evidence += "Additional files matching ambiguous patterns (verify origin):"
                    $evidence += $ambiguousFindings
                }
            }
            elseif ($ambiguousFindings.Count -gt 0) {
                $finalResult = "MANUAL"
                $status = "수동진단"
                $summary = "Files matching sample/example/test/install/setup/readme or .sql/.log patterns were found under Apache web paths, but these also match legitimate application/library content. Verify manually whether they are default-generated install artifacts that must be removed."
                $evidence += "Files requiring manual origin review:"
                $evidence += $ambiguousFindings
            }
            else {
                $finalResult = "GOOD"
                $status = "양호"
                $summary = "Default manual/sample/test/backup files were not found under resolved Apache web paths."
            }

            $commandOutput = $evidence -join "`n"
            $commandExecuted = "Parse DocumentRoot and search known Apache Windows web paths for manual/sample/test/backup/temporary files"
        }
    }
}
catch {
    $finalResult = "MANUAL"
    $status = "수동진단"
    $summary = "Diagnostic execution failed; manual review required."
    $commandOutput = "Diagnostic execution failed: $($_.Exception.Message)"
    $commandExecuted = "Apache Windows unnecessary file discovery"
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
