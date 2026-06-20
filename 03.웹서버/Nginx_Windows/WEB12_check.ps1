# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Version: 1.0.1
# @Last Updated: 2026-05-24
# ============================================================================
# [Assessment Item]
# @ID          : WEB-12
# @Category    : 웹서비스>2.서비스관리
# @Platform    : Nginx_Windows
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
. "${SCRIPT_DIR}\nginx_windows_lib.ps1"

$ITEM_ID = "WEB-12"
$ITEM_NAME = "웹 서비스 링크 사용 금지"
$SEVERITY = "중"

$purpose = "무분별한 심볼 릭 링크, 별칭(aliases) 등을 제거하여 허용하지 않은 경로에서의 접근을 차단해 경로 검증을 우회한 시스템 파일 접근을 방지하기 위함"
$threat = "보안상 민감한 내용이 포함되어 있는 파일이 악의적인 사용자에게 노출될 경우 침해 사고로 이어질 위험이 존재함 접근을 허용한 웹 디렉터리 내에 서버의 다른 디렉터리나 파일들에 접근할 수 있는 심볼 릭 링크, aliases, 바로가기 등이 존재하는 경우 해당 링크를 통해 허용하지 않은 다른 디렉터리에 액세스할 수 있는 위험이 존재함"
$criteria_good = "심볼 릭 링크,aliases, 바로가기 등의 링크 사용을 허용하지 않는 경우"
$criteria_bad = "심볼 릭 링크,aliases, 바로가기 등의 링크 사용을 허용하는 경우"
$remediation = "웹 서비스 링크 사용 제한 설정"

try {
    $state = Get-NginxWindowsState

    if (-not $state.Installed) {
        $finalResult = "N/A"
        $status = "N/A"
        $summary = "Nginx for Windows service/process/configuration was not found."
        $commandOutput = "No nginx.exe process, Nginx service, or known nginx.conf path found."
        $commandExecuted = "Get-CimInstance Win32_Process/Win32_Service; known Nginx nginx.conf paths"
    }
    elseif ($state.ConfigFiles.Count -eq 0) {
        $finalResult = "MANUAL"
        $status = "수동진단"
        $summary = "Nginx was found, but nginx.conf could not be located automatically."
        $commandOutput = Get-NginxWindowsProcessEvidence -State $state
        $commandExecuted = "Discover Nginx Windows process/service configuration paths"
    }
    else {
        # WEB-14 미러: 설정된 root는 존재하지만 실제 경로 확인(resolve)이 불가한 경우를 추적한다.
        # (환경변수 미확장, UNC 오프라인, 사용자 지정 경로 부재 등) 이때 어떤 웹 루트도
        # 스캔되지 못하므로 양호로 단정하지 않고 수동진단으로 유도한다.
        $configuredRoots = @(Get-NginxRootPaths -State $state)
        $roots = @(($configuredRoots + (Get-NginxDefaultRootCandidates)) | Select-Object -Unique)
        $aliases = @(Get-NginxAliasPaths -State $state)
        $linkFindings = [System.Collections.Generic.List[string]]::new()
        $scanIncomplete = $false
        $scannedRootCount = 0

        foreach ($root in $roots) {
            if (-not (Test-Path -LiteralPath $root -PathType Container)) {
                continue
            }
            $scannedRootCount++
            # 심볼릭 링크/바로가기 누락을 막기 위해 스캔 결과를 절단(Select-Object -First N)하지 않는다.
            # 열거 중 오류가 발생하면 불완전 스캔으로 표시하여 양호 단정을 방지한다.
            $scanErrors = $null
            foreach ($item in @(Get-ChildItem -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue -ErrorVariable scanErrors | Where-Object {
                ($_.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or $_.Extension -match '(?i)^\.lnk$'
            })) {
                $linkFindings.Add($item.FullName) | Out-Null
            }
            if ($scanErrors -and $scanErrors.Count -gt 0) {
                $scanIncomplete = $true
            }
        }
        $webRootUnresolved = ($roots.Count -gt 0 -and $scannedRootCount -eq 0)

        $commandExecuted = "Inspect Nginx alias directives and all reparse/link files under configured roots (no result cap)"
        $commandOutput = (@(
            "Config files: $($state.Config.Files -join ', ')",
            "Root paths: $($roots -join ', ')",
            "Alias directives: $($aliases.Count)",
            ($aliases | ForEach-Object { "$($_.Directive) => $($_.Path)" }),
            "Reparse/link findings: $($linkFindings.Count)",
            $linkFindings,
            "Scan incomplete (enumeration errors): $scanIncomplete"
        ) | Where-Object { $_ }) -join "`n"

        if ($linkFindings.Count -gt 0) {
            $finalResult = "VULNERABLE"
            $status = "취약"
            $summary = "Reparse points or shortcut links were found under Nginx web roots."
        }
        elseif ($aliases.Count -gt 0) {
            $finalResult = "MANUAL"
            $status = "수동진단"
            $summary = "Nginx alias directives were found. Confirm each alias is required and does not expose unauthorized paths."
        }
        elseif ($scanIncomplete) {
            # 링크를 찾지 못했더라도 스캔이 불완전했다면 양호로 단정할 수 없음 → 수동진단
            $finalResult = "MANUAL"
            $status = "수동진단"
            $summary = "Web root link scan was incomplete due to enumeration errors (access denied/long paths). Manually verify that no symbolic links or shortcuts expose unauthorized paths."
        }
        elseif ($webRootUnresolved) {
            # 설정에 root는 존재하나 실제 경로를 확인하지 못해 어떤 웹 루트도 스캔하지 못함 → 양호 단정 불가
            $finalResult = "MANUAL"
            $status = "수동진단"
            $summary = "Nginx root directive(s) exist but the web root path could not be resolved; verify symlinks/aliases manually."
        }
        elseif ($scannedRootCount -gt 0) {
            $finalResult = "GOOD"
            $status = "양호"
            $summary = "No Nginx alias directives or reparse/link files were found under resolved web roots."
        }
        else {
            $finalResult = "MANUAL"
            $status = "수동진단"
            $summary = "Nginx configuration was found, but no web root path was resolved for link inspection."
        }
    }
}
catch {
    $finalResult = "MANUAL"
    $status = "수동진단"
    $summary = "Diagnostic execution failed; manual review required."
    $commandOutput = "Diagnostic execution failed: $($_.Exception.Message)"
    $commandExecuted = "Nginx Windows link and alias discovery"
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
