# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Version: 1.0.1
# @Last Updated: 2026-05-24
# ============================================================================
# [Assessment Item]
# @ID          : WEB-26
# @Category    : 웹서비스>4.패치및로그관리
# @Platform    : Nginx_Windows
# @Severity    : 중
# @Title       : 로그 디렉터리 및 파일 권한 설정
# @Description : docs/guideline_metadata.json and docs guidelines must be applied before final automation.
# @Reference   : docs/guideline_metadata.json and docs guideline Markdown
# ============================================================================

#Requires -Version 5.1

$ErrorActionPreference = 'Stop'
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\..\lib"
. "${LIB_DIR}\result_manager.ps1"
. "${SCRIPT_DIR}\nginx_windows_lib.ps1"

$ITEM_ID = "WEB-26"
$ITEM_NAME = "로그 디렉터리 및 파일 권한 설정"
$SEVERITY = "중"

$purpose = "로그 파일에 공격자에게 유용한 정보가 들어 있을 수 있으므로 권한 관리를 통해 비인가자에 의한 정보 유출, 로그 파일의 훼손 및 변조를 방지하기 위함"
$threat = "로그 디렉터리 및 파일에 적절한 권한이 설정되어 있지 않은 경우, 비인가자가 로그 파일에 접근할 수 있으므로 사용자 및 시스템 정보 유출, 로그 파일 조작 등의 공격 위험이 존재함"
$criteria_good = "로그 디렉터리 및 파일에 일반 사용자의 접근 권한이 없는 경우"
$criteria_bad = "로그 디렉터리 및 파일에 일반 사용자의 접근 권한이 있는 경우"
$remediation = "로그 디렉터리 및 파일에 일반 사용자 접근 권한 제거 설정"

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
        $logPaths = [System.Collections.Generic.List[string]]::new()
        foreach ($line in $state.ActiveLines) {
            if ($line -match '^(?i)(access_log|error_log)\s+([^\s;]+)') {
                $candidate = $Matches[2]
                if ($candidate -notmatch '^(?i)(off|stderr|syslog:)') {
                    $resolved = Resolve-NginxConfiguredPath -Path $candidate -ConfigFiles $state.ConfigFiles
                    if ($resolved -and -not $logPaths.Contains($resolved)) {
                        $logPaths.Add($resolved) | Out-Null
                    }
                }
            }
        }
        foreach ($conf in $state.ConfigFiles) {
            $prefix = Split-Path -Parent (Split-Path -Parent $conf)
            foreach ($candidate in @((Join-Path $prefix 'logs'), (Join-Path $prefix 'log'))) {
                if (Test-Path -LiteralPath $candidate -PathType Container) {
                    $resolved = [System.IO.Path]::GetFullPath($candidate)
                    if (-not $logPaths.Contains($resolved)) {
                        $logPaths.Add($resolved) | Out-Null
                    }
                }
            }
        }

        $aclEvidence = foreach ($path in $logPaths) {
            if (Test-Path -LiteralPath $path) {
                Get-NginxBroadAclEvidence -Path $path -Role 'LogPath'
            }
        }

        $evidence = [System.Collections.Generic.List[string]]::new()
        if ($logPaths.Count -gt 0) {
            $evidence.Add("Log paths:`n$($logPaths -join "`n")") | Out-Null
        }
        if ($aclEvidence) {
            $evidence.Add("Broad ACL evidence:`n" + (($aclEvidence | ForEach-Object { "$($_.Role): $($_.Path) => $($_.Principal) $($_.Access) ($($_.Rights))" }) -join "`n")) | Out-Null
        }
        if ($logPaths.Count -eq 0) {
            $evidence.Add("No existing Nginx log path was resolved from configuration.") | Out-Null
        }

        $commandExecuted = "Parse Nginx access_log/error_log paths and inspect NTFS ACLs"
        $commandOutput = ($evidence | Where-Object { $_ }) -join "`n`n"

        if ($logPaths.Count -eq 0) {
            $finalResult = "MANUAL"
            $status = "수동진단"
            $summary = "Nginx log paths could not be resolved; inspect active access_log and error_log paths manually."
        }
        elseif (@($aclEvidence | Where-Object { $_.Access -eq 'Write' -or $_.Access -eq 'Unknown' }).Count -gt 0) {
            $finalResult = "VULNERABLE"
            $status = "취약"
            $summary = "Nginx log paths have broad local write or unreadable ACL evidence."
        }
        elseif ($aclEvidence) {
            $finalResult = "MANUAL"
            $status = "수동진단"
            $summary = "Nginx log paths have broad local read ACL evidence; confirm whether this is required."
        }
        else {
            $finalResult = "GOOD"
            $status = "양호"
            $summary = "No broad local user ACL entries were found on resolved Nginx log paths."
        }
    }
}
catch {
    $finalResult = "MANUAL"
    $status = "수동진단"
    $summary = "Diagnostic execution failed; manual review required."
    $commandOutput = "Diagnostic execution failed: $($_.Exception.Message)"
    $commandExecuted = "Nginx Windows log path ACL discovery"
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
