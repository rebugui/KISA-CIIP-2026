# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Version: 1.0.1
# @Last Updated: 2026-05-24
# ============================================================================
# [Assessment Item]
# @ID          : WEB-26
# @Category    : 웹서비스>4.패치및로그관리
# @Platform    : Apache_Windows
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
. "${SCRIPT_DIR}\apache_windows_lib.ps1"

$ITEM_ID = "WEB-26"
$ITEM_NAME = "로그 디렉터리 및 파일 권한 설정"
$SEVERITY = "중"

$purpose = "로그 파일에 공격자에게 유용한 정보가 들어 있을 수 있으므로 권한 관리를 통해 비인가자에 의한 정보 유출, 로그 파일의 훼손 및 변조를 방지하기 위함"
$threat = "로그 디렉터리 및 파일에 적절한 권한이 설정되어 있지 않은 경우, 비인가자가 로그 파일에 접근할 수 있으므로 사용자 및 시스템 정보 유출, 로그 파일 조작 등의 공격 위험이 존재함"
$criteria_good = "로그 디렉터리 및 파일에 일반 사용자의 접근 권한이 없는 경우"
$criteria_bad = "로그 디렉터리 및 파일에 일반 사용자의 접근 권한이 있는 경우"
$remediation = "로그 디렉터리 및 파일에 일반 사용자 접근 권한 제거 설정"

function Test-BroadLogPrincipal {
    param([System.Security.Principal.IdentityReference]$Identity)
    try {
        $sid = $Identity.Translate([System.Security.Principal.SecurityIdentifier]).Value
    }
    catch {
        $sid = [string]$Identity
    }
    return @(
        $sid -eq 'S-1-1-0',
        $sid -eq 'S-1-5-11',
        $sid -eq 'S-1-5-32-545',
        $sid -eq 'S-1-5-32-546',
        $sid -match '-513$',
        ([string]$Identity) -match '(?i)Everyone|Authenticated Users|BUILTIN\\Users|Guests|Domain Users'
    ) -contains $true
}

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
        $summary = "Apache service exists, but configuration files were not found for log path inspection."
        $commandOutput = ($services | ForEach-Object { "$($_.Name) [$($_.State)] $($_.PathName)" }) -join "`n"
        $commandExecuted = "Get-CimInstance Win32_Service; known Apache httpd.conf paths"
    }
    else {
        $config = Get-ApacheWindowsConfigText -ConfigFiles $configFiles
        $activeLines = @($config.Text -split "`r?`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ -and $_ -notmatch '^#' })
        $logPaths = [System.Collections.Generic.List[string]]::new()

        foreach ($line in $activeLines) {
            if ($line -match '^(?i)(ErrorLog|CustomLog|TransferLog)\s+"?([^"\s]+)"?') {
                $candidate = $Matches[2].Replace('/', '\')
                if (-not [System.IO.Path]::IsPathRooted($candidate)) {
                    foreach ($conf in $configFiles) {
                        $root = Split-Path -Parent (Split-Path -Parent $conf)
                        $candidatePath = Join-Path $root $candidate
                        if (Test-Path -LiteralPath $candidatePath) {
                            $candidate = $candidatePath
                            break
                        }
                    }
                }
                if (Test-Path -LiteralPath $candidate) {
                    $resolved = [System.IO.Path]::GetFullPath($candidate)
                    if (-not $logPaths.Contains($resolved)) {
                        $logPaths.Add($resolved) | Out-Null
                    }
                }
            }
        }

        foreach ($conf in $configFiles) {
            $root = Split-Path -Parent (Split-Path -Parent $conf)
            foreach ($candidate in @((Join-Path $root 'logs'), (Join-Path $root 'log'))) {
                if (Test-Path -LiteralPath $candidate -PathType Container) {
                    $resolved = [System.IO.Path]::GetFullPath($candidate)
                    if (-not $logPaths.Contains($resolved)) {
                        $logPaths.Add($resolved) | Out-Null
                    }
                }
            }
        }

        $aclEvidence = [System.Collections.Generic.List[string]]::new()
        foreach ($path in $logPaths) {
            $targets = @($path)
            if (Test-Path -LiteralPath $path -PathType Container) {
                $targets += @(Get-ChildItem -LiteralPath $path -File -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName)
            }
            foreach ($target in $targets) {
                try {
                    $acl = Get-Acl -LiteralPath $target -ErrorAction Stop
                    foreach ($rule in $acl.Access) {
                        if ($rule.AccessControlType -eq 'Allow' -and (Test-BroadLogPrincipal -Identity $rule.IdentityReference)) {
                            $aclEvidence.Add("$target => $($rule.IdentityReference) $($rule.FileSystemRights)") | Out-Null
                        }
                    }
                }
                catch {
                    $aclEvidence.Add("$target => ACL read failed: $($_.Exception.Message)") | Out-Null
                }
            }
        }

        $commandExecuted = "Parse Apache ErrorLog/CustomLog/TransferLog paths and inspect NTFS ACLs"
        $commandOutput = (@(
            if ($logPaths.Count -gt 0) { "Log paths:`n" + ($logPaths -join "`n") }
            if ($aclEvidence.Count -gt 0) { "Broad ACL evidence:`n" + ($aclEvidence -join "`n") }
            if ($logPaths.Count -eq 0) { "No existing Apache log path was resolved from configuration." }
        ) -join "`n`n")

        if ($logPaths.Count -eq 0) {
            $finalResult = "MANUAL"
            $status = "수동진단"
            $summary = "Apache log paths could not be resolved; inspect active ErrorLog and CustomLog paths manually."
        }
        elseif ($aclEvidence.Count -gt 0) {
            $finalResult = "VULNERABLE"
            $status = "취약"
            $summary = "Apache log paths have broad local user ACL entries."
        }
        else {
            $finalResult = "GOOD"
            $status = "양호"
            $summary = "No broad local user ACL entries were found on resolved Apache log paths."
        }
    }
}
catch {
    $finalResult = "MANUAL"
    $status = "수동진단"
    $summary = "Diagnostic execution failed; manual review required."
    $commandOutput = "Diagnostic execution failed: $($_.Exception.Message)"
    $commandExecuted = "Apache Windows log path ACL discovery"
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
