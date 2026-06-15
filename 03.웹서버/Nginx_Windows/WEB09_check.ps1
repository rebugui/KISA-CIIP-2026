# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Version: 1.0.1
# @Last Updated: 2026-05-24
# ============================================================================
# [Assessment Item]
# @ID          : WEB-09
# @Category    : 웹서비스>2.서비스관리
# @Platform    : Nginx_Windows
# @Severity    : 상
# @Title       : 웹 서비스 프로세스 권한 제한
# @Description : docs/guideline_metadata.json and docs guidelines must be applied before final automation.
# @Reference   : docs/guideline_metadata.json and docs guideline Markdown
# ============================================================================

#Requires -Version 5.1

$ErrorActionPreference = 'Stop'
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\..\lib"
. "${LIB_DIR}\result_manager.ps1"
. "${SCRIPT_DIR}\nginx_windows_lib.ps1"

$ITEM_ID = "WEB-09"
$ITEM_NAME = "웹 서비스 프로세스 권한 제한"
$SEVERITY = "상"

$purpose = "웹 프로세스가 웹 서비스 운영에 필요한 최소한의 권한만을 갖도록 제한함으로써 웹 사이트 방문자가 웹 서비스의 취약점을 이용해 시스템에 대한 어떤 권한도 획득할 수 없도록하여 침해 사고 발생 시 피해 범위 확산을 방지하기 위함"
$threat = "웹 프로세스 권한을 제한하지 않은 경우, 웹 사이트 방문자가 웹 서비스의 취약점을 이용하여 시스템 권한을 획득할 수 있으며, 웹 취약점을 통해 접속 권한을 획득한 경우에는 관리자 권한을 획득하여 서버에 접속 후 정보의 변경, 훼손 및 유출될 위험이 존재함"
$criteria_good = "웹 프로세스(웹 서비스)가 관리자 권한이 부여된 계정이 아닌 운영에 필요한 최소한의 권한을 가진 별도의 계정으로 구동되고 있는 경우"
$criteria_bad = "웹 프로세스(웹 서비스)가 운영에 필요한 최소한의 권한을 가진 별도의 계정이 아닌 관리자 권한이 부여된 계정으로 구동되고 있는 경우"
$remediation = "웹 서비스 프로세스 구동 시 관리자 권한이 아닌 운영에 필요한 최소한의 권한을 가진 계정으로 구동 설정"

try {
    $state = Get-NginxWindowsState

    if (-not $state.Installed) {
        $finalResult = "N/A"
        $status = "N/A"
        $summary = "Nginx for Windows service/process/configuration was not found."
        $commandOutput = "No nginx.exe process, Nginx service, or known nginx.conf path found."
        $commandExecuted = "Get-CimInstance Win32_Process/Win32_Service; known Nginx nginx.conf paths"
    }
    else {
        $ownerEvidence = [System.Collections.Generic.List[string]]::new()
        $processEvidence = [System.Collections.Generic.List[string]]::new()

        foreach ($process in $state.Processes) {
            $ownerText = "UNKNOWN"
            try {
                $owner = Invoke-CimMethod -InputObject $process -MethodName GetOwner -ErrorAction Stop
                if ($owner.ReturnValue -eq 0) {
                    $ownerText = if ($owner.Domain) { "$($owner.Domain)\$($owner.User)" } else { $owner.User }
                    $ownerEvidence.Add($ownerText) | Out-Null
                }
            }
            catch {
                $ownerText = "OWNER_LOOKUP_FAILED: $($_.Exception.Message)"
            }
            $processEvidence.Add("PID=$($process.ProcessId); Owner=$ownerText; CommandLine=$($process.CommandLine)") | Out-Null
        }

        $accountEvidence = @()
        $accountEvidence += @($state.Services | ForEach-Object { $_.StartName } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        $accountEvidence += @($ownerEvidence | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        $accountEvidence = @($accountEvidence | Select-Object -Unique)

        $highPrivilegeAccounts = @($accountEvidence | Where-Object {
            $_ -match '^(?i)(LocalSystem|NT AUTHORITY\\SYSTEM)$' -or
            $_ -match '(?i)(^|\\)Administrator$' -or
            $_ -match '(?i)(^|\\)Administrators$'
        })
        $lowPrivilegeAccounts = @($accountEvidence | Where-Object {
            $_ -match '^(?i)(NT AUTHORITY\\LocalService|NT AUTHORITY\\NetworkService|LocalService|NetworkService)$' -or
            ($_ -notmatch '^(?i)(LocalSystem|NT AUTHORITY\\SYSTEM)$' -and $_ -notmatch '(?i)(^|\\)Administrator(s)?$')
        })

        $evidence = @(
            "Service/process evidence:",
            (Get-NginxWindowsProcessEvidence -State $state),
            "Process owners:",
            ($processEvidence -join "`n"),
            "Account evidence: $($accountEvidence -join ', ')"
        )

        if ($highPrivilegeAccounts.Count -gt 0) {
            $finalResult = "VULNERABLE"
            $status = "취약"
            $summary = "Nginx appears to run with an administrator-equivalent Windows account. Configure the service to use a dedicated least-privilege account."
            $evidence += "High privilege account evidence:"
            $evidence += $highPrivilegeAccounts
        }
        elseif ($lowPrivilegeAccounts.Count -gt 0) {
            $finalResult = "GOOD"
            $status = "양호"
            $summary = "Nginx service/process account evidence is not administrator-equivalent."
            $evidence += "Least-privilege account evidence:"
            $evidence += $lowPrivilegeAccounts
        }
        else {
            $finalResult = "MANUAL"
            $status = "수동진단"
            $summary = "Nginx was found, but the service/process account could not be determined."
        }

        $commandOutput = $evidence -join "`n"
        $commandExecuted = "Inspect Nginx Windows service StartName and running nginx.exe process owner"
    }
}
catch {
    $finalResult = "MANUAL"
    $status = "수동진단"
    $summary = "Diagnostic execution failed; manual review required."
    $commandOutput = "Diagnostic execution failed: $($_.Exception.Message)"
    $commandExecuted = "Nginx Windows process privilege discovery"
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
