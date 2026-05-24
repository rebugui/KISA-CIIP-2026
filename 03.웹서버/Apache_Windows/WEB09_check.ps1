# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Version: 1.0.1
# @Last Updated: 2026-05-24
# ============================================================================
# [Assessment Item]
# @ID          : WEB-09
# @Category    : 웹서비스>2.서비스관리
# @Platform    : Apache_Windows
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
. "${SCRIPT_DIR}\apache_windows_lib.ps1"

$ITEM_ID = "WEB-09"
$ITEM_NAME = "웹 서비스 프로세스 권한 제한"
$SEVERITY = "상"

$purpose = "웹 프로세스가 웹 서비스 운영에 필요한 최소한의 권한만을 갖도록 제한함으로써 웹 사이트 방문자가 웹 서비스의 취약점을 이용해 시스템에 대한 어떤 권한도 획득할 수 없도록하여 침해 사고 발생 시 피해 범위 확산을 방지하기 위함"
$threat = "웹 프로세스 권한을 제한하지 않은 경우, 웹 사이트 방문자가 웹 서비스의 취약점을 이용하여 시스템 권한을 획득할 수 있으며, 웹 취약점을 통해 접속 권한을 획득한 경우에는 관리자 권한을 획득하여 서버에 접속 후 정보의 변경, 훼손 및 유출될 위험이 존재함"
$criteria_good = "웹 프로세스(웹 서비스)가 관리자 권한이 부여된 계정이 아닌 운영에 필요한 최소한의 권한을 가진 별도의 계정으로 구동되고 있는 경우"
$criteria_bad = ""
$remediation = "웹 서비스 프로세스 구동 시 관리자 권한이 아닌 운영에 필요한 최소한의 권한을 가진 계정으로 구동 설정"

try {
    $services = @(Get-ApacheWindowsServices)

    if ($services.Count -eq 0) {
        $finalResult = "N/A"
        $status = "N/A"
        $summary = "Apache for Windows service was not found."
        $commandOutput = "No Apache/httpd Windows service found."
        $commandExecuted = "Get-CimInstance Win32_Service | Where-Object Name/DisplayName matches Apache/httpd"
    }
    else {
        $serviceEvidence = @($services | Select-Object Name, DisplayName, State, StartName, PathName)
        $processEvidence = New-Object System.Collections.Generic.List[string]
        $ownerEvidence = New-Object System.Collections.Generic.List[string]

        $apacheProcesses = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {
            $_.Name -match '^(?i)(httpd|apache)\.exe$' -or $_.CommandLine -match '(?i)apache|httpd'
        })

        foreach ($process in $apacheProcesses) {
            $ownerText = "UNKNOWN"
            try {
                $owner = Invoke-CimMethod -InputObject $process -MethodName GetOwner -ErrorAction Stop
                if ($owner.ReturnValue -eq 0) {
                    $ownerText = if ($owner.Domain) { "$($owner.Domain)\$($owner.User)" } else { $owner.User }
                    $ownerEvidence.Add($ownerText)
                }
            }
            catch {
                $ownerText = "OWNER_LOOKUP_FAILED: $($_.Exception.Message)"
            }
            $processEvidence.Add("PID=$($process.ProcessId); Name=$($process.Name); Owner=$ownerText; CommandLine=$($process.CommandLine)")
        }

        $accountEvidence = @()
        $accountEvidence += @($services | ForEach-Object { $_.StartName } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
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
            "Service evidence:",
            (($serviceEvidence | Format-List | Out-String).Trim()),
            "Process evidence count: $($processEvidence.Count)",
            "Account evidence: $($accountEvidence -join ', ')"
        )

        if ($processEvidence.Count -gt 0) {
            $evidence += "Running Apache processes:"
            $evidence += $processEvidence
        }

        if ($highPrivilegeAccounts.Count -gt 0) {
            $finalResult = "VULNERABLE"
            $status = "취약"
            $summary = "Apache appears to run with an administrator-equivalent Windows account. Configure the service to use a dedicated least-privilege account."
            $evidence += "High privilege account evidence:"
            $evidence += $highPrivilegeAccounts
        }
        elseif ($lowPrivilegeAccounts.Count -gt 0) {
            $finalResult = "GOOD"
            $status = "양호"
            $summary = "Apache service/process account evidence is not administrator-equivalent."
            $evidence += "Least-privilege account evidence:"
            $evidence += $lowPrivilegeAccounts
        }
        else {
            $finalResult = "MANUAL"
            $status = "수동진단"
            $summary = "Apache service was found, but the service/process account could not be determined."
        }

        $commandOutput = $evidence -join "`n"
        $commandExecuted = "Inspect Apache Windows service StartName and running httpd/apache.exe process owner"
    }
}
catch {
    $finalResult = "MANUAL"
    $status = "수동진단"
    $summary = "Diagnostic execution failed; manual review required."
    $commandOutput = "Diagnostic execution failed: $($_.Exception.Message)"
    $commandExecuted = "Apache Windows process privilege discovery"
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
