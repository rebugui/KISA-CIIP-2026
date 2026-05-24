# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Version: 1.0.1
# @Last Updated: 2026-05-24
# ============================================================================
# [Assessment Item]
# @ID          : WEB-25
# @Category    : 웹서비스>4.패치및로그관리
# @Platform    : Nginx_Windows
# @Severity    : 상
# @Title       : 주기적 보안 패치 및 벤더 권고 사항 적용
# @Description : docs/guideline_metadata.json and docs guidelines must be applied before final automation.
# @Reference   : docs/guideline_metadata.json and docs guideline Markdown
# ============================================================================

#Requires -Version 5.1

$ErrorActionPreference = 'Stop'
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\..\lib"
. "${LIB_DIR}\result_manager.ps1"
. "${SCRIPT_DIR}\nginx_windows_lib.ps1"

$ITEM_ID = "WEB-25"
$ITEM_NAME = "주기적 보안 패치 및 벤더 권고 사항 적용"
$SEVERITY = "상"

$purpose = "주기적인 최신 보안 패치를 통해 보안성 및 시스템 안정성을 확보하기 위함"
$threat = "주기적으로 최신 보안 패치를 적용하지 않을 경우, 알려진 취약점을 이용한 공격 또는 새로운 공격에 대한 침해 사고 발생 위험이 존재함"
$criteria_good = "최신 보안 패치가 적용되어 있으며, 패치 적용 정책을 수립하여 주기적인 패치 관리를 하는 경우"
$criteria_bad = "최신 보안 패치가 적용되어 있지 않거나 패치 적용 정책을 수립 및 주기적인 패치 관리를 하지"
$remediation = "패치 적용에 따른 서비스 영향 정도를 정확히 파악하여 주기적인 패치 적용 정책 수립 및 적용하도록 설정"

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
        $versionEvidence = [System.Collections.Generic.List[string]]::new()
        foreach ($process in $state.Processes) {
            if ($process.ExecutablePath -and (Test-Path -LiteralPath $process.ExecutablePath -PathType Leaf)) {
                try {
                    $version = (Get-Item -LiteralPath $process.ExecutablePath).VersionInfo.ProductVersion
                    $versionEvidence.Add("$($process.ExecutablePath): $version") | Out-Null
                }
                catch {
                    $versionEvidence.Add("$($process.ExecutablePath): version lookup failed: $($_.Exception.Message)") | Out-Null
                }
            }
        }

        $finalResult = "MANUAL"
        $status = "수동진단"
        $summary = "Nginx was found. Compare detected version and patch policy against current vendor security advisories."
        $evidence = [System.Collections.Generic.List[string]]::new()
        $evidence.Add("Service/process evidence:") | Out-Null
        $evidence.Add((Get-NginxWindowsProcessEvidence -State $state)) | Out-Null
        if ($versionEvidence.Count -gt 0) {
            $evidence.Add("Version evidence:`n$($versionEvidence -join "`n")") | Out-Null
        }
        else {
            $evidence.Add("No executable version evidence resolved.") | Out-Null
        }
        $commandOutput = ($evidence | Where-Object { $_ }) -join "`n"
        $commandExecuted = "Collect Nginx Windows service/process/version evidence for vendor advisory comparison"
    }
}
catch {
    $finalResult = "MANUAL"
    $status = "수동진단"
    $summary = "Diagnostic execution failed; manual review required."
    $commandOutput = "Diagnostic execution failed: $($_.Exception.Message)"
    $commandExecuted = "Nginx Windows patch/version evidence discovery"
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
