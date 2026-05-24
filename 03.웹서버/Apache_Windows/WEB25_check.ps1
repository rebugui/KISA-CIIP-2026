# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Version: 1.0.1
# @Last Updated: 2026-05-24
# ============================================================================
# [Assessment Item]
# @ID          : WEB-25
# @Category    : 웹서비스>4.패치및로그관리
# @Platform    : Apache_Windows
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
. "${SCRIPT_DIR}\apache_windows_lib.ps1"

$ITEM_ID = "WEB-25"
$ITEM_NAME = "주기적 보안 패치 및 벤더 권고 사항 적용"
$SEVERITY = "상"

$purpose = "주기적인 최신 보안 패치를 통해 보안성 및 시스템 안정성을 확보하기 위함"
$threat = "주기적으로 최신 보안 패치를 적용하지 않을 경우, 알려진 취약점을 이용한 공격 또는 새로운 공격에 대한 침해 사고 발생 위험이 존재함"
$criteria_good = "최신 보안 패치가 적용되어 있으며, 패치 적용 정책을 수립하여 주기적인 패치 관리를 하는 경우"
$criteria_bad = "최신 보안 패치가 적용되어 있지 않거나 패치 적용 정책을 수립 및 주기적인 패치 관리를 하지"
$remediation = "패치 적용에 따른 서비스 영향 정도를 정확히 파악하여 주기적인 패치 적용 정책 수립 및 적용하도록 설정"

try {
    $services = @(Get-ApacheWindowsServices)
    $configFiles = @(Get-ApacheWindowsConfigCandidates)
    $versionEvidence = [System.Collections.Generic.List[string]]::new()

    foreach ($service in $services) {
        $pathName = [string]$service.PathName
        if ($pathName -match '(?i)"([^"]*\\(?:httpd|apache)\.exe)"') {
            $exePath = $Matches[1]
        }
        elseif ($pathName -match '(?i)(\S*\\(?:httpd|apache)\.exe)') {
            $exePath = $Matches[1]
        }
        else {
            $exePath = $null
        }

        if ($exePath -and (Test-Path -LiteralPath $exePath -PathType Leaf)) {
            try {
                $info = (Get-Item -LiteralPath $exePath).VersionInfo
                $versionEvidence.Add("$exePath => FileVersion=$($info.FileVersion); ProductVersion=$($info.ProductVersion)") | Out-Null
            }
            catch {
                $versionEvidence.Add("$exePath => version read failed: $($_.Exception.Message)") | Out-Null
            }
        }
    }

    if ($services.Count -eq 0 -and $configFiles.Count -eq 0 -and $versionEvidence.Count -eq 0) {
        $finalResult = "N/A"
        $status = "N/A"
        $summary = "Apache for Windows service/configuration was not found."
        $commandOutput = "No Apache service, known httpd.conf path, or Apache executable version evidence found."
        $commandExecuted = "Get-CimInstance Win32_Service; known Apache httpd.conf paths; executable version lookup"
    }
    else {
        $finalResult = "MANUAL"
        $status = "수동진단"
        $summary = "Apache version and patch policy require comparison with current vendor advisories and local patch management evidence."
        $commandOutput = (@(
            if ($services) { "Services:`n" + (($services | ForEach-Object { "$($_.Name) [$($_.State)] $($_.PathName)" }) -join "`n") }
            if ($configFiles) { "Config files:`n" + ($configFiles -join "`n") }
            if ($versionEvidence.Count -gt 0) { "Version evidence:`n" + ($versionEvidence -join "`n") }
            "Manual evidence required: Apache Lounge/ASF advisory comparison, OS/package inventory, and periodic patch policy."
        ) -join "`n`n")
        $commandExecuted = "Apache Windows service/config/version discovery; manual vendor advisory comparison required"
    }
}
catch {
    $finalResult = "MANUAL"
    $status = "수동진단"
    $summary = "Diagnostic execution failed; manual review required."
    $commandOutput = "Diagnostic execution failed: $($_.Exception.Message)"
    $commandExecuted = "Apache Windows version and patch evidence discovery"
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
