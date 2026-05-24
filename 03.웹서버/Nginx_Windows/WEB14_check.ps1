# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Version: 1.0.1
# @Last Updated: 2026-05-24
# ============================================================================
# [Assessment Item]
# @ID          : WEB-14
# @Category    : 웹서비스>2.서비스관리
# @Platform    : Nginx_Windows
# @Severity    : 상
# @Title       : 웹 서비스 경로 내 파일의 접근 통제
# @Description : docs/guideline_metadata.json and docs guidelines must be applied before final automation.
# @Reference   : docs/guideline_metadata.json and docs guideline Markdown
# ============================================================================

#Requires -Version 5.1

$ErrorActionPreference = 'Stop'
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\..\lib"
. "${LIB_DIR}\result_manager.ps1"
. "${SCRIPT_DIR}\nginx_windows_lib.ps1"

$ITEM_ID = "WEB-14"
$ITEM_NAME = "웹 서비스 경로 내 파일의 접근 통제"
$SEVERITY = "상"

$purpose = "웹 서비스 경로의 파일들에 관리자를 제외한 일반 사용자의 파일 접근 권한을 제거함으로써 인가되지 않은 사용자가 허용되지 않는 파일에 접근하는 것을 차단하기 위함"
$threat = "웹 서비스 경로 파일에 비인가자가 접근 가능한 경우, 해당 파일의 수정 및 삭제로 인해 웹 서비스 운영 장애 및 계정 비밀번호 정보 등의 중요한 정보가 노출될 위험이 존재함"
$criteria_good = "주요 설정 파일 및 디렉터리에 불필요한 접근 권한이 부여되지 않은 경우"
$criteria_bad = "주요 설정 파일 및 디렉터리에 불필요한 접근 권한이 부여된 경우"
$remediation = "주요 설정 파일 및 디렉터리에 불필요한 접근 권한 제거 설정"

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
        $summary = "Nginx was found, but configuration files were not found for ACL inspection."
        $commandOutput = Get-NginxWindowsProcessEvidence -State $state
        $commandExecuted = "Discover Nginx Windows process/service configuration paths"
    }
    else {
        $assessedPaths = [System.Collections.Generic.List[object]]::new()
        foreach ($file in @($state.Config.Files)) {
            $assessedPaths.Add([pscustomobject]@{ Path = $file; Role = 'ConfigFile' }) | Out-Null
            $dir = Split-Path -Parent $file
            if ($dir -and -not ($assessedPaths | Where-Object { $_.Path -eq $dir -and $_.Role -eq 'ConfigDirectory' })) {
                $assessedPaths.Add([pscustomobject]@{ Path = $dir; Role = 'ConfigDirectory' }) | Out-Null
            }
        }
        foreach ($root in @((Get-NginxRootPaths -State $state) + (Get-NginxDefaultRootCandidates) | Select-Object -Unique)) {
            if (Test-Path -LiteralPath $root) {
                $assessedPaths.Add([pscustomobject]@{ Path = $root; Role = 'DocumentRoot' }) | Out-Null
            }
        }

        $aclEvidence = foreach ($pathInfo in $assessedPaths) {
            Get-NginxBroadAclEvidence -Path $pathInfo.Path -Role $pathInfo.Role
        }
        $vulnerableEvidence = @($aclEvidence | Where-Object {
            $_.Access -eq 'Unknown' -or
            $_.Access -eq 'Write' -or
            (($_.Role -eq 'ConfigFile' -or $_.Role -eq 'ConfigDirectory') -and $_.Access -eq 'Read')
        })
        $manualEvidence = @($aclEvidence | Where-Object {
            $_.Role -eq 'DocumentRoot' -and $_.Access -eq 'Read'
        })

        $commandExecuted = "Get-Acl on Nginx config files, config directories, and resolved root directories"
        $commandOutput = if ($aclEvidence) {
            ($aclEvidence | ForEach-Object { "$($_.Role): $($_.Path) => $($_.Principal) $($_.Access) ($($_.Rights))" }) -join "`n"
        }
        else {
            "No broad Everyone/Users/Authenticated Users/Guests/Domain Users ACL entries found on assessed Nginx paths."
        }

        if ($vulnerableEvidence.Count -gt 0) {
            $finalResult = "VULNERABLE"
            $status = "취약"
            $summary = "Broad local user access was found on Nginx configuration or web service paths."
        }
        elseif ($manualEvidence.Count -gt 0) {
            $finalResult = "MANUAL"
            $status = "수동진단"
            $summary = "Nginx web root has broad read access; confirm whether this is required and whether sensitive files are excluded."
        }
        else {
            $finalResult = "GOOD"
            $status = "양호"
            $summary = "No unnecessary broad local user ACLs were found on Nginx configuration files, configuration directories, or resolved web root directories."
        }
    }
}
catch {
    $finalResult = "MANUAL"
    $status = "수동진단"
    $summary = "Diagnostic execution failed; manual review required."
    $commandOutput = "Diagnostic execution failed: $($_.Exception.Message)"
    $commandExecuted = "Nginx Windows ACL discovery"
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
