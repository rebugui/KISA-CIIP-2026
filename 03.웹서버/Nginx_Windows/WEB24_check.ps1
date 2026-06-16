# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Version: 1.0.1
# @Last Updated: 2026-05-24
# ============================================================================
# [Assessment Item]
# @ID          : WEB-24
# @Category    : 웹서비스>3.보안설정 별도의업로드경로사용및권한설정
# @Platform    : Nginx_Windows
# @Severity    : 중
# @Title       : 별도의 업로드 경로 사용 및 권한 설정
# @Description : docs/guideline_metadata.json and docs guidelines must be applied before final automation.
# @Reference   : docs/guideline_metadata.json and docs guideline Markdown
# ============================================================================

#Requires -Version 5.1

$ErrorActionPreference = 'Stop'
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\..\lib"
. "${LIB_DIR}\result_manager.ps1"
. "${SCRIPT_DIR}\nginx_windows_lib.ps1"

$ITEM_ID = "WEB-24"
$ITEM_NAME = "별도의 업로드 경로 사용 및 권한 설정"
$SEVERITY = "중"

$purpose = "웹 서버 루트 디렉터리 내 업로드 경로가 아닌 별도의 디렉터리에서 파일을 업로드할 수 있도록하여 루트 디렉터리 내 악의적인 파일 업로드 및 실행을 방지하기 위함"
$threat = "웹 서버 내 별도의 파일 업로드 경로 사용 및 적절한 권한 설정을 하지 않을 경우, 악의적인 목적을 가진 파일을 업로드하여 시스템 침투, 중요 정보 유출 및 변조 등의 침해 사고의 가능성이 있음"
$criteria_good = "별도의 업로드 경로를 사용하고 일반 사용자의 접근 권한이 부여되지 않은 경우"
$criteria_bad = "별도의 업로드 경로를 사용하지 않거나, 일반 사용자의 접근 권한이 부여된 경우"
$remediation = "기본 경로가 아닌 별도의 업로드 경로를 지정하고, 해당 경로에 대한 일반 사용자의 접근 권한을 제한하도록 설정"

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
        $roots = @((Get-NginxRootPaths -State $state) + (Get-NginxDefaultRootCandidates) | Select-Object -Unique)
        $uploadLines = @($state.ActiveLines | Where-Object {
            $_ -match '(?i)(upload|client_body_temp_path|dav_methods|create_full_put_path)'
        })
        $uploadPaths = [System.Collections.Generic.List[string]]::new()

        foreach ($line in $uploadLines) {
            if ($line -match '^(?i)(client_body_temp_path|alias|root)\s+(.+);$') {
                $path = Resolve-NginxConfiguredPath -Path $Matches[2] -ConfigFiles $state.ConfigFiles
                if ($path -and -not $uploadPaths.Contains($path)) {
                    $uploadPaths.Add($path) | Out-Null
                }
            }
        }

        $verifiedPaths = [System.Collections.Generic.List[string]]::new()
        $broadAcl = foreach ($path in $uploadPaths) {
            if (Test-Path -LiteralPath $path) {
                $verifiedPaths.Add($path) | Out-Null
                Get-NginxBroadAclEvidence -Path $path -Role 'UploadPath'
            }
        }
        $insideRoot = @($uploadPaths | Where-Object {
            $uploadPath = $_
            @($roots | Where-Object { $uploadPath.StartsWith($_, [System.StringComparison]::OrdinalIgnoreCase) }).Count -gt 0
        })

        $evidence = [System.Collections.Generic.List[string]]::new()
        $evidence.Add("Root paths: $($roots -join ', ')") | Out-Null
        $evidence.Add("Upload-related directives: $($uploadLines.Count)") | Out-Null
        foreach ($line in $uploadLines) { $evidence.Add($line) | Out-Null }
        $evidence.Add("Resolved upload paths: $($uploadPaths -join ', ')") | Out-Null
        if ($broadAcl) {
            $evidence.Add("Broad ACL evidence:") | Out-Null
            foreach ($entry in $broadAcl) {
                $evidence.Add("$($entry.Role): $($entry.Path) => $($entry.Principal) $($entry.Access) ($($entry.Rights))") | Out-Null
            }
        }

        $commandExecuted = "Parse Nginx upload-related directives and inspect upload path placement/ACLs"
        $commandOutput = ($evidence | Where-Object { $_ }) -join "`n"

        if ($uploadLines.Count -eq 0) {
            $finalResult = "MANUAL"
            $status = "수동진단"
            $summary = "No Nginx upload-specific directive was found. Confirm application upload paths and filesystem ACLs manually."
        }
        elseif ($insideRoot.Count -gt 0 -or @($broadAcl | Where-Object { $_.Access -eq 'Write' -or $_.Access -eq 'Read' }).Count -gt 0) {
            $finalResult = "VULNERABLE"
            $status = "취약"
            $summary = "Upload-related paths appear to be inside a web root or grant broad local-user read/write ACL access (general users can access the upload path)."
        }
        elseif (@($broadAcl | Where-Object { $_.Access -eq 'Unknown' }).Count -gt 0) {
            $finalResult = "MANUAL"
            $status = "수동진단"
            $summary = "Upload-path ACLs could not be read; inspect upload directory permissions manually (general users must not have access)."
        }
        elseif ($uploadPaths.Count -gt 0 -and $verifiedPaths.Count -gt 0) {
            $finalResult = "GOOD"
            $status = "양호"
            $summary = "Detected Nginx upload-related paths are outside resolved web roots and no broad write ACL evidence was found."
        }
        elseif ($uploadPaths.Count -gt 0) {
            # Upload paths resolved outside the web root, but none of them exist
            # or are readable on the scan host, so their NTFS ACLs were never
            # inspected. The criteria require BOTH a separate path AND general
            # users lacking access; with the second conjunct unverifiable we
            # cannot conclude GOOD (mirrors the Linux sibling's "GOOD로 단정 불가").
            $finalResult = "MANUAL"
            $status = "수동진단"
            $summary = "Upload-related paths resolved outside the web root, but the directories do not exist or are not readable on this host, so their NTFS ACLs could not be inspected. Manually verify the upload directory's permissions (general users must not have access)."
        }
        else {
            $finalResult = "MANUAL"
            $status = "수동진단"
            $summary = "Upload-related directives were found, but upload storage paths could not be resolved automatically."
        }
    }
}
catch {
    $finalResult = "MANUAL"
    $status = "수동진단"
    $summary = "Diagnostic execution failed; manual review required."
    $commandOutput = "Diagnostic execution failed: $($_.Exception.Message)"
    $commandExecuted = "Nginx Windows upload path discovery"
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
