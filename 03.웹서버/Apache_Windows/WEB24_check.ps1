# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Version: 1.0.1
# @Last Updated: 2026-05-24
# ============================================================================
# [Assessment Item]
# @ID          : WEB-24
# @Category    : 웹서비스>3.보안설정 별도의업로드경로사용및권한설정
# @Platform    : Apache_Windows
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
. "${SCRIPT_DIR}\apache_windows_lib.ps1"

$ITEM_ID = "WEB-24"
$ITEM_NAME = "별도의 업로드 경로 사용 및 권한 설정"
$SEVERITY = "중"

$purpose = "웹 서버 루트 디렉터리 내 업로드 경로가 아닌 별도의 디렉터리에서 파일을 업로드할 수 있도록하여 루트 디렉터리 내 악의적인 파일 업로드 및 실행을 방지하기 위함"
$threat = "웹 서버 내 별도의 파일 업로드 경로 사용 및 적절한 권한 설정을 하지 않을 경우, 악의적인 목적을 가진 파일을 업로드하여 시스템 침투, 중요 정보 유출 및 변조 등의 침해 사고의 가능성이 있음"
$criteria_good = "별도의 업로드 경로를 사용하고 일반 사용자의 접근 권한이 부여되지 않은 경우"
$criteria_bad = "별도의 업로드 경로를 사용하지 않거나, 일반 사용자의 접근 권한이 부여된 경우"
$remediation = "기본 경로가 아닌 별도의 업로드 경로를 지정하고, 해당 경로에 대한 일반 사용자의 접근 권한을 제한하도록 설정"

function Test-BroadUploadPrincipal {
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

function Test-UploadWriteRight {
    param([System.Security.AccessControl.FileSystemRights]$Rights)
    $writeRights = @(
        [System.Security.AccessControl.FileSystemRights]::FullControl,
        [System.Security.AccessControl.FileSystemRights]::Modify,
        [System.Security.AccessControl.FileSystemRights]::Write,
        [System.Security.AccessControl.FileSystemRights]::WriteData,
        [System.Security.AccessControl.FileSystemRights]::AppendData,
        [System.Security.AccessControl.FileSystemRights]::CreateFiles,
        [System.Security.AccessControl.FileSystemRights]::CreateDirectories
    )
    foreach ($right in $writeRights) {
        if (($Rights -band $right) -eq $right) {
            return $true
        }
    }
    return $false
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
        $summary = "Apache service exists, but configuration files were not found for upload path inspection."
        $commandOutput = ($services | ForEach-Object { "$($_.Name) [$($_.State)] $($_.PathName)" }) -join "`n"
        $commandExecuted = "Get-CimInstance Win32_Service; known Apache httpd.conf paths"
    }
    else {
        $config = Get-ApacheWindowsConfigText -ConfigFiles $configFiles
        $activeLines = @($config.Text -split "`r?`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ -and $_ -notmatch '^#' })
        $docRoots = @($activeLines | ForEach-Object {
            if ($_ -match '^(?i)DocumentRoot\s+"?([^"#]+?)"?\s*$') { $Matches[1].Trim().Trim('"').Replace('/', '\') }
        } | Where-Object { $_ })
        $uploadMappings = @($activeLines | Where-Object {
            $_ -match '^(?i)(Alias|AliasMatch)\s+["'']?[^"''\s]*upload[^"''\s]*["'']?\s+' -or
            $_ -match '(?i)upload'
        })
        $uploadPaths = @($uploadMappings | ForEach-Object {
            if ($_ -match '^(?i)(Alias|AliasMatch)\s+\S+\s+"?([^"]+)"?') { $Matches[2].Trim().Trim('"').Replace('/', '\') }
        } | Where-Object { $_ -and (Test-Path -LiteralPath $_ -PathType Container) } | Sort-Object -Unique)
        $docRootUpload = @($uploadPaths | Where-Object {
            $p = $_
            @($docRoots | Where-Object { $p.StartsWith($_, [System.StringComparison]::OrdinalIgnoreCase) }).Count -gt 0
        })

        $aclEvidence = foreach ($path in $uploadPaths) {
            try {
                $acl = Get-Acl -LiteralPath $path -ErrorAction Stop
                foreach ($rule in $acl.Access) {
                    if ($rule.AccessControlType -eq 'Allow' -and (Test-BroadUploadPrincipal -Identity $rule.IdentityReference) -and (Test-UploadWriteRight -Rights $rule.FileSystemRights)) {
                        "$path => $($rule.IdentityReference) $($rule.FileSystemRights)"
                    }
                }
            }
            catch {
                "$path => ACL read failed: $($_.Exception.Message)"
            }
        }

        $commandExecuted = "Parse upload-related Apache Alias/config lines and inspect upload directory ACLs"
        $commandOutput = (@(
            if ($docRoots) { "DocumentRoot:`n" + ($docRoots -join "`n") }
            if ($uploadMappings) { "Upload-related directives:`n" + ($uploadMappings -join "`n") }
            if ($uploadPaths) { "Resolved upload paths:`n" + ($uploadPaths -join "`n") }
            if ($aclEvidence) { "Broad write ACL evidence:`n" + ($aclEvidence -join "`n") }
            if (-not $uploadMappings) { "No upload-related Apache directives found." }
        ) -join "`n`n")

        if ($uploadMappings.Count -eq 0) {
            $finalResult = "MANUAL"
            $status = "수동진단"
            $summary = "No upload path was identified from Apache configuration; confirm application upload handling manually."
        }
        elseif ($docRootUpload.Count -gt 0 -or $aclEvidence.Count -gt 0) {
            $finalResult = "VULNERABLE"
            $status = "취약"
            $summary = "Upload path evidence indicates DocumentRoot placement or broad write permissions."
        }
        elseif ($uploadPaths.Count -gt 0) {
            $finalResult = "GOOD"
            $status = "양호"
            $summary = "Upload paths were found outside detected DocumentRoot paths and no broad write ACL evidence was found."
        }
        else {
            $finalResult = "MANUAL"
            $status = "수동진단"
            $summary = "Upload-related directives exist, but paths could not be resolved for ACL verification."
        }
    }
}
catch {
    $finalResult = "MANUAL"
    $status = "수동진단"
    $summary = "Diagnostic execution failed; manual review required."
    $commandOutput = "Diagnostic execution failed: $($_.Exception.Message)"
    $commandExecuted = "Apache Windows upload path discovery"
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
