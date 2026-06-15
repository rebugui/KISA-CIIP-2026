# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Version: 1.0.1
# @Last Updated: 2026-05-24
# ============================================================================
# [Assessment Item]
# @ID          : WEB-14
# @Category    : 웹서비스>2.서비스관리
# @Platform    : Apache_Windows
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
. "${SCRIPT_DIR}\apache_windows_lib.ps1"

$ITEM_ID = "WEB-14"
$ITEM_NAME = "웹 서비스 경로 내 파일의 접근 통제"
$SEVERITY = "상"

$purpose = "웹 서비스 경로의 파일들에 관리자를 제외한 일반 사용자의 파일 접근 권한을 제거함으로써 인가되지 않은 사용자가 허용되지 않는 파일에 접근하는 것을 차단하기 위함"
$threat = "웹 서비스 경로 파일에 비인가자가 접근 가능한 경우, 해당 파일의 수정 및 삭제로 인해 웹 서비스 운영 장애 및 계정 비밀번호 정보 등의 중요한 정보가 노출될 위험이 존재함"
$criteria_good = "주요 설정 파일 및 디렉터리에 불필요한 접근 권한이 부여되지 않은 경우"
$criteria_bad = "주요 설정 파일 및 디렉터리에 불필요한 접근 권한이 부여된 경우"
$remediation = "주요 설정 파일 및 디렉터리에 불필요한 접근 권한 제거 설정"

function Test-BroadPrincipal {
    param([System.Security.Principal.IdentityReference]$Identity)

    try {
        $sid = $Identity.Translate([System.Security.Principal.SecurityIdentifier]).Value
    }
    catch {
        $sid = [string]$Identity
    }

    return ($sid -eq 'S-1-1-0') -or ($sid -eq 'S-1-5-11') -or ($sid -eq 'S-1-5-32-545') -or ($sid -eq 'S-1-5-32-546') -or ($sid -match '-513$') -or (([string]$Identity) -match '(?i)Everyone|Authenticated Users|BUILTIN\\Users|Guests|Domain Users')
}

function Test-AnyRight {
    param(
        [System.Security.AccessControl.FileSystemRights]$Rights,
        [System.Security.AccessControl.FileSystemRights[]]$Expected
    )

    foreach ($right in $Expected) {
        if (($Rights -band $right) -eq $right) {
            return $true
        }
    }

    return $false
}

function Get-ApacheDocumentRoots {
    param([string]$ConfigText)

    $roots = [System.Collections.Generic.List[string]]::new()
    foreach ($line in ($ConfigText -split "`r?`n")) {
        $trimmed = $line.Trim()
        if ($trimmed -match '^#') {
            continue
        }

        if ($trimmed -match '^(?i)DocumentRoot\s+"?([^"#]+?)"?\s*$') {
            $candidate = $Matches[1].Trim().Replace('/', '\')
            if (Test-Path -LiteralPath $candidate -PathType Container) {
                try {
                    $resolved = [System.IO.Path]::GetFullPath($candidate)
                    if (-not $roots.Contains($resolved)) {
                        $roots.Add($resolved) | Out-Null
                    }
                }
                catch {
                    continue
                }
            }
        }
    }

    return @($roots)
}

function Get-BroadAclEvidence {
    param(
        [string]$Path,
        [string]$PathRole
    )

    $evidence = [System.Collections.Generic.List[object]]::new()
    $readRights = @(
        [System.Security.AccessControl.FileSystemRights]::Read,
        [System.Security.AccessControl.FileSystemRights]::ReadAndExecute,
        [System.Security.AccessControl.FileSystemRights]::ListDirectory
    )
    $writeRights = @(
        [System.Security.AccessControl.FileSystemRights]::FullControl,
        [System.Security.AccessControl.FileSystemRights]::Modify,
        [System.Security.AccessControl.FileSystemRights]::Write,
        [System.Security.AccessControl.FileSystemRights]::WriteData,
        [System.Security.AccessControl.FileSystemRights]::AppendData,
        [System.Security.AccessControl.FileSystemRights]::CreateFiles,
        [System.Security.AccessControl.FileSystemRights]::CreateDirectories,
        [System.Security.AccessControl.FileSystemRights]::Delete,
        [System.Security.AccessControl.FileSystemRights]::ChangePermissions,
        [System.Security.AccessControl.FileSystemRights]::TakeOwnership
    )

    try {
        $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
    }
    catch {
        return [pscustomobject]@{
            Path = $Path
            Role = $PathRole
            Access = 'Unknown'
            Principal = 'N/A'
            Rights = "ACL read failed: $($_.Exception.Message)"
        }
    }

    foreach ($rule in $acl.Access) {
        if ($rule.AccessControlType -ne 'Allow') {
            continue
        }
        if (-not (Test-BroadPrincipal -Identity $rule.IdentityReference)) {
            continue
        }

        $hasWrite = Test-AnyRight -Rights $rule.FileSystemRights -Expected $writeRights
        $hasRead = Test-AnyRight -Rights $rule.FileSystemRights -Expected $readRights
        if ($hasWrite -or $hasRead) {
            $evidence.Add([pscustomobject]@{
                Path = $Path
                Role = $PathRole
                Access = if ($hasWrite) { 'Write' } else { 'Read' }
                Principal = [string]$rule.IdentityReference
                Rights = [string]$rule.FileSystemRights
            }) | Out-Null
        }
    }

    return @($evidence)
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
        $summary = "Apache service exists, but configuration files were not found for ACL inspection."
        $commandOutput = ($services | ForEach-Object { "$($_.Name) [$($_.State)] $($_.PathName)" }) -join "`n"
        $commandExecuted = "Get-CimInstance Win32_Service; known Apache httpd.conf paths"
    }
    else {
        $config = Get-ApacheWindowsConfigText -ConfigFiles $configFiles
        $assessedPaths = [System.Collections.Generic.List[object]]::new()

        foreach ($file in @($config.Files)) {
            $assessedPaths.Add([pscustomobject]@{ Path = $file; Role = 'ConfigFile' }) | Out-Null
            $dir = Split-Path -Parent $file
            if ($dir -and -not ($assessedPaths | Where-Object { $_.Path -eq $dir -and $_.Role -eq 'ConfigDirectory' })) {
                $assessedPaths.Add([pscustomobject]@{ Path = $dir; Role = 'ConfigDirectory' }) | Out-Null
            }
        }

        $resolvedRoots = @(Get-ApacheDocumentRoots -ConfigText $config.Text)
        foreach ($root in $resolvedRoots) {
            $assessedPaths.Add([pscustomobject]@{ Path = $root; Role = 'DocumentRoot' }) | Out-Null
        }

        # 설정에 DocumentRoot가 선언되어 있으나 실제 경로를 확인(resolve)하지 못한 경우 추적.
        # (예: 환경변수/UNC 경로 → Test-Path 실패로 위 helper에서 제외됨) 웹 루트 ACL을
        # 점검하지 못하므로 양호로 단정하지 않고 수동진단으로 유도한다.
        $declaredRootCount = @(
            $config.Text -split "`r?`n" |
                ForEach-Object { $_.Trim() } |
                Where-Object { $_ -notmatch '^#' -and $_ -match '^(?i)DocumentRoot\s+"?([^"#]+?)"?\s*$' }
        ).Count
        $webRootUnresolved = ($declaredRootCount -gt 0 -and $resolvedRoots.Count -eq 0)

        $aclEvidence = foreach ($pathInfo in $assessedPaths) {
            Get-BroadAclEvidence -Path $pathInfo.Path -PathRole $pathInfo.Role
        }

        $vulnerableEvidence = @($aclEvidence | Where-Object {
            $_.Access -eq 'Unknown' -or
            $_.Access -eq 'Write' -or
            (($_.Role -eq 'ConfigFile' -or $_.Role -eq 'ConfigDirectory') -and $_.Access -eq 'Read')
        })
        $manualEvidence = @($aclEvidence | Where-Object {
            $_.Role -eq 'DocumentRoot' -and $_.Access -eq 'Read'
        })

        $commandExecuted = "Get-Acl on Apache config files, config directories, and DocumentRoot directories"
        $commandOutput = if ($aclEvidence) {
            ($aclEvidence | ForEach-Object { "$($_.Role): $($_.Path) => $($_.Principal) $($_.Access) ($($_.Rights))" }) -join "`n"
        }
        else {
            "No broad Everyone/Users/Authenticated Users/Guests/Domain Users ACL entries found on assessed Apache paths."
        }

        if ($vulnerableEvidence.Count -gt 0) {
            $finalResult = "VULNERABLE"
            $status = "취약"
            $summary = "Broad local user access was found on Apache configuration or web service paths."
        }
        elseif ($manualEvidence.Count -gt 0) {
            $finalResult = "MANUAL"
            $status = "수동진단"
            $summary = "DocumentRoot has broad read access; confirm whether this is required and whether sensitive files are excluded."
        }
        elseif ($webRootUnresolved) {
            # DocumentRoot는 선언되어 있으나 실제 경로를 확인하지 못해 웹 루트 ACL 미점검 → 양호 단정 불가
            $finalResult = "MANUAL"
            $status = "수동진단"
            $summary = "Apache DocumentRoot is declared but its path could not be resolved/accessed (environment variable/UNC). Manually verify ACLs on the web service path; configuration files were checked but the web root was not."
        }
        else {
            $finalResult = "GOOD"
            $status = "양호"
            $summary = "No unnecessary broad local user ACLs were found on Apache configuration files, configuration directories, or detected DocumentRoot directories."
        }
    }
}
catch {
    $finalResult = "MANUAL"
    $status = "수동진단"
    $summary = "Diagnostic execution failed; manual review required."
    $commandOutput = "Diagnostic execution failed: $($_.Exception.Message)"
    $commandExecuted = "Apache Windows ACL discovery"
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
