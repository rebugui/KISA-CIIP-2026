#Requires -Version 5.1

function Add-CubridUniquePath {
    param([System.Collections.Generic.List[string]]$Paths, [string]$Candidate, [string]$PathType = 'Any')
    if ([string]::IsNullOrWhiteSpace($Candidate)) { return }
    try { $resolved = [System.IO.Path]::GetFullPath($Candidate.Trim('"')) } catch { return }
    $exists = switch ($PathType) {
        'Leaf' { Test-Path -LiteralPath $resolved -PathType Leaf }
        'Container' { Test-Path -LiteralPath $resolved -PathType Container }
        default { Test-Path -LiteralPath $resolved }
    }
    if ($exists -and -not $Paths.Contains($resolved)) { $Paths.Add($resolved) | Out-Null }
}

function Get-CubridWindowsServices {
    try {
        @(Get-CimInstance Win32_Service -ErrorAction Stop | Where-Object {
            $_.Name -match '(?i)cubrid' -or $_.DisplayName -match '(?i)cubrid'
        })
    } catch { @() }
}

function Get-CubridWindowsProcesses {
    try {
        @(Get-CimInstance Win32_Process -ErrorAction Stop | Where-Object {
            $_.Name -match '(?i)^(cub_master|cub_broker|cub_server|cub_manager|csql|cubrid|cubrid_rel)\.exe$'
        })
    } catch { @() }
}

function Get-CubridCommandPath {
    param([string[]]$Names)
    foreach ($name in $Names) {
        $found = Get-Command $name -ErrorAction SilentlyContinue
        if ($found) { return $found.Source }
    }
    foreach ($root in @($env:CUBRID, $env:ProgramFiles, ${env:ProgramFiles(x86)}, 'C:\CUBRID')) {
        if ([string]::IsNullOrWhiteSpace($root) -or -not (Test-Path -LiteralPath $root -PathType Container)) { continue }
        foreach ($name in $Names) {
            $candidate = Get-ChildItem -LiteralPath $root -Recurse -File -Filter $name -ErrorAction SilentlyContinue |
                Where-Object { $_.FullName -match '(?i)\\bin\\' } |
                Select-Object -First 1
            if ($candidate) { return $candidate.FullName }
        }
    }
    return $null
}

function Get-CubridWindowsState {
    $services = @(Get-CubridWindowsServices)
    $processes = @(Get-CubridWindowsProcesses)
    $homes = [System.Collections.Generic.List[string]]::new()
    Add-CubridUniquePath -Paths $homes -Candidate $env:CUBRID -PathType Container
    foreach ($obj in @($services + $processes)) {
        $cmd = if ($obj.PathName) { [string]$obj.PathName } else { [string]$obj.CommandLine }
        if ($cmd -match '(?i)"([^"]*\\bin\\(?:cub_master|cub_broker|cub_server|csql|cubrid|cubrid_rel)\.exe)"') {
            Add-CubridUniquePath -Paths $homes -Candidate (Split-Path -Parent (Split-Path -Parent $Matches[1])) -PathType Container
        }
        elseif ($cmd -match '(?i)(\S*\\bin\\(?:cub_master|cub_broker|cub_server|csql|cubrid|cubrid_rel)\.exe)') {
            Add-CubridUniquePath -Paths $homes -Candidate (Split-Path -Parent (Split-Path -Parent $Matches[1])) -PathType Container
        }
    }

    $configs = [System.Collections.Generic.List[string]]::new()
    foreach ($home in $homes) {
        foreach ($candidate in @(
            (Join-Path $home 'conf\cubrid.conf'),
            (Join-Path $home 'conf\cubrid_broker.conf'),
            (Join-Path $home 'conf\databases.txt'),
            (Join-Path $home 'databases\databases.txt')
        )) {
            Add-CubridUniquePath -Paths $configs -Candidate $candidate -PathType Leaf
        }
    }

    $installedEvidence = ($services.Count -gt 0 -or $processes.Count -gt 0 -or $homes.Count -gt 0)
    [pscustomobject]@{
        Services = $services
        Processes = $processes
        CubridHomes = @($homes)
        ConfigFiles = @($configs)
        CsqlPath = if ($installedEvidence) { Get-CubridCommandPath -Names @('csql.exe', 'csql') } else { $null }
        RelPath = if ($installedEvidence) { Get-CubridCommandPath -Names @('cubrid_rel.exe', 'cubrid_rel') } else { $null }
        Installed = $installedEvidence
    }
}

function Get-CubridWindowsEvidence {
    param($State)
    @(
        $State.Services | ForEach-Object { "Service $($_.Name) [$($_.State)] $($_.StartName): $($_.PathName)" }
        $State.Processes | ForEach-Object { "Process $($_.ProcessId): $($_.CommandLine)" }
        if ($State.CubridHomes.Count -gt 0) { "CubridHomes: $($State.CubridHomes -join ', ')" }
        if ($State.ConfigFiles.Count -gt 0) { "ConfigFiles: $($State.ConfigFiles -join ', ')" }
        if ($State.CsqlPath) { "CsqlPath: $($State.CsqlPath)" }
        if ($State.RelPath) { "RelPath: $($State.RelPath)" }
    ) -join "`n"
}

function New-CubridResult {
    param([string]$FinalResult, [string]$Summary, [string]$CommandOutput, [string]$CommandExecuted)
    $status = switch ($FinalResult) {
        'GOOD' { '양호' }
        'VULNERABLE' { '취약' }
        'N/A' { 'N/A' }
        default { '수동진단' }
    }
    [pscustomobject]@{ FinalResult = $FinalResult; Status = $status; Summary = $Summary; CommandOutput = $CommandOutput; CommandExecuted = $CommandExecuted }
}

function New-CubridNotInstalledResult {
    New-CubridResult 'N/A' 'CUBRID for Windows service/process/home evidence was not found.' 'No CUBRID service, cub_master.exe/cub_broker.exe process, or CUBRID home evidence found.' 'Get-CimInstance Win32_Service/Win32_Process; inspect CUBRID env'
}

function Invoke-CubridQuery {
    param($State, [string]$Query)
    if (-not $State.CsqlPath) {
        return [pscustomobject]@{ Ok = $false; Output = 'csql.exe client was not found.'; Command = 'csql client discovery' }
    }
    $database = if ($env:DB_NAME) { $env:DB_NAME } elseif ($env:CUBRID_DB) { $env:CUBRID_DB } else { 'demodb' }
    $user = if ($env:DB_USER) { $env:DB_USER } elseif ($env:CUBRID_USER) { $env:CUBRID_USER } else { 'dba' }
    $args = @('-u', $user)
    if ($env:DB_PASSWORD -or $env:CUBRID_PASSWORD) {
        $password = if ($env:DB_PASSWORD) { $env:DB_PASSWORD } else { $env:CUBRID_PASSWORD }
        $args += @('-p', $password)
    }
    $args += @('-c', $Query, $database)
    $output = & $State.CsqlPath @args 2>&1
    $exit = $LASTEXITCODE
    $text = (($output | Out-String).Trim())
    $ok = ($exit -eq 0 -and $text -notmatch '(?i)ERROR|failed|Cannot connect')
    [pscustomobject]@{ Ok = $ok; Output = $text; Command = "$($State.CsqlPath) -u $user -c <query> $database" }
}

function Invoke-CubridSqlCheck {
    param($State, [string]$Query, [scriptblock]$Judge, [string]$Description)
    $result = Invoke-CubridQuery -State $State -Query $Query
    if (-not $result.Ok) {
        return New-CubridResult 'MANUAL' "CUBRID was found, but SQL evidence for $Description could not be collected automatically." ("Discovery evidence:`n$(Get-CubridWindowsEvidence -State $State)`n`nSQL output:`n$($result.Output)") $result.Command
    }
    & $Judge $result
}

function Get-CubridConfigLines {
    param($State, [string]$Pattern)
    foreach ($file in $State.ConfigFiles) {
        $lines = @(Select-String -LiteralPath $file -Pattern $Pattern -ErrorAction SilentlyContinue)
        foreach ($line in $lines) { "${file}:$($line.LineNumber): $($line.Line.Trim())" }
    }
}

function Test-CubridBroadPrincipal {
    param([System.Security.Principal.IdentityReference]$Identity)
    try { $sid = $Identity.Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { $sid = [string]$Identity }
    return ($sid -eq 'S-1-1-0') -or ($sid -eq 'S-1-5-11') -or ($sid -eq 'S-1-5-32-545') -or ($sid -eq 'S-1-5-32-546') -or ($sid -match '-513$') -or (([string]$Identity) -match '(?i)Everyone|Authenticated Users|BUILTIN\\Users|Guests|Domain Users')
}

function Get-CubridBroadAclEvidence {
    param([string]$Path, [string]$Role)
    $writeRights = @([System.Security.AccessControl.FileSystemRights]::FullControl, [System.Security.AccessControl.FileSystemRights]::Modify, [System.Security.AccessControl.FileSystemRights]::Write, [System.Security.AccessControl.FileSystemRights]::WriteData, [System.Security.AccessControl.FileSystemRights]::AppendData, [System.Security.AccessControl.FileSystemRights]::CreateFiles, [System.Security.AccessControl.FileSystemRights]::CreateDirectories, [System.Security.AccessControl.FileSystemRights]::Delete, [System.Security.AccessControl.FileSystemRights]::ChangePermissions, [System.Security.AccessControl.FileSystemRights]::TakeOwnership)
    try { $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop } catch { return [pscustomobject]@{ Path = $Path; Role = $Role; Access = 'Unknown'; Principal = 'N/A'; Rights = "ACL read failed: $($_.Exception.Message)" } }
    foreach ($rule in $acl.Access) {
        if ($rule.AccessControlType -ne 'Allow' -or -not (Test-CubridBroadPrincipal -Identity $rule.IdentityReference)) { continue }
        foreach ($right in $writeRights) {
            if (($rule.FileSystemRights -band $right) -eq $right) {
                [pscustomobject]@{ Path = $Path; Role = $Role; Access = 'Write'; Principal = [string]$rule.IdentityReference; Rights = [string]$rule.FileSystemRights }
                break
            }
        }
    }
}

function Get-CubridLocalAdminMemberSids {
    try {
        $group = [ADSI]"WinNT://./Administrators,group"
        $members = @($group.Invoke('Members'))
        $sids = foreach ($m in $members) {
            try {
                $bytes = $m.GetType().InvokeMember('objectSid', 'GetProperty', $null, $m, $null)
                (New-Object System.Security.Principal.SecurityIdentifier($bytes, 0)).Value
            } catch { }
        }
        return @($sids | Where-Object { $_ })
    } catch { return $null }
}

function Test-CubridServiceAccountAdmin {
    param([string]$Account)
    # Well-known administrator-equivalent service identities (always VULNERABLE).
    if ($Account -match '^(?i)\s*(\.\\)?(LocalSystem|NT AUTHORITY\\SYSTEM|NT AUTHORITY\\System|System)\s*$') {
        return [pscustomobject]@{ Account = $Account; Admin = $true; Resolved = $true; Detail = "$Account is the LocalSystem account" }
    }
    # Resolve the StartName to a SID. Normalize '.\name' to the local computer principal.
    $normalized = $Account
    if ($normalized -match '^\.\\(.+)$') { $normalized = "$env:COMPUTERNAME\$($Matches[1])" }
    elseif ($normalized -notmatch '\\') { $normalized = "$env:COMPUTERNAME\$normalized" }
    $sid = $null
    try { $sid = (New-Object System.Security.Principal.NTAccount($normalized)).Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { $sid = $null }
    if (-not $sid) {
        return [pscustomobject]@{ Account = $Account; Admin = $false; Resolved = $false; Detail = "$Account could not be resolved to a SID" }
    }
    # The built-in Administrator account and the local Administrators group itself are admin-equivalent.
    if ($sid -eq 'S-1-5-32-544' -or $sid -match '-500$') {
        return [pscustomobject]@{ Account = $Account; Admin = $true; Resolved = $true; Detail = "$Account ($sid) is a built-in administrator principal" }
    }
    $adminSids = Get-CubridLocalAdminMemberSids
    if ($null -eq $adminSids) {
        return [pscustomobject]@{ Account = $Account; Admin = $false; Resolved = $false; Detail = "$Account ($sid) resolved, but local Administrators membership could not be enumerated" }
    }
    if ($adminSids -contains $sid) {
        return [pscustomobject]@{ Account = $Account; Admin = $true; Resolved = $true; Detail = "$Account ($sid) is a member of the local Administrators group" }
    }
    return [pscustomobject]@{ Account = $Account; Admin = $false; Resolved = $true; Detail = "$Account ($sid) is not a member of the local Administrators group" }
}

function Invoke-CubridWindowsCheck {
    param([string]$ItemId, [string]$ItemName)
    $state = Get-CubridWindowsState
    if (-not $state.Installed) { return New-CubridNotInstalledResult }
    $evidence = Get-CubridWindowsEvidence -State $state

    switch ($ItemId) {
        'D-01' { return Invoke-CubridSqlCheck $state "SELECT name, password FROM db_user;" { param($r) if ($r.Output -match '(?im)^dba\s+($|NULL|\s*$)') { New-CubridResult 'VULNERABLE' 'CUBRID DBA/default account appears to have an empty password.' $r.Output $r.Command } elseif ($r.Output -match '(?m)\S') { New-CubridResult 'MANUAL' 'CUBRID user password evidence was collected; confirm default account password policy.' $r.Output $r.Command } else { New-CubridResult 'MANUAL' 'No CUBRID user rows were returned.' 'No rows returned.' $r.Command } } 'default account password policy' }
        'D-02' { return Invoke-CubridSqlCheck $state "SELECT name FROM db_user WHERE name IN ('public','dba','test','demo') OR name LIKE 'test%';" { param($r) if ($r.Output -match '(?im)^(test|demo)') { New-CubridResult 'VULNERABLE' 'Unnecessary CUBRID sample/test accounts were found.' $r.Output $r.Command } elseif ($r.Output -match '(?m)\S') { New-CubridResult 'MANUAL' 'CUBRID default/public accounts exist; confirm only required accounts remain.' $r.Output $r.Command } else { New-CubridResult 'MANUAL' 'No CUBRID accounts matched the sample/test name filter; review the full account list to confirm no unnecessary (e.g. demonstration or retiree) accounts remain.' 'No rows returned.' $r.Command } } 'unnecessary account removal' }
        'D-03' { return New-CubridResult 'N/A' 'Password lifetime and complexity item is not explicitly targeted to CUBRID in the guideline metadata.' 'D-03 target excludes CUBRID.' 'Map DBMS password-policy guideline applicability' }
        'D-04' { return Invoke-CubridSqlCheck $state "SELECT a.name FROM db_user a, table(direct_groups) AS t(roles) WHERE roles.name = 'DBA';" { param($r) if ($r.Output -match '(?m)\S') { New-CubridResult 'MANUAL' 'CUBRID DBA-group membership was collected; confirm only required accounts hold DBA privilege.' $r.Output $r.Command } else { New-CubridResult 'MANUAL' 'No CUBRID DBA-group membership rows were returned; manually confirm DBA privilege is restricted to required accounts.' 'No rows returned.' $r.Command } } 'administrator privilege restriction' }
        'D-05' { return New-CubridResult 'N/A' 'Password reuse item is not explicitly targeted to CUBRID in the guideline metadata.' 'D-05 target excludes CUBRID.' 'Map DBMS password-reuse guideline applicability' }
        'D-06' { return New-CubridResult 'N/A' 'Individual DB account assignment item is not explicitly targeted to CUBRID in the guideline metadata.' 'D-06 target excludes CUBRID.' 'Map DBMS account-assignment guideline applicability' }
        'D-07' { $accounts = @($state.Services | ForEach-Object { $_.StartName } | Where-Object { $_ }); if ($accounts.Count -eq 0) { return New-CubridResult 'MANUAL' 'CUBRID service account could not be determined.' $evidence 'Inspect CUBRID Windows service StartName' }; $assessed = @($accounts | ForEach-Object { Test-CubridServiceAccountAdmin -Account $_ }); $detail = ($assessed | ForEach-Object { $_.Detail }) -join '; '; if (@($assessed | Where-Object { $_.Admin }).Count -gt 0) { return New-CubridResult 'VULNERABLE' 'CUBRID Windows service runs as an administrator-equivalent account (LocalSystem or local Administrators member).' $detail 'Resolve CUBRID service StartName SID and expand local Administrators membership' }; if (@($assessed | Where-Object { -not $_.Resolved }).Count -gt 0) { return New-CubridResult 'MANUAL' 'CUBRID Windows service account administrator-equivalence could not be resolved; verify the account is not a local Administrators member.' $detail 'Resolve CUBRID service StartName SID and expand local Administrators membership' }; return New-CubridResult 'GOOD' 'CUBRID Windows service account is not administrator-equivalent.' $detail 'Resolve CUBRID service StartName SID and expand local Administrators membership' }
        'D-08' { return New-CubridResult 'N/A' 'Transport encryption item is not explicitly targeted to CUBRID in the guideline metadata.' 'D-08 target excludes CUBRID.' 'Map DBMS encryption guideline applicability' }
        'D-09' { return New-CubridResult 'N/A' 'Failed-login lockout item is not explicitly targeted to CUBRID in the guideline metadata.' 'D-09 target excludes CUBRID.' 'Map DBMS lockout guideline applicability' }
        'D-10' { return New-CubridResult 'N/A' 'Remote DB access restriction item is not explicitly targeted to CUBRID in the guideline metadata.' 'D-10 target excludes CUBRID.' 'Map DBMS remote-access guideline applicability' }
        'D-11' { return New-CubridResult 'N/A' 'System table access restriction item is not explicitly targeted to CUBRID in the guideline metadata.' 'D-11 target excludes CUBRID.' 'Map DBMS system-table guideline applicability' }
        'D-12' { return New-CubridResult 'N/A' 'Oracle listener password control is not applicable to CUBRID.' 'CUBRID does not expose Oracle Listener password semantics.' 'Map DBMS listener-password guideline applicability' }
        'D-13' { return New-CubridResult 'N/A' 'Unnecessary ODBC/OLE-DB driver cleanup item is not explicitly targeted to CUBRID in the guideline metadata.' 'D-13 target excludes CUBRID.' 'Map DBMS ODBC guideline applicability' }
        'D-14' { $targets = @($state.CubridHomes + $state.ConfigFiles | Select-Object -Unique); $acl = @(foreach ($path in $targets) { Get-CubridBroadAclEvidence -Path $path -Role 'CubridPath' }); $writeRows = @($acl | Where-Object { $_.Access -eq 'Write' }); $unknownRows = @($acl | Where-Object { $_.Access -eq 'Unknown' }); if ($writeRows.Count -gt 0) { return New-CubridResult 'VULNERABLE' 'Broad local write ACL evidence was found on CUBRID paths.' (($writeRows | ForEach-Object { "$($_.Path) => $($_.Principal) $($_.Access) ($($_.Rights))" }) -join "`n") 'Get-Acl CUBRID directories/files' }; if ($unknownRows.Count -gt 0) { return New-CubridResult 'MANUAL' 'CUBRID path ACLs could not be read (insufficient privilege or hardened ACL); manually verify no broad-write ACEs exist.' (($unknownRows | ForEach-Object { "$($_.Path) => $($_.Rights)" }) -join "`n") 'Get-Acl CUBRID directories/files' }; if ($targets.Count -eq 0) { return New-CubridResult 'MANUAL' 'CUBRID paths were not found for ACL assessment.' $evidence 'Get-Acl CUBRID directories/files' }; return New-CubridResult 'GOOD' 'No broad local write ACL entries were found on assessed CUBRID paths.' ($targets -join ', ') 'Get-Acl CUBRID directories/files' }
        'D-15' { return New-CubridResult 'N/A' 'Oracle listener log/trace modification control is not applicable to CUBRID.' 'CUBRID does not expose Oracle Listener log/trace semantics.' 'Map DBMS listener-log guideline applicability' }
        'D-16' { return New-CubridResult 'N/A' 'SQL Server Windows authentication mode control is not applicable to CUBRID.' 'CUBRID authentication is controlled by CUBRID users and service configuration.' 'Map DBMS authentication-mode guideline applicability' }
        'D-17' { return New-CubridResult 'N/A' 'AuditTable DBA-only access item is not explicitly targeted to CUBRID in the guideline metadata.' 'D-17 target excludes CUBRID.' 'Map DBMS audit-table guideline applicability' }
        'D-18' { return Invoke-CubridSqlCheck $state "SELECT g.grantee_name, g.object_name, g.privilege_type FROM db_auth g WHERE g.grantee_name='PUBLIC';" { param($r) if ($r.Output -match '(?im)PUBLIC') { New-CubridResult 'MANUAL' 'CUBRID privileges granted to PUBLIC were detected; manually confirm no application/DBA role or table privilege is granted to the PUBLIC group.' $r.Output $r.Command } else { New-CubridResult 'MANUAL' 'PUBLIC grant evidence could not be confirmed automatically; manually verify that no application/DBA role is assigned to the PUBLIC group via the CUBRID grant catalog.' $r.Output $r.Command } } 'public role restriction' }
        'D-19' { return New-CubridResult 'N/A' 'Oracle OS role parameters are not applicable to CUBRID.' 'CUBRID does not expose Oracle OS_ROLES/REMOTE_OS_AUTHENTICATION/REMOTE_OS_ROLES parameters.' 'Map Oracle OS role guideline applicability' }
        'D-20' { return New-CubridResult 'N/A' 'Unauthorized object owner item is not explicitly targeted to CUBRID in the guideline metadata.' 'D-20 target excludes CUBRID.' 'Map DBMS object-owner guideline applicability' }
        'D-21' { return New-CubridResult 'N/A' 'GRANT OPTION restriction item is not explicitly targeted to CUBRID in the guideline metadata.' 'D-21 target excludes CUBRID.' 'Map DBMS grant-option guideline applicability' }
        'D-22' { return New-CubridResult 'N/A' 'Resource limit item is not explicitly targeted to CUBRID in the guideline metadata.' 'D-22 target excludes CUBRID.' 'Map DBMS resource-limit guideline applicability' }
        'D-23' { return New-CubridResult 'N/A' 'SQL Server xp_cmdshell control is not applicable to CUBRID.' 'CUBRID has no xp_cmdshell feature.' 'Map DBMS command-shell guideline applicability' }
        'D-24' { return New-CubridResult 'N/A' 'SQL Server registry extended procedure control is not applicable to CUBRID.' 'CUBRID does not expose SQL Server registry extended procedures.' 'Map DBMS registry-procedure guideline applicability' }
        'D-25' { if ($state.RelPath) { $output = & $state.RelPath 2>&1 | Out-String; return New-CubridResult 'MANUAL' 'CUBRID was found. Compare detected version and patch level against current CUBRID release notes.' $output "$($state.RelPath)" }; return New-CubridResult 'MANUAL' 'CUBRID was found, but cubrid_rel.exe was not found. Confirm version and patch level manually.' $evidence 'cubrid_rel discovery' }
        'D-26' { return New-CubridResult 'N/A' 'Audit logging item is not explicitly targeted to CUBRID in the guideline metadata.' 'D-26 target excludes CUBRID.' 'Map DBMS audit guideline applicability' }
        default { return New-CubridResult 'MANUAL' "No CUBRID Windows diagnostic rule is defined for $ItemId." $evidence 'CUBRID Windows generic discovery' }
    }
}
