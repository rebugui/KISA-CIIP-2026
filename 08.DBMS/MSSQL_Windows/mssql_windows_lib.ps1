#Requires -Version 5.1

function Add-MsSqlUniquePath {
    param(
        [System.Collections.Generic.List[string]]$Paths,
        [string]$Candidate,
        [string]$PathType = 'Any'
    )
    if ([string]::IsNullOrWhiteSpace($Candidate)) { return }
    try { $resolved = [System.IO.Path]::GetFullPath($Candidate.Trim('"')) } catch { return }
    $exists = switch ($PathType) {
        'Leaf' { Test-Path -LiteralPath $resolved -PathType Leaf }
        'Container' { Test-Path -LiteralPath $resolved -PathType Container }
        default { Test-Path -LiteralPath $resolved }
    }
    if ($exists -and -not $Paths.Contains($resolved)) { $Paths.Add($resolved) | Out-Null }
}

function Get-MsSqlWindowsServices {
    try {
        @(Get-CimInstance Win32_Service -ErrorAction Stop | Where-Object {
            $_.Name -match '(?i)^(MSSQL|SQLAgent|SQLBrowser)' -or $_.DisplayName -match '(?i)SQL Server'
        })
    } catch { @() }
}

function Get-MsSqlWindowsProcesses {
    try {
        @(Get-CimInstance Win32_Process -ErrorAction Stop | Where-Object {
            $_.Name -match '(?i)^sqlservr\.exe$'
        })
    } catch { @() }
}

function Test-MsSqlEngineService {
    param($Service)
    if (-not $Service -or [string]::IsNullOrWhiteSpace($Service.Name)) { return $false }
    return ($Service.Name -match '(?i)^MSSQLSERVER$|^MSSQL\$.+')
}

function Get-MsSqlCliPath {
    foreach ($cmd in @('sqlcmd.exe', 'sqlcmd')) {
        $found = Get-Command $cmd -ErrorAction SilentlyContinue
        if ($found) { return $found.Source }
    }
    foreach ($root in @($env:ProgramFiles, ${env:ProgramFiles(x86)}, 'C:\Program Files\Microsoft SQL Server')) {
        if ([string]::IsNullOrWhiteSpace($root) -or -not (Test-Path -LiteralPath $root -PathType Container)) { continue }
        $candidate = Get-ChildItem -LiteralPath $root -Recurse -File -Filter 'sqlcmd.exe' -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($candidate) { return $candidate.FullName }
    }
    return $null
}

function Get-MsSqlInstanceNames {
    param([object[]]$Services)
    $names = [System.Collections.Generic.List[string]]::new()
    foreach ($service in $Services) {
        if ($service.Name -eq 'MSSQLSERVER') {
            if (-not $names.Contains('MSSQLSERVER')) { $names.Add('MSSQLSERVER') | Out-Null }
        }
        elseif ($service.Name -match '^MSSQL\$(.+)$') {
            if (-not $names.Contains($Matches[1])) { $names.Add($Matches[1]) | Out-Null }
        }
    }
    return @($names)
}

function Get-MsSqlRegistryEvidence {
    $items = [System.Collections.Generic.List[object]]::new()
    foreach ($base in @('HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Microsoft SQL Server')) {
        if (-not (Test-Path -LiteralPath $base)) { continue }
        foreach ($node in @(Get-ChildItem -LiteralPath $base -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.Name -match 'SuperSocketNetLib|MSSQLServer\\Audit|LoginMode' } | Select-Object -First 200)) {
            try {
                $props = Get-ItemProperty -LiteralPath $node.PSPath -ErrorAction Stop
                $items.Add([pscustomobject]@{ Path = $node.Name; Properties = $props }) | Out-Null
            } catch {}
        }
    }
    return @($items)
}

function Get-MsSqlWindowsState {
    $services = @(Get-MsSqlWindowsServices)
    $engineServices = @($services | Where-Object { Test-MsSqlEngineService -Service $_ })
    $processes = @(Get-MsSqlWindowsProcesses)
    $paths = [System.Collections.Generic.List[string]]::new()
    foreach ($service in $services) {
        if ($service.PathName -match '(?i)"([^"]*\\sqlservr\.exe)"') {
            Add-MsSqlUniquePath -Paths $paths -Candidate (Split-Path -Parent $Matches[1]) -PathType Container
        }
        elseif ($service.PathName -match '(?i)(\S*\\sqlservr\.exe)') {
            Add-MsSqlUniquePath -Paths $paths -Candidate (Split-Path -Parent $Matches[1]) -PathType Container
        }
    }
    foreach ($process in $processes) {
        if ($process.ExecutablePath) {
            Add-MsSqlUniquePath -Paths $paths -Candidate (Split-Path -Parent $process.ExecutablePath) -PathType Container
        }
    }
    # Only run the expensive filesystem/registry discovery when SQL Server is
    # actually present. Otherwise a host without SQL Server recurses all of
    # Program Files looking for sqlcmd.exe and the check hangs (60s+).
    $installed = ($engineServices.Count -gt 0 -or $processes.Count -gt 0)
    [pscustomobject]@{
        Services = $services
        EngineServices = $engineServices
        Processes = $processes
        Instances = @(Get-MsSqlInstanceNames -Services $engineServices)
        BinDirs = @($paths)
        CliPath = if ($installed) { Get-MsSqlCliPath } else { $null }
        RegistryEvidence = if ($installed) { @(Get-MsSqlRegistryEvidence) } else { @() }
        Installed = $installed
    }
}

function Get-MsSqlWindowsEvidence {
    param($State)
    @(
        $State.Services | ForEach-Object { "Service $($_.Name) [$($_.State)] $($_.StartName): $($_.PathName)" }
        $State.Processes | ForEach-Object { "Process $($_.ProcessId): $($_.CommandLine)" }
        if ($State.Instances.Count -gt 0) { "Instances: $($State.Instances -join ', ')" }
        if ($State.BinDirs.Count -gt 0) { "BinDirs: $($State.BinDirs -join ', ')" }
        if ($State.CliPath) { "CliPath: $($State.CliPath)" }
    ) -join "`n"
}

function Invoke-MsSqlQuery {
    param($State, [string]$Query)
    if (-not $State.CliPath) {
        return [pscustomobject]@{ Ok = $false; Output = 'sqlcmd.exe client was not found.'; Command = 'sqlcmd client discovery' }
    }
    $server = if ($env:DB_HOST) { $env:DB_HOST } elseif ($env:MSSQL_SERVER) { $env:MSSQL_SERVER } elseif ($State.Instances.Count -gt 0 -and $State.Instances[0] -ne 'MSSQLSERVER') { ".\$($State.Instances[0])" } else { 'localhost' }
    $database = if ($env:DB_NAME) { $env:DB_NAME } else { 'master' }
    $args = @('-S', $server, '-d', $database, '-W', '-h', '-1', '-Q', $Query)
    if ($env:DB_USER -or $env:MSSQL_USER) {
        $user = if ($env:DB_USER) { $env:DB_USER } else { $env:MSSQL_USER }
        $password = if ($env:DB_PASSWORD) { $env:DB_PASSWORD } else { $env:MSSQL_PASSWORD }
        $args += @('-U', $user, '-P', $password)
    }
    else {
        $args += '-E'
    }
    $output = & $State.CliPath @args 2>&1
    $exit = $LASTEXITCODE
    [pscustomobject]@{ Ok = ($exit -eq 0); Output = (($output | Out-String).Trim()); Command = "$($State.CliPath) -S $server -d $database -Q <query>" }
}

function Test-MsSqlBroadPrincipal {
    param([System.Security.Principal.IdentityReference]$Identity)
    try { $sid = $Identity.Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { $sid = [string]$Identity }
    return ($sid -eq 'S-1-1-0') -or ($sid -eq 'S-1-5-11') -or ($sid -eq 'S-1-5-32-545') -or ($sid -eq 'S-1-5-32-546') -or ($sid -match '-513$') -or (([string]$Identity) -match '(?i)Everyone|Authenticated Users|BUILTIN\\Users|Guests|Domain Users')
}

function Get-MsSqlBroadAclEvidence {
    param([string]$Path, [string]$Role)
    $writeRights = @([System.Security.AccessControl.FileSystemRights]::FullControl, [System.Security.AccessControl.FileSystemRights]::Modify, [System.Security.AccessControl.FileSystemRights]::Write, [System.Security.AccessControl.FileSystemRights]::WriteData, [System.Security.AccessControl.FileSystemRights]::AppendData, [System.Security.AccessControl.FileSystemRights]::CreateFiles, [System.Security.AccessControl.FileSystemRights]::CreateDirectories, [System.Security.AccessControl.FileSystemRights]::Delete, [System.Security.AccessControl.FileSystemRights]::ChangePermissions, [System.Security.AccessControl.FileSystemRights]::TakeOwnership)
    try { $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop } catch { return [pscustomobject]@{ Path = $Path; Role = $Role; Access = 'Unknown'; Principal = 'N/A'; Rights = "ACL read failed: $($_.Exception.Message)" } }
    foreach ($rule in $acl.Access) {
        if ($rule.AccessControlType -ne 'Allow' -or -not (Test-MsSqlBroadPrincipal -Identity $rule.IdentityReference)) { continue }
        foreach ($right in $writeRights) {
            if (($rule.FileSystemRights -band $right) -eq $right) {
                [pscustomobject]@{ Path = $Path; Role = $Role; Access = 'Write'; Principal = [string]$rule.IdentityReference; Rights = [string]$rule.FileSystemRights }
                break
            }
        }
    }
}

function New-MsSqlResult {
    param([string]$FinalResult, [string]$Summary, [string]$CommandOutput, [string]$CommandExecuted)
    $status = switch ($FinalResult) { 'GOOD' { '양호' } 'VULNERABLE' { '취약' } 'N/A' { 'N/A' } default { '수동진단' } }
    [pscustomobject]@{ FinalResult = $FinalResult; Status = $status; Summary = $Summary; CommandOutput = $CommandOutput; CommandExecuted = $CommandExecuted }
}

function New-MsSqlNotInstalledResult {
    New-MsSqlResult 'N/A' 'SQL Server for Windows service/process was not found.' 'No MSSQLSERVER/MSSQL$* service or sqlservr.exe process evidence found.' 'Get-CimInstance Win32_Service/Win32_Process'
}

function Invoke-MsSqlSqlCheck {
    param($State, [string]$Query, [scriptblock]$Judge, [string]$Description)
    $result = Invoke-MsSqlQuery -State $State -Query $Query
    if (-not $result.Ok) {
        return New-MsSqlResult 'MANUAL' "SQL Server was found, but SQL evidence for $Description could not be collected automatically." ("Discovery evidence:`n$(Get-MsSqlWindowsEvidence -State $State)`n`nSQL output:`n$($result.Output)") $result.Command
    }
    & $Judge $result
}

function Invoke-MsSqlWindowsCheck {
    param([string]$ItemId, [string]$ItemName)
    $state = Get-MsSqlWindowsState
    if (-not $state.Installed) { return New-MsSqlNotInstalledResult }
    $evidence = Get-MsSqlWindowsEvidence -State $state

    switch ($ItemId) {
        'D-01' { return Invoke-MsSqlSqlCheck $state "SELECT name,is_disabled,LOGINPROPERTY(name,'IsLocked') AS is_locked FROM sys.sql_logins WHERE name IN ('sa','admin','test','guest');" { param($r) if ($r.Output -match '(?im)^sa\s+0') { New-MsSqlResult 'MANUAL' 'The sa/default SQL login is enabled. Confirm password/policy state and approved use.' $r.Output $r.Command } elseif ($r.Output -match '(?m)\S') { New-MsSqlResult 'GOOD' 'Default SQL login evidence was collected and no enabled sa evidence was obvious.' $r.Output $r.Command } else { New-MsSqlResult 'GOOD' 'No default SQL login evidence was returned.' 'No rows returned.' $r.Command } } 'default account password policy' }
        'D-02' { return Invoke-MsSqlSqlCheck $state "SELECT name,is_disabled FROM sys.server_principals WHERE name IN ('guest','test','admin') OR name LIKE 'test%';" { param($r) if ($r.Output -match '(?m)\S') { New-MsSqlResult 'VULNERABLE' 'Unnecessary SQL Server login/principal evidence was found.' $r.Output $r.Command } else { New-MsSqlResult 'GOOD' 'No obvious unnecessary SQL Server principals were returned.' 'No rows returned.' $r.Command } } 'unnecessary account removal' }
        'D-03' { return Invoke-MsSqlSqlCheck $state "SELECT name,is_policy_checked,is_expiration_checked FROM sys.sql_logins WHERE type_desc='SQL_LOGIN';" { param($r) if ($r.Output -match '(?m)\s+0\s+|0$') { New-MsSqlResult 'VULNERABLE' 'SQL logins without password policy or expiration checks were found.' $r.Output $r.Command } else { New-MsSqlResult 'GOOD' 'SQL login password policy/expiration checks appear enabled.' $r.Output $r.Command } } 'password lifetime and complexity' }
        'D-04' { return Invoke-MsSqlSqlCheck $state "SELECT sp.name FROM sys.server_role_members rm JOIN sys.server_principals sp ON rm.member_principal_id=sp.principal_id JOIN sys.server_principals rp ON rm.role_principal_id=rp.principal_id WHERE rp.name='sysadmin';" { param($r) if ($r.Output -match '(?m)^(sa|NT SERVICE|BUILTIN\\Administrators|##)') { New-MsSqlResult 'MANUAL' 'SQL Server sysadmin members exist; verify only approved DBA accounts are included.' $r.Output $r.Command } elseif ($r.Output -match '(?m)\S') { New-MsSqlResult 'VULNERABLE' 'Potentially nonstandard SQL Server sysadmin members were found.' $r.Output $r.Command } else { New-MsSqlResult 'GOOD' 'No SQL Server sysadmin member evidence was returned.' 'No rows returned.' $r.Command } } 'administrator privilege restriction' }
        'D-05' { return New-MsSqlResult 'MANUAL' 'SQL Server password reuse depends on Windows/domain policy or custom control. Confirm institutional reuse policy.' $evidence 'Review SQL Server/Windows password reuse policy' }
        'D-06' { return Invoke-MsSqlSqlCheck $state "SELECT name FROM sys.server_principals WHERE type_desc IN ('SQL_LOGIN','WINDOWS_LOGIN','WINDOWS_GROUP') AND name IN ('sa','admin','dba','shared');" { param($r) if ($r.Output -match '(?m)\S') { New-MsSqlResult 'MANUAL' 'Shared or privileged SQL Server account names were found; confirm individual account assignment policy.' $r.Output $r.Command } else { New-MsSqlResult 'GOOD' 'No obvious shared SQL Server account names were returned.' 'No rows returned.' $r.Command } } 'individual DB account assignment' }
        'D-07' { return New-MsSqlResult 'N/A' '해당 항목 MSSQL 대상 아님 (per guideline_metadata.json: D-07 target = Oracle DB, MySQL, Altibase, Cubrid).' 'D-07 target excludes SQL Server.' 'Map DBMS guideline applicability' }
        'D-08' { return Invoke-MsSqlSqlCheck $state "SELECT name, SUBSTRING(CONVERT(varchar(8), CONVERT(varbinary(4), LEFT(password_hash,2))),1,8) AS hash_version FROM sys.sql_logins WHERE is_disabled = 0 AND password_hash IS NOT NULL;" { param($r) New-MsSqlResult 'MANUAL' 'D-08 criterion is the stored password hash algorithm (SHA-256 이상), not TLS transport. SQL Server 2012+ stores SQL login password hashes with SHA-512 (32-bit salt); the hash version byte is not a reliable basis for an automated GOOD/VULNERABLE verdict. Verify the SQL Server version and the password hash policy (sys.sql_logins.password_hash) against the institutional requirement.' $r.Output $r.Command } 'password hash algorithm' }
        'D-09' { return New-MsSqlResult 'N/A' '해당 항목 MSSQL 대상 아님 (per guideline_metadata.json: D-09 target = Oracle DB, Altibase, Tibero).' 'D-09 target excludes SQL Server.' 'Map DBMS guideline applicability' }
        'D-10' { return New-MsSqlResult 'N/A' '해당 항목 MSSQL 대상 아님 (per guideline_metadata.json: D-10 target = Windows OS, Oracle DB, MySQL, Altibase, Tibero, PostgreSQL).' 'D-10 product list excludes SQL Server.' 'Map DBMS guideline applicability' }
        'D-11' { return Invoke-MsSqlSqlCheck $state "SELECT pr.name, pe.permission_name, pe.state_desc FROM sys.server_permissions pe JOIN sys.server_principals pr ON pe.grantee_principal_id=pr.principal_id WHERE pr.name NOT IN ('sa','public') AND pe.class_desc='SERVER';" { param($r) if ($r.Output -match '(?m)\S') { New-MsSqlResult 'MANUAL' 'Server-level permissions exist; confirm only DBAs are authorized.' $r.Output $r.Command } else { New-MsSqlResult 'GOOD' 'No non-DBA server-level permission evidence was returned.' 'No rows returned.' $r.Command } } 'system table access restriction' }
        'D-12' { return New-MsSqlResult 'N/A' 'Oracle listener password control is not applicable to SQL Server.' 'SQL Server uses endpoint/network configuration rather than Oracle listener password.' 'Map DBMS listener-password guideline applicability' }
        'D-13' { $drivers = @(@('HKLM:\SOFTWARE\ODBC\ODBCINST.INI','HKLM:\SOFTWARE\WOW6432Node\ODBC\ODBCINST.INI') | ForEach-Object { Get-ChildItem $_ -ErrorAction SilentlyContinue } | Where-Object { $_.PSChildName -match '(?i)SQL Server|ODBC Driver .* SQL Server' } | Select-Object -ExpandProperty PSChildName -Unique); if ($drivers.Count -gt 0) { return New-MsSqlResult 'MANUAL' 'SQL Server ODBC drivers/data sources were found. Confirm only required DSNs/drivers remain.' ($drivers -join "`n") 'Inspect Windows ODBC registry driver entries (native + WOW6432Node)' }; return New-MsSqlResult 'GOOD' 'No SQL Server ODBC driver entries were found in the inspected registry paths.' 'No SQL Server ODBC entries returned.' 'Inspect Windows ODBC registry driver entries (native + WOW6432Node)' }
        'D-14' { return New-MsSqlResult 'N/A' '해당 항목 MSSQL 대상 아님 (per guideline_metadata.json: D-14 target = Oracle DB, PostgreSQL, Cubrid).' 'D-14 target excludes SQL Server.' 'Map DBMS guideline applicability' }
        'D-15' { return New-MsSqlResult 'N/A' 'Oracle listener log/trace modification control is not applicable to SQL Server.' 'SQL Server has no Oracle listener component.' 'Map DBMS listener-log guideline applicability' }
        'D-16' { return Invoke-MsSqlSqlCheck $state "SELECT SERVERPROPERTY('IsIntegratedSecurityOnly') AS WindowsOnly;" { param($r) if ($r.Output -match '(?m)^\s*1\s*$') { New-MsSqlResult 'GOOD' 'SQL Server is configured for Windows Authentication mode only.' $r.Output $r.Command } else { $sa = Invoke-MsSqlQuery -State $state -Query "SELECT name,is_disabled,is_policy_checked FROM sys.sql_logins WHERE name='sa';"; $combined = "IsIntegratedSecurityOnly:`n$($r.Output)`n`nsa login state (name is_disabled is_policy_checked):`n$($sa.Output)"; if (-not $sa.Ok) { New-MsSqlResult 'MANUAL' 'Mixed authentication mode is enabled, but the sa login state (sys.sql_logins is_disabled/is_policy_checked) could not be collected automatically. Manually confirm whether sa is disabled or, if enabled, has a strong password policy.' $combined $r.Command } elseif ($sa.Output -match '(?im)^sa\s+1\s+\d') { New-MsSqlResult 'GOOD' 'Mixed authentication mode is enabled, but the sa login is disabled (criteria_good).' $combined $r.Command } elseif ($sa.Output -match '(?im)^sa\s+0\s+1') { New-MsSqlResult 'GOOD' 'Mixed authentication mode is enabled and the sa login is enabled with the SQL password policy enforced (is_policy_checked=1, criteria_good). Manually confirm the policy strength meets the institutional requirement.' $combined $r.Command } elseif ($sa.Output -match '(?im)^sa\s+0\s+0') { New-MsSqlResult 'VULNERABLE' 'Mixed authentication mode is enabled, the sa login is enabled, and no password policy is enforced (is_policy_checked=0, criteria_bad).' $combined $r.Command } else { New-MsSqlResult 'MANUAL' 'Mixed authentication mode is enabled, but the sa login state could not be parsed. Manually confirm whether sa is disabled or, if enabled, has a strong password policy.' $combined $r.Command } } } 'Windows authentication mode' }
        'D-17' { return New-MsSqlResult 'N/A' 'AuditTable DBA-only access control is Oracle-specific and not directly applicable to SQL Server.' 'SQL Server auditing storage depends on SQL Server Audit/file/event log configuration.' 'Map DBMS AuditTable guideline applicability' }
        'D-18' { return New-MsSqlResult 'N/A' '해당 항목 MSSQL 대상 아님 (per guideline_metadata.json: D-18 target = Oracle DB, Altibase, Tibero, Cubrid).' 'D-18 target excludes SQL Server.' 'Map DBMS guideline applicability' }
        'D-19' { return New-MsSqlResult 'N/A' 'OS_ROLES and REMOTE_OS_AUTHENTICATION controls are Oracle-specific and not applicable to SQL Server.' 'SQL Server does not expose Oracle OS role parameters.' 'Map Oracle OS role guideline applicability' }
        'D-20' { return New-MsSqlResult 'N/A' '해당 항목 MSSQL 대상 아님 (per guideline_metadata.json: D-20 target = Oracle DB, Altibase, Tibero, PostgreSQL).' 'D-20 target excludes SQL Server.' 'Map DBMS guideline applicability' }
        'D-21' { return New-MsSqlResult 'N/A' '해당 항목 MSSQL 대상 아님 (per guideline_metadata.json: D-21 target = Oracle DB, MySQL, Altibase, Tibero).' 'D-21 target excludes SQL Server.' 'Map DBMS guideline applicability' }
        'D-22' { return New-MsSqlResult 'N/A' '해당 항목 MSSQL 대상 아님 (per guideline_metadata.json: D-22 target = Oracle DB).' 'D-22 target excludes SQL Server.' 'Map DBMS guideline applicability' }
        'D-23' { return Invoke-MsSqlSqlCheck $state "SELECT CAST(value_in_use AS int) FROM sys.configurations WHERE name='xp_cmdshell';" { param($r) if ($r.Output -match '1') { New-MsSqlResult 'VULNERABLE' 'SQL Server xp_cmdshell is enabled.' $r.Output $r.Command } else { New-MsSqlResult 'GOOD' 'SQL Server xp_cmdshell is disabled.' $r.Output $r.Command } } 'xp_cmdshell restriction' }
        'D-24' { return Invoke-MsSqlSqlCheck $state "SELECT OBJECT_NAME(pe.major_id) AS proc_name, USER_NAME(pe.grantee_principal_id) AS grantee, pe.permission_name, pe.state_desc FROM master.sys.database_permissions pe WHERE OBJECT_NAME(pe.major_id) LIKE 'xp_reg%' AND USER_NAME(pe.grantee_principal_id) IN ('public','guest');" { param($r) if ($r.Output -match '(?m)\S') { New-MsSqlResult 'VULNERABLE' 'Restricted registry extended procedures (xp_reg*) are EXECUTE-granted to public/guest (criteria_bad). Remove the grant with REVOKE.' $r.Output $r.Command } else { New-MsSqlResult 'MANUAL' 'No xp_reg* EXECUTE grant to public/guest was returned from master.sys.database_permissions, but this cannot be statically proven complete (the full restricted xp_reg* set and DBA exceptions require live T-SQL verification). Manually confirm no restricted system extended procedures are granted to DBA-외 guest/public.' ("SQL output:`n$($r.Output)") $r.Command } } 'registry procedure permission restriction' }
        'D-25' { return Invoke-MsSqlSqlCheck $state "SELECT @@VERSION;" { param($r) New-MsSqlResult 'MANUAL' 'SQL Server was found. Compare detected version and patch policy against current Microsoft security advisories.' $r.Output $r.Command } 'vendor patch status' }
        'D-26' { return Invoke-MsSqlSqlCheck $state "SELECT a.name AS audit_name, a.is_state_enabled, ISNULL(d.audit_action_name,'(no spec details)') AS action FROM sys.server_audits a LEFT JOIN sys.server_audit_specifications s ON 1=1 LEFT JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id;" { param($r) if ($r.Output -match '(?m)\S') { New-MsSqlResult 'MANUAL' 'SQL Server Audit objects exist. D-26 requires that access/change/delete (접근/변경/삭제) actions are covered by the audit policy; an enabled audit target alone does not confirm action-scope coverage. Verify the audit specification actions against the institutional audit logging policy.' $r.Output $r.Command } else { New-MsSqlResult 'MANUAL' 'No SQL Server Audit evidence was returned; confirm institutional audit logging policy.' 'No rows returned.' $r.Command } } 'audit logging policy' }
        default { return New-MsSqlResult 'MANUAL' "No SQL Server Windows diagnostic rule is defined for $ItemId." $evidence 'SQL Server Windows generic discovery' }
    }
}
