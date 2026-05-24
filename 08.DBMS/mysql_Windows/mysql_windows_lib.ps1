#Requires -Version 5.1

function Add-MySqlUniquePath {
    param(
        [System.Collections.Generic.List[string]]$Paths,
        [string]$Candidate,
        [string]$PathType = 'Any'
    )
    if ([string]::IsNullOrWhiteSpace($Candidate)) { return }
    try { $resolved = [System.IO.Path]::GetFullPath($Candidate.Trim('"')) }
    catch { return }

    $exists = switch ($PathType) {
        'Leaf' { Test-Path -LiteralPath $resolved -PathType Leaf }
        'Container' { Test-Path -LiteralPath $resolved -PathType Container }
        default { Test-Path -LiteralPath $resolved }
    }
    if ($exists -and -not $Paths.Contains($resolved)) {
        $Paths.Add($resolved) | Out-Null
    }
}

function Get-MySqlWindowsServices {
    try {
        @(Get-CimInstance Win32_Service -ErrorAction Stop | Where-Object {
            $_.Name -match '(?i)mysql|mariadb' -or $_.DisplayName -match '(?i)mysql|mariadb'
        })
    }
    catch { @() }
}

function Get-MySqlWindowsProcesses {
    try {
        @(Get-CimInstance Win32_Process -ErrorAction Stop | Where-Object {
            $_.Name -match '(?i)^(mysqld|mariadbd)\.exe$'
        })
    }
    catch { @() }
}

function Get-MySqlCliPath {
    foreach ($cmd in @('mysql.exe', 'mariadb.exe')) {
        $found = Get-Command $cmd -ErrorAction SilentlyContinue
        if ($found) { return $found.Source }
    }

    foreach ($root in @($env:ProgramFiles, ${env:ProgramFiles(x86)}, 'C:\ProgramData', 'C:\tools')) {
        if ([string]::IsNullOrWhiteSpace($root) -or -not (Test-Path -LiteralPath $root -PathType Container)) { continue }
        $candidate = Get-ChildItem -LiteralPath $root -Recurse -File -ErrorAction SilentlyContinue -Filter 'mysql.exe' |
            Where-Object { $_.FullName -match '(?i)\\bin\\mysql\.exe$' } |
            Select-Object -First 1
        if ($candidate) { return $candidate.FullName }
    }
    return $null
}

function Get-MySqlWindowsConfigCandidates {
    $paths = [System.Collections.Generic.List[string]]::new()
    foreach ($candidate in @(
        "$env:ProgramData\MySQL\MySQL Server 8.0\my.ini",
        "$env:ProgramData\MySQL\MySQL Server 5.7\my.ini",
        "$env:ProgramFiles\MySQL\MySQL Server 8.0\my.ini",
        "$env:ProgramFiles\MySQL\MySQL Server 5.7\my.ini",
        "${env:ProgramFiles(x86)}\MySQL\MySQL Server 5.7\my.ini",
        'C:\my.ini',
        'C:\Windows\my.ini'
    )) {
        Add-MySqlUniquePath -Paths $paths -Candidate $candidate -PathType Leaf
    }

    foreach ($service in Get-MySqlWindowsServices) {
        $pathName = [string]$service.PathName
        if ($pathName -match '(?i)--defaults-file="?([^"\s]+)"?') {
            Add-MySqlUniquePath -Paths $paths -Candidate $Matches[1] -PathType Leaf
        }
    }
    foreach ($process in Get-MySqlWindowsProcesses) {
        $cmd = [string]$process.CommandLine
        if ($cmd -match '(?i)--defaults-file="?([^"\s]+)"?') {
            Add-MySqlUniquePath -Paths $paths -Candidate $Matches[1] -PathType Leaf
        }
    }
    return @($paths)
}

function Get-MySqlDataDirs {
    param(
        [string[]]$ConfigFiles,
        [object[]]$Services,
        [object[]]$Processes
    )
    $dirs = [System.Collections.Generic.List[string]]::new()
    foreach ($file in $ConfigFiles) {
        $text = Get-Content -LiteralPath $file -Raw -ErrorAction SilentlyContinue
        foreach ($line in ($text -split "`r?`n")) {
            if ($line.Trim() -match '^(?i)datadir\s*=\s*(.+)$') {
                Add-MySqlUniquePath -Paths $dirs -Candidate $Matches[1].Trim().Trim('"') -PathType Container
            }
        }
    }
    foreach ($obj in @($Services + $Processes)) {
        $cmd = if ($obj.PathName) { [string]$obj.PathName } else { [string]$obj.CommandLine }
        if ($cmd -match '(?i)--datadir="?([^"\s]+)"?') {
            Add-MySqlUniquePath -Paths $dirs -Candidate $Matches[1] -PathType Container
        }
    }
    foreach ($candidate in @(
        "$env:ProgramData\MySQL\MySQL Server 8.0\Data",
        "$env:ProgramData\MySQL\MySQL Server 5.7\Data",
        "$env:ProgramFiles\MySQL\MySQL Server 8.0\Data",
        "$env:ProgramFiles\MySQL\MySQL Server 5.7\Data"
    )) {
        Add-MySqlUniquePath -Paths $dirs -Candidate $candidate -PathType Container
    }
    return @($dirs)
}

function Get-MySqlWindowsState {
    $services = @(Get-MySqlWindowsServices)
    $processes = @(Get-MySqlWindowsProcesses)
    $configs = @(Get-MySqlWindowsConfigCandidates)
    $dataDirs = @(Get-MySqlDataDirs -ConfigFiles $configs -Services $services -Processes $processes)
    [pscustomobject]@{
        Services = $services
        Processes = $processes
        ConfigFiles = $configs
        DataDirs = $dataDirs
        CliPath = Get-MySqlCliPath
        Installed = ($services.Count -gt 0 -or $processes.Count -gt 0 -or $configs.Count -gt 0 -or $dataDirs.Count -gt 0)
    }
}

function Get-MySqlWindowsEvidence {
    param($State)
    @(
        $State.Services | ForEach-Object { "Service $($_.Name) [$($_.State)] $($_.StartName): $($_.PathName)" }
        $State.Processes | ForEach-Object { "Process $($_.ProcessId): $($_.CommandLine)" }
        if ($State.ConfigFiles.Count -gt 0) { "ConfigFiles: $($State.ConfigFiles -join ', ')" }
        if ($State.DataDirs.Count -gt 0) { "DataDirs: $($State.DataDirs -join ', ')" }
        if ($State.CliPath) { "CliPath: $($State.CliPath)" }
    ) -join "`n"
}

function Invoke-MySqlQuery {
    param(
        $State,
        [string]$Query
    )
    if (-not $State.CliPath) {
        return [pscustomobject]@{ Ok = $false; Output = 'mysql.exe/mariadb.exe client was not found.'; Command = 'mysql client discovery' }
    }

    $user = if ($env:DB_USER) { $env:DB_USER } elseif ($env:MYSQL_USER) { $env:MYSQL_USER } else { 'root' }
    $password = if ($env:DB_PASSWORD) { $env:DB_PASSWORD } else { $env:MYSQL_PWD }
    $host = if ($env:DB_HOST) { $env:DB_HOST } elseif ($env:MYSQL_HOST) { $env:MYSQL_HOST } else { 'localhost' }
    $port = if ($env:DB_PORT) { $env:DB_PORT } elseif ($env:MYSQL_TCP_PORT) { $env:MYSQL_TCP_PORT } else { '3306' }

    $args = @('-N', '-B', "-u$user", "-h$host", "-P$port", '-e', $Query)
    $oldPwd = $env:MYSQL_PWD
    if ($password) { $env:MYSQL_PWD = $password }
    try {
        $output = & $State.CliPath @args 2>&1
        $exit = $LASTEXITCODE
    }
    finally {
        if ($null -ne $oldPwd) { $env:MYSQL_PWD = $oldPwd } else { Remove-Item Env:\MYSQL_PWD -ErrorAction SilentlyContinue }
    }

    [pscustomobject]@{
        Ok = ($exit -eq 0)
        Output = (($output | Out-String).Trim())
        Command = "$($State.CliPath) -N -B -u$user -h$host -P$port -e <query>"
    }
}

function Test-MySqlBroadPrincipal {
    param([System.Security.Principal.IdentityReference]$Identity)
    try { $sid = $Identity.Translate([System.Security.Principal.SecurityIdentifier]).Value }
    catch { $sid = [string]$Identity }
    return @(
        $sid -eq 'S-1-1-0',
        $sid -eq 'S-1-5-11',
        $sid -eq 'S-1-5-32-545',
        $sid -eq 'S-1-5-32-546',
        $sid -match '-513$',
        ([string]$Identity) -match '(?i)Everyone|Authenticated Users|BUILTIN\\Users|Guests|Domain Users'
    ) -contains $true
}

function Test-MySqlAnyRight {
    param(
        [System.Security.AccessControl.FileSystemRights]$Rights,
        [System.Security.AccessControl.FileSystemRights[]]$Expected
    )
    foreach ($right in $Expected) {
        if (($Rights -band $right) -eq $right) { return $true }
    }
    return $false
}

function Get-MySqlBroadAclEvidence {
    param([string]$Path, [string]$Role)
    $readRights = @([System.Security.AccessControl.FileSystemRights]::Read, [System.Security.AccessControl.FileSystemRights]::ReadAndExecute, [System.Security.AccessControl.FileSystemRights]::ListDirectory)
    $writeRights = @([System.Security.AccessControl.FileSystemRights]::FullControl, [System.Security.AccessControl.FileSystemRights]::Modify, [System.Security.AccessControl.FileSystemRights]::Write, [System.Security.AccessControl.FileSystemRights]::WriteData, [System.Security.AccessControl.FileSystemRights]::AppendData, [System.Security.AccessControl.FileSystemRights]::CreateFiles, [System.Security.AccessControl.FileSystemRights]::CreateDirectories, [System.Security.AccessControl.FileSystemRights]::Delete, [System.Security.AccessControl.FileSystemRights]::ChangePermissions, [System.Security.AccessControl.FileSystemRights]::TakeOwnership)
    try { $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop }
    catch { return [pscustomobject]@{ Path = $Path; Role = $Role; Access = 'Unknown'; Principal = 'N/A'; Rights = "ACL read failed: $($_.Exception.Message)" } }
    foreach ($rule in $acl.Access) {
        if ($rule.AccessControlType -ne 'Allow' -or -not (Test-MySqlBroadPrincipal -Identity $rule.IdentityReference)) { continue }
        $hasWrite = Test-MySqlAnyRight -Rights $rule.FileSystemRights -Expected $writeRights
        $hasRead = Test-MySqlAnyRight -Rights $rule.FileSystemRights -Expected $readRights
        if ($hasWrite -or $hasRead) {
            [pscustomobject]@{ Path = $Path; Role = $Role; Access = if ($hasWrite) { 'Write' } else { 'Read' }; Principal = [string]$rule.IdentityReference; Rights = [string]$rule.FileSystemRights }
        }
    }
}

function New-MySqlResult {
    param([string]$FinalResult, [string]$Summary, [string]$CommandOutput, [string]$CommandExecuted)
    $status = switch ($FinalResult) { 'GOOD' { '양호' } 'VULNERABLE' { '취약' } 'N/A' { 'N/A' } default { '수동진단' } }
    [pscustomobject]@{ FinalResult = $FinalResult; Status = $status; Summary = $Summary; CommandOutput = $CommandOutput; CommandExecuted = $CommandExecuted }
}

function New-MySqlNotInstalledResult {
    New-MySqlResult 'N/A' 'MySQL/MariaDB for Windows service/process/configuration was not found.' 'No MySQL service, process, config file, data directory, or client evidence found.' 'Get-CimInstance Win32_Service/Win32_Process; known MySQL paths'
}

function Invoke-MySqlSqlCheck {
    param($State, [string]$Query, [scriptblock]$Judge, [string]$Description)
    $result = Invoke-MySqlQuery -State $State -Query $Query
    if (-not $result.Ok) {
        return New-MySqlResult 'MANUAL' "MySQL was found, but SQL evidence for $Description could not be collected automatically." ("Discovery evidence:`n$(Get-MySqlWindowsEvidence -State $State)`n`nSQL output:`n$($result.Output)") $result.Command
    }
    & $Judge $result
}

function Invoke-MySqlWindowsCheck {
    param([string]$ItemId, [string]$ItemName)
    $state = Get-MySqlWindowsState
    if (-not $state.Installed) { return New-MySqlNotInstalledResult }
    $configText = @($state.ConfigFiles | ForEach-Object { "# FILE: $_`n" + (Get-Content -LiteralPath $_ -Raw -ErrorAction SilentlyContinue) }) -join "`n"
    $evidence = Get-MySqlWindowsEvidence -State $state

    switch ($ItemId) {
        'D-01' { return Invoke-MySqlSqlCheck $state "SELECT user,host,IF(authentication_string IS NULL OR authentication_string='', 'EMPTY','SET') FROM mysql.user WHERE user IN ('root','mysql','test') OR user='';" { param($r) if ($r.Output -match '(?m)\bEMPTY\b|^\s*\t') { New-MySqlResult 'VULNERABLE' 'Default, anonymous, or empty-password MySQL account evidence was found.' $r.Output $r.Command } else { New-MySqlResult 'GOOD' 'No default empty-password MySQL account evidence was found.' $r.Output $r.Command } } 'default account password policy' }
        'D-02' { return Invoke-MySqlSqlCheck $state "SELECT user,host,account_locked FROM mysql.user WHERE user IN ('test','anonymous','') OR user LIKE 'test%';" { param($r) if ($r.Output -match '(?m)\S') { New-MySqlResult 'VULNERABLE' 'Unnecessary MySQL accounts were found.' $r.Output $r.Command } else { New-MySqlResult 'GOOD' 'No obvious unnecessary MySQL accounts were found.' 'No rows returned.' $r.Command } } 'unnecessary account removal' }
        'D-03' { return Invoke-MySqlSqlCheck $state "SHOW VARIABLES WHERE Variable_name IN ('default_password_lifetime','validate_password.policy','validate_password.length');" { param($r) if ($r.Output -match 'default_password_lifetime\s+(0|NULL)' -or $r.Output -notmatch 'validate_password') { New-MySqlResult 'MANUAL' 'MySQL password lifetime/complexity evidence is missing or weak; confirm institutional policy.' $r.Output $r.Command } else { New-MySqlResult 'GOOD' 'MySQL password lifetime/complexity variables were found.' $r.Output $r.Command } } 'password lifetime and complexity' }
        'D-04' { return Invoke-MySqlSqlCheck $state "SELECT user,host FROM mysql.user WHERE Super_priv='Y' OR Grant_priv='Y' OR Create_user_priv='Y';" { param($r) if ($r.Output -match '(?m)^(root|mysql)\b') { New-MySqlResult 'MANUAL' 'Administrative MySQL privileges exist; verify they are limited to approved DBA accounts.' $r.Output $r.Command } elseif ($r.Output -match '(?m)\S') { New-MySqlResult 'VULNERABLE' 'Non-default accounts with high MySQL privileges were found.' $r.Output $r.Command } else { New-MySqlResult 'GOOD' 'No excessive MySQL administrative privilege evidence was returned.' 'No rows returned.' $r.Command } } 'administrator privilege restriction' }
        'D-05' { return Invoke-MySqlSqlCheck $state "SHOW VARIABLES LIKE 'password_history'; SHOW VARIABLES LIKE 'password_reuse_interval';" { param($r) if ($r.Output -match '\s+[1-9]\d*') { New-MySqlResult 'GOOD' 'MySQL password reuse restriction variables are configured.' $r.Output $r.Command } else { New-MySqlResult 'MANUAL' 'MySQL password reuse restriction evidence is missing or disabled.' $r.Output $r.Command } } 'password reuse restriction' }
        'D-06' { return Invoke-MySqlSqlCheck $state "SELECT user,COUNT(*) FROM mysql.user GROUP BY user HAVING COUNT(*) > 1 OR user IN ('root','admin','dba');" { param($r) if ($r.Output -match '(?m)\S') { New-MySqlResult 'MANUAL' 'Shared or privileged MySQL account names were found; confirm individual account assignment policy.' $r.Output $r.Command } else { New-MySqlResult 'GOOD' 'No obvious shared MySQL account evidence was returned.' 'No rows returned.' $r.Command } } 'individual DB account assignment' }
        'D-07' { $accounts = @($state.Services | ForEach-Object { $_.StartName } | Where-Object { $_ }); if ($accounts -match '^(?i)(LocalSystem|NT AUTHORITY\\SYSTEM)$|Administrator') { return New-MySqlResult 'VULNERABLE' 'MySQL Windows service appears to run with administrator-equivalent OS privileges.' ($accounts -join ', ') 'Inspect MySQL Windows service StartName' }; if ($accounts.Count -gt 0) { return New-MySqlResult 'GOOD' 'MySQL Windows service account is not administrator-equivalent.' ($accounts -join ', ') 'Inspect MySQL Windows service StartName' }; return New-MySqlResult 'MANUAL' 'MySQL service account could not be determined.' $evidence 'Inspect MySQL Windows service StartName' }
        'D-08' { return Invoke-MySqlSqlCheck $state "SHOW VARIABLES WHERE Variable_name IN ('require_secure_transport','tls_version','ssl_fips_mode');" { param($r) if ($r.Output -match 'require_secure_transport\s+ON' -and $r.Output -notmatch 'TLSv1(\.0|\.1)?\b|SSLv') { New-MySqlResult 'GOOD' 'MySQL secure transport and TLS variable evidence was found.' $r.Output $r.Command } else { New-MySqlResult 'MANUAL' 'MySQL encryption/TLS evidence is incomplete or may allow weak transport; verify policy.' $r.Output $r.Command } } 'secure encryption algorithm use' }
        'D-09' { return Invoke-MySqlSqlCheck $state "SHOW VARIABLES WHERE Variable_name IN ('connection_control_failed_connections_threshold','connection_control_min_connection_delay','connection_control_max_connection_delay');" { param($r) if ($r.Output -match 'connection_control_failed_connections_threshold\s+[1-9]') { New-MySqlResult 'GOOD' 'MySQL failed-login delay/lockout plugin variables are configured.' $r.Output $r.Command } else { New-MySqlResult 'MANUAL' 'MySQL failed-login lockout evidence is missing; confirm plugin or compensating control.' $r.Output $r.Command } } 'failed login lockout policy' }
        'D-10' { return Invoke-MySqlSqlCheck $state "SELECT user,host FROM mysql.user WHERE host IN ('%','0.0.0.0','::') OR host LIKE '%.%';" { param($r) if ($r.Output -match '%|0\.0\.0\.0|::') { New-MySqlResult 'VULNERABLE' 'MySQL accounts allowing broad remote access were found.' $r.Output $r.Command } elseif ($r.Output -match '(?m)\S') { New-MySqlResult 'MANUAL' 'Remote MySQL host grants exist; confirm they are approved and network-restricted.' $r.Output $r.Command } else { New-MySqlResult 'GOOD' 'No broad MySQL remote host grants were returned.' 'No rows returned.' $r.Command } } 'remote DB access restriction' }
        'D-11' { return Invoke-MySqlSqlCheck $state "SELECT Grantee,Table_schema,Privilege_type FROM information_schema.schema_privileges WHERE Table_schema IN ('mysql','performance_schema','sys','information_schema');" { param($r) if ($r.Output -match '(?i)PUBLIC|%') { New-MySqlResult 'VULNERABLE' 'Broad system schema privilege evidence was found.' $r.Output $r.Command } elseif ($r.Output -match '(?m)\S') { New-MySqlResult 'MANUAL' 'System schema privileges exist; confirm only DBAs are authorized.' $r.Output $r.Command } else { New-MySqlResult 'GOOD' 'No explicit non-DBA system schema privilege evidence was returned.' 'No rows returned.' $r.Command } } 'system table access restriction' }
        'D-12' { return New-MySqlResult 'N/A' 'MySQL does not use an Oracle-style listener password for this guideline item.' 'Listener password control is not applicable to MySQL Windows.' 'Map DBMS listener-password guideline applicability' }
        'D-13' { $drivers = @(Get-ChildItem 'HKLM:\SOFTWARE\ODBC\ODBCINST.INI' -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match '(?i)mysql|mariadb' } | Select-Object -ExpandProperty PSChildName); if ($drivers.Count -gt 0) { return New-MySqlResult 'MANUAL' 'MySQL ODBC drivers/data sources were found. Confirm only required DSNs/drivers remain.' ($drivers -join "`n") 'Inspect Windows ODBC registry driver entries' }; return New-MySqlResult 'GOOD' 'No MySQL ODBC driver entries were found in the inspected registry path.' 'No MySQL ODBC entries returned.' 'Inspect Windows ODBC registry driver entries' }
        'D-14' { $targets = @($state.ConfigFiles + $state.DataDirs | Select-Object -Unique); $acl = foreach ($path in $targets) { Get-MySqlBroadAclEvidence -Path $path -Role 'MySqlPath' }; $bad = @($acl | Where-Object { $_.Access -eq 'Write' -or $_.Access -eq 'Unknown' }); if ($bad.Count -gt 0) { return New-MySqlResult 'VULNERABLE' 'Broad local write or unknown ACL evidence was found on MySQL files/directories.' (($bad | ForEach-Object { "$($_.Path) => $($_.Principal) $($_.Access) ($($_.Rights))" }) -join "`n") 'Get-Acl MySQL config files and data directories' }; if ($acl) { return New-MySqlResult 'MANUAL' 'Broad local read ACL evidence was found on MySQL paths; confirm sensitive files are excluded.' (($acl | ForEach-Object { "$($_.Path) => $($_.Principal) $($_.Access) ($($_.Rights))" }) -join "`n") 'Get-Acl MySQL config files and data directories' }; return New-MySqlResult 'GOOD' 'No broad local user ACL entries were found on assessed MySQL paths.' ($targets -join ', ') 'Get-Acl MySQL config files and data directories' }
        'D-15' { return New-MySqlResult 'N/A' 'Oracle listener log/trace modification control is not applicable to MySQL.' 'MySQL has no Oracle listener component.' 'Map DBMS listener-log guideline applicability' }
        'D-16' { return New-MySqlResult 'N/A' 'SQL Server Windows authentication mode control is not applicable to MySQL.' 'MySQL does not use SQL Server Windows authentication mode.' 'Map DBMS Windows-auth guideline applicability' }
        'D-17' { return New-MySqlResult 'N/A' 'AuditTable DBA-only access control is Oracle-specific and not directly applicable to MySQL.' 'MySQL audit storage depends on plugin/file/table implementation.' 'Map DBMS AuditTable guideline applicability' }
        'D-18' { return Invoke-MySqlSqlCheck $state "SELECT user,host FROM mysql.user WHERE Grant_priv='Y' OR Super_priv='Y';" { param($r) if ($r.Output -match '(?m)\S') { New-MySqlResult 'MANUAL' 'Privileged MySQL role/account evidence exists; confirm PUBLIC-style role exposure is not used.' $r.Output $r.Command } else { New-MySqlResult 'GOOD' 'No obvious privileged role/account exposure evidence was returned.' 'No rows returned.' $r.Command } } 'public role restriction' }
        'D-19' { return New-MySqlResult 'N/A' 'OS_ROLES and REMOTE_OS_AUTHENTICATION controls are Oracle-specific and not applicable to MySQL.' 'MySQL does not expose OS_ROLES/REMOTE_OS_AUTHENTICATION/REMOTE_OS_ROLES parameters.' 'Map Oracle OS role guideline applicability' }
        'D-20' { return Invoke-MySqlSqlCheck $state "SELECT user,host FROM mysql.user WHERE Create_priv='Y' OR Create_routine_priv='Y' OR Alter_routine_priv='Y';" { param($r) if ($r.Output -match '(?m)\S') { New-MySqlResult 'MANUAL' 'MySQL object-owner creation privileges exist; confirm only authorized owners have them.' $r.Output $r.Command } else { New-MySqlResult 'GOOD' 'No object-owner creation privilege evidence was returned.' 'No rows returned.' $r.Command } } 'unauthorized object owner restriction' }
        'D-21' { return Invoke-MySqlSqlCheck $state "SELECT user,host FROM mysql.user WHERE Grant_priv='Y';" { param($r) if ($r.Output -match '(?m)\S') { New-MySqlResult 'MANUAL' 'MySQL GRANT OPTION evidence exists; confirm it is limited to approved DBA accounts.' $r.Output $r.Command } else { New-MySqlResult 'GOOD' 'No MySQL GRANT OPTION evidence was returned.' 'No rows returned.' $r.Command } } 'GRANT OPTION restriction' }
        'D-22' { return Invoke-MySqlSqlCheck $state "SHOW VARIABLES WHERE Variable_name IN ('max_user_connections','max_connections','max_execution_time');" { param($r) if ($r.Output -match 'max_user_connections\s+[1-9]|max_execution_time\s+[1-9]') { New-MySqlResult 'GOOD' 'MySQL resource limit variable evidence was found.' $r.Output $r.Command } else { New-MySqlResult 'MANUAL' 'MySQL resource limit evidence is missing or global-only; confirm institutional resource policy.' $r.Output $r.Command } } 'resource limit function' }
        'D-23' { return New-MySqlResult 'N/A' 'SQL Server xp_cmdshell control is not applicable to MySQL.' 'MySQL has no xp_cmdshell feature.' 'Map SQL Server xp_cmdshell guideline applicability' }
        'D-24' { return New-MySqlResult 'N/A' 'SQL Server registry procedure permission control is not applicable to MySQL.' 'MySQL has no SQL Server registry procedures.' 'Map SQL Server registry procedure guideline applicability' }
        'D-25' { return Invoke-MySqlSqlCheck $state "SELECT VERSION();" { param($r) New-MySqlResult 'MANUAL' 'MySQL was found. Compare detected version and patch policy against current vendor security advisories.' $r.Output $r.Command } 'vendor patch status' }
        'D-26' { return Invoke-MySqlSqlCheck $state "SHOW VARIABLES WHERE Variable_name IN ('general_log','log_output','log_error','log_bin','server_audit_logging');" { param($r) if ($r.Output -match 'general_log\s+ON|log_bin\s+ON|server_audit_logging\s+ON') { New-MySqlResult 'GOOD' 'MySQL audit/general/binary log evidence was found.' $r.Output $r.Command } else { New-MySqlResult 'MANUAL' 'MySQL audit log evidence is incomplete; confirm institutional audit logging policy and plugin configuration.' $r.Output $r.Command } } 'audit logging policy' }
        default { return New-MySqlResult 'MANUAL' "No MySQL Windows diagnostic rule is defined for $ItemId." $evidence 'MySQL Windows generic discovery' }
    }
}
