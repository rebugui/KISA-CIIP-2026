#Requires -Version 5.1

function Add-OracleUniquePath {
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

function Get-OracleWindowsServices {
    try {
        @(Get-CimInstance Win32_Service -ErrorAction Stop | Where-Object {
            $_.Name -match '(?i)^Oracle(Service|Ora|.+TNSListener)' -or $_.DisplayName -match '(?i)Oracle'
        })
    } catch { @() }
}

function Get-OracleWindowsProcesses {
    try {
        @(Get-CimInstance Win32_Process -ErrorAction Stop | Where-Object {
            $_.Name -match '(?i)^(oracle|tnslsnr)\.exe$'
        })
    } catch { @() }
}

function Get-OracleCliPath {
    foreach ($cmd in @('sqlplus.exe', 'sqlplus')) {
        $found = Get-Command $cmd -ErrorAction SilentlyContinue
        if ($found) { return $found.Source }
    }
    foreach ($root in @($env:ORACLE_HOME, $env:ProgramFiles, ${env:ProgramFiles(x86)}, 'C:\oracle', 'C:\app')) {
        if ([string]::IsNullOrWhiteSpace($root) -or -not (Test-Path -LiteralPath $root -PathType Container)) { continue }
        $candidate = Get-ChildItem -LiteralPath $root -Recurse -File -Filter 'sqlplus.exe' -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -match '(?i)\\bin\\sqlplus\.exe$' } |
            Select-Object -First 1
        if ($candidate) { return $candidate.FullName }
    }
    return $null
}

function Get-OracleRegistryHomes {
    $homes = [System.Collections.Generic.List[string]]::new()
    foreach ($base in @('HKLM:\SOFTWARE\Oracle', 'HKLM:\SOFTWARE\WOW6432Node\Oracle')) {
        if (-not (Test-Path -LiteralPath $base)) { continue }
        foreach ($node in @(Get-ChildItem -LiteralPath $base -Recurse -ErrorAction SilentlyContinue | Select-Object -First 200)) {
            try {
                $props = Get-ItemProperty -LiteralPath $node.PSPath -ErrorAction Stop
                foreach ($name in @('ORACLE_HOME', 'OracleHome', 'ORACLE_HOME_NAME')) {
                    if ($props.$name) { Add-OracleUniquePath -Paths $homes -Candidate ([string]$props.$name) -PathType Container }
                }
            } catch {}
        }
    }
    return @($homes)
}

function Get-OracleWindowsState {
    $services = @(Get-OracleWindowsServices)
    $processes = @(Get-OracleWindowsProcesses)
    $homes = [System.Collections.Generic.List[string]]::new()
    Add-OracleUniquePath -Paths $homes -Candidate $env:ORACLE_HOME -PathType Container

    foreach ($service in $services) {
        $pathName = [string]$service.PathName
        if ($pathName -match '(?i)"([^"]*\\bin\\(?:oracle|tnslsnr)\.exe)"') {
            Add-OracleUniquePath -Paths $homes -Candidate (Split-Path -Parent (Split-Path -Parent $Matches[1])) -PathType Container
        }
        elseif ($pathName -match '(?i)(\S*\\bin\\(?:oracle|tnslsnr)\.exe)') {
            Add-OracleUniquePath -Paths $homes -Candidate (Split-Path -Parent (Split-Path -Parent $Matches[1])) -PathType Container
        }
    }
    foreach ($process in $processes) {
        if ($process.ExecutablePath -match '(?i)\\bin\\(?:oracle|tnslsnr)\.exe$') {
            Add-OracleUniquePath -Paths $homes -Candidate (Split-Path -Parent (Split-Path -Parent $process.ExecutablePath)) -PathType Container
        }
    }
    foreach ($home in Get-OracleRegistryHomes) {
        Add-OracleUniquePath -Paths $homes -Candidate $home -PathType Container
    }

    $configs = [System.Collections.Generic.List[string]]::new()
    foreach ($dir in @($env:TNS_ADMIN | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })) {
        Add-OracleUniquePath -Paths $configs -Candidate (Join-Path $dir 'listener.ora') -PathType Leaf
        Add-OracleUniquePath -Paths $configs -Candidate (Join-Path $dir 'sqlnet.ora') -PathType Leaf
        Add-OracleUniquePath -Paths $configs -Candidate (Join-Path $dir 'tnsnames.ora') -PathType Leaf
    }
    foreach ($home in $homes) {
        foreach ($candidate in @(
            (Join-Path $home 'network\admin\listener.ora'),
            (Join-Path $home 'network\admin\sqlnet.ora'),
            (Join-Path $home 'network\admin\tnsnames.ora')
        )) {
            Add-OracleUniquePath -Paths $configs -Candidate $candidate -PathType Leaf
        }
    }

    $initFiles = [System.Collections.Generic.List[string]]::new()
    foreach ($home in $homes) {
        foreach ($pattern in @('database\init*.ora', 'dbs\init*.ora', 'admin\*\pfile\init*.ora')) {
            Get-ChildItem -LiteralPath $home -Recurse -File -Filter (Split-Path $pattern -Leaf) -ErrorAction SilentlyContinue |
                Where-Object { $_.FullName -match [regex]::Escape((Split-Path $pattern -Leaf).Replace('*', '')) -or $_.Name -match '^init.*\.ora$' } |
                Select-Object -First 40 |
                ForEach-Object { Add-OracleUniquePath -Paths $initFiles -Candidate $_.FullName -PathType Leaf }
        }
    }

    $installedEvidence = ($services.Count -gt 0 -or $processes.Count -gt 0 -or $homes.Count -gt 0)

    [pscustomobject]@{
        Services = $services
        Processes = $processes
        OracleHomes = @($homes)
        ConfigFiles = @($configs)
        InitFiles = @($initFiles)
        CliPath = if ($installedEvidence) { Get-OracleCliPath } else { $null }
        Installed = $installedEvidence
    }
}

function Get-OracleWindowsEvidence {
    param($State)
    @(
        $State.Services | ForEach-Object { "Service $($_.Name) [$($_.State)] $($_.StartName): $($_.PathName)" }
        $State.Processes | ForEach-Object { "Process $($_.ProcessId): $($_.CommandLine)" }
        if ($State.OracleHomes.Count -gt 0) { "OracleHomes: $($State.OracleHomes -join ', ')" }
        if ($State.ConfigFiles.Count -gt 0) { "ConfigFiles: $($State.ConfigFiles -join ', ')" }
        if ($State.InitFiles.Count -gt 0) { "InitFiles: $($State.InitFiles -join ', ')" }
        if ($State.CliPath) { "CliPath: $($State.CliPath)" }
    ) -join "`n"
}

function New-OracleResult {
    param([string]$FinalResult, [string]$Summary, [string]$CommandOutput, [string]$CommandExecuted)
    $status = switch ($FinalResult) {
        'GOOD' { '양호' }
        'VULNERABLE' { '취약' }
        'N/A' { 'N/A' }
        default { '수동진단' }
    }
    [pscustomobject]@{ FinalResult = $FinalResult; Status = $status; Summary = $Summary; CommandOutput = $CommandOutput; CommandExecuted = $CommandExecuted }
}

function New-OracleNotInstalledResult {
    New-OracleResult 'N/A' 'Oracle Database for Windows service/process/home evidence was not found.' 'No Oracle service, oracle.exe/tnslsnr.exe process, or ORACLE_HOME evidence found.' 'Get-CimInstance Win32_Service/Win32_Process; inspect Oracle registry'
}

function Invoke-OracleQuery {
    param($State, [string]$Query)
    if (-not $State.CliPath) {
        return [pscustomobject]@{ Ok = $false; Output = 'sqlplus.exe client was not found.'; Command = 'sqlplus client discovery' }
    }
    if ($env:ORACLE_CONNECT_STRING) {
        $conn = $env:ORACLE_CONNECT_STRING
        $display = 'ORACLE_CONNECT_STRING'
    }
    elseif (($env:DB_USER -or $env:ORACLE_USER) -and ($env:DB_PASSWORD -or $env:ORACLE_PASSWORD)) {
        $user = if ($env:DB_USER) { $env:DB_USER } else { $env:ORACLE_USER }
        $password = if ($env:DB_PASSWORD) { $env:DB_PASSWORD } else { $env:ORACLE_PASSWORD }
        $hostName = if ($env:DB_HOST) { $env:DB_HOST } elseif ($env:ORACLE_HOST) { $env:ORACLE_HOST } else { 'localhost' }
        $port = if ($env:DB_PORT) { $env:DB_PORT } elseif ($env:ORACLE_PORT) { $env:ORACLE_PORT } else { '1521' }
        $service = if ($env:DB_NAME) { $env:DB_NAME } elseif ($env:ORACLE_SERVICE_NAME) { $env:ORACLE_SERVICE_NAME } elseif ($env:ORACLE_SID) { $env:ORACLE_SID } else { 'ORCL' }
        $conn = "$user/$password@${hostName}:$port/$service"
        $display = "$user/***@${hostName}:$port/$service"
    }
    else {
        $conn = '/ as sysdba'
        $display = '/ as sysdba'
    }
    $inputText = "set heading off feedback off pagesize 500 linesize 32767 trimspool on`n$Query`nexit`n"
    $output = $inputText | & $State.CliPath -L -S $conn 2>&1
    $exit = $LASTEXITCODE
    $text = (($output | Out-String).Trim())
    $ok = ($exit -eq 0 -and $text -notmatch '(?i)ORA-\d+|SP2-\d+|TNS-\d+')
    [pscustomobject]@{ Ok = $ok; Output = $text; Command = "$($State.CliPath) -L -S $display" }
}

function Invoke-OracleSqlCheck {
    param($State, [string]$Query, [scriptblock]$Judge, [string]$Description)
    $result = Invoke-OracleQuery -State $State -Query $Query
    if (-not $result.Ok) {
        return New-OracleResult 'MANUAL' "Oracle was found, but SQL evidence for $Description could not be collected automatically." ("Discovery evidence:`n$(Get-OracleWindowsEvidence -State $State)`n`nSQL output:`n$($result.Output)") $result.Command
    }
    & $Judge $result
}

function Get-OracleConfigLines {
    param($State, [string]$Pattern)
    foreach ($file in @($State.ConfigFiles + $State.InitFiles)) {
        $lines = @(Select-String -LiteralPath $file -Pattern $Pattern -ErrorAction SilentlyContinue)
        foreach ($line in $lines) { "${file}:$($line.LineNumber): $($line.Line.Trim())" }
    }
}

function Get-OracleVersionPair {
    param($State)
    $r = Invoke-OracleQuery -State $State -Query "SELECT BANNER FROM v`$version WHERE BANNER LIKE 'Oracle%';"
    if (-not $r.Ok) { return $null }
    $m = [regex]::Match($r.Output, '(?im)Oracle.*?(\d+)\.(\d+)')
    if (-not $m.Success) { return $null }
    [pscustomobject]@{ Major = [int]$m.Groups[1].Value; Minor = [int]$m.Groups[2].Value; Output = $r.Output; Command = $r.Command }
}

function Test-OracleBroadPrincipal {
    param([System.Security.Principal.IdentityReference]$Identity)
    try { $sid = $Identity.Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { $sid = [string]$Identity }
    return ($sid -eq 'S-1-1-0') -or ($sid -eq 'S-1-5-11') -or ($sid -eq 'S-1-5-32-545') -or ($sid -eq 'S-1-5-32-546') -or ($sid -match '-513$') -or (([string]$Identity) -match '(?i)Everyone|Authenticated Users|BUILTIN\\Users|Guests|Domain Users')
}

function Get-OracleBroadAclEvidence {
    param([string]$Path, [string]$Role)
    $writeRights = @([System.Security.AccessControl.FileSystemRights]::FullControl, [System.Security.AccessControl.FileSystemRights]::Modify, [System.Security.AccessControl.FileSystemRights]::Write, [System.Security.AccessControl.FileSystemRights]::WriteData, [System.Security.AccessControl.FileSystemRights]::AppendData, [System.Security.AccessControl.FileSystemRights]::CreateFiles, [System.Security.AccessControl.FileSystemRights]::CreateDirectories, [System.Security.AccessControl.FileSystemRights]::Delete, [System.Security.AccessControl.FileSystemRights]::ChangePermissions, [System.Security.AccessControl.FileSystemRights]::TakeOwnership)
    try { $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop } catch { return [pscustomobject]@{ Path = $Path; Role = $Role; Access = 'Unknown'; Principal = 'N/A'; Rights = "ACL read failed: $($_.Exception.Message)" } }
    foreach ($rule in $acl.Access) {
        if ($rule.AccessControlType -ne 'Allow' -or -not (Test-OracleBroadPrincipal -Identity $rule.IdentityReference)) { continue }
        foreach ($right in $writeRights) {
            if (($rule.FileSystemRights -band $right) -eq $right) {
                [pscustomobject]@{ Path = $Path; Role = $Role; Access = 'Write'; Principal = [string]$rule.IdentityReference; Rights = [string]$rule.FileSystemRights }
                break
            }
        }
    }
}

function Invoke-OracleWindowsCheck {
    param([string]$ItemId, [string]$ItemName)
    $state = Get-OracleWindowsState
    if (-not $state.Installed) { return New-OracleNotInstalledResult }
    $evidence = Get-OracleWindowsEvidence -State $state

    switch ($ItemId) {
        'D-01' { return Invoke-OracleSqlCheck $state "SELECT username||' '||account_status||' '||NVL(password_versions,'-') FROM dba_users WHERE username IN ('SYS','SYSTEM','DBSNMP','SYSMAN','OUTLN','SCOTT');" { param($r) if ($r.Output -match '(?im)^(SYS|SYSTEM|DBSNMP|SYSMAN|OUTLN|SCOTT)\s+OPEN') { New-OracleResult 'MANUAL' 'Default Oracle accounts are open; confirm password change, lock policy, and approved use.' $r.Output $r.Command } elseif ($r.Output -match '(?m)\S') { New-OracleResult 'GOOD' 'Default Oracle account evidence was collected without obvious open-account risk.' $r.Output $r.Command } else { New-OracleResult 'GOOD' 'No default Oracle account evidence was returned.' 'No rows returned.' $r.Command } } 'default account password policy' }
        'D-02' { return Invoke-OracleSqlCheck $state "SELECT username||' '||account_status FROM dba_users WHERE username IN ('SCOTT','HR','OE','PM','IX','SH','BI','ADAMS','CLARK','BLAKE','JONES','DEMO') OR username LIKE 'TEST%';" { param($r) if ($r.Output -match '(?im)\s+OPEN') { New-OracleResult 'VULNERABLE' 'Unnecessary Oracle sample/test accounts are open.' $r.Output $r.Command } elseif ($r.Output -match '(?m)\S') { New-OracleResult 'MANUAL' 'Sample/test Oracle accounts exist; confirm they are locked or approved.' $r.Output $r.Command } else { New-OracleResult 'GOOD' 'No obvious sample/test Oracle accounts were returned.' 'No rows returned.' $r.Command } } 'unnecessary account removal' }
        'D-03' { return Invoke-OracleSqlCheck $state "SELECT resource_name||'='||limit FROM dba_profiles WHERE profile='DEFAULT' AND resource_name IN ('PASSWORD_LIFE_TIME','PASSWORD_VERIFY_FUNCTION','FAILED_LOGIN_ATTEMPTS','PASSWORD_LOCK_TIME');" { param($r) if ($r.Output -match '(?im)PASSWORD_VERIFY_FUNCTION=NULL|PASSWORD_LIFE_TIME=UNLIMITED|FAILED_LOGIN_ATTEMPTS=UNLIMITED') { New-OracleResult 'VULNERABLE' 'Oracle DEFAULT profile password lifetime/complexity/lockout controls are weak.' $r.Output $r.Command } else { New-OracleResult 'GOOD' 'Oracle DEFAULT profile password controls appear configured.' $r.Output $r.Command } } 'password lifetime and complexity' }
        'D-04' { return Invoke-OracleSqlCheck $state "SELECT 'PW:'||username FROM v`$pwfile_users WHERE username NOT IN (SELECT grantee FROM dba_role_privs WHERE granted_role='DBA') AND username != 'INTERNAL' AND SYSDBA='TRUE' UNION ALL SELECT 'ADM:'||grantee FROM dba_sys_privs WHERE grantee NOT IN ('SYS','SYSTEM','DBA','AQ_ADMINISTRATOR_ROLE','DSYS','BACSYS','SCHEDULER_ADMIN','MSYS') AND admin_option='YES' AND grantee NOT IN (SELECT grantee FROM dba_role_privs WHERE granted_role='DBA') UNION ALL SELECT 'ROL:'||grantee FROM dba_role_privs WHERE granted_role='DBA' ORDER BY 1;" { param($r) if ($r.Output -match '(?im)^PW:\S|^ADM:\S') { New-OracleResult 'VULNERABLE' 'Non-default Oracle users have admin-equivalent privileges (SYSDBA or ADMIN_OPTION) without the DBA role.' $r.Output $r.Command } elseif ($r.Output -match '(?im)^ROL:(?!SYS$)(?!SYSTEM$)\S') { New-OracleResult 'MANUAL' 'Oracle DBA role grantees beyond SYS/SYSTEM exist; confirm only approved administrators are included.' $r.Output $r.Command } elseif ($r.Output -match '(?m)\S') { New-OracleResult 'GOOD' 'Only default administrative DBA grantees (SYS/SYSTEM) were obvious.' $r.Output $r.Command } else { New-OracleResult 'GOOD' 'No DBA role or admin-equivalent privilege evidence was returned.' 'No rows returned.' $r.Command } } 'administrator privilege restriction' }
        'D-05' { return Invoke-OracleSqlCheck $state "SELECT resource_name||'='||limit FROM dba_profiles WHERE resource_name IN ('PASSWORD_REUSE_TIME','PASSWORD_REUSE_MAX') ORDER BY profile,resource_name;" { param($r) if ($r.Output -match '(?im)=UNLIMITED|=DEFAULT') { New-OracleResult 'MANUAL' 'Oracle password reuse controls require profile-by-profile review.' $r.Output $r.Command } else { New-OracleResult 'GOOD' 'Oracle password reuse profile limits were collected without obvious unlimited evidence.' $r.Output $r.Command } } 'password reuse policy' }
        'D-06' { return Invoke-OracleSqlCheck $state "SELECT username FROM dba_users WHERE username IN ('DBA','ADMIN','OPER','SHARED') OR username LIKE 'APP_%' ORDER BY username;" { param($r) if ($r.Output -match '(?m)\S') { New-OracleResult 'MANUAL' 'Shared or privileged-looking Oracle accounts were found; confirm individual account assignment policy.' $r.Output $r.Command } else { New-OracleResult 'GOOD' 'No obvious shared Oracle account names were returned.' 'No rows returned.' $r.Command } } 'individual DB account assignment' }
        'D-07' { $accounts = @($state.Services | Where-Object { $_.Name -match '(?i)^OracleService' } | ForEach-Object { $_.StartName } | Where-Object { $_ }); if ($accounts -match '^(?i)(LocalSystem|NT AUTHORITY\\SYSTEM)$|Administrator') { return New-OracleResult 'VULNERABLE' 'Oracle database Windows service appears to run with administrator-equivalent OS privileges.' ($accounts -join ', ') 'Inspect Oracle Windows service StartName' }; if ($accounts.Count -gt 0) { return New-OracleResult 'GOOD' 'Oracle database Windows service account is not administrator-equivalent.' ($accounts -join ', ') 'Inspect Oracle Windows service StartName' }; return New-OracleResult 'MANUAL' 'Oracle database service account could not be determined.' $evidence 'Inspect Oracle Windows service StartName' }
        'D-08' { return Invoke-OracleSqlCheck $state "SELECT BANNER FROM v`$version WHERE BANNER LIKE 'Oracle%';" { param($r) $mv = [regex]::Match($r.Output, '(?im)Oracle.*?(\d+)\.(\d+)'); if (-not $mv.Success) { return New-OracleResult 'MANUAL' 'Oracle version could not be parsed; confirm password hash algorithm (PASSWORD_VERSIONS) manually.' $r.Output $r.Command }; $maj = [int]$mv.Groups[1].Value; $min = [int]$mv.Groups[2].Value; if ($maj -le 11 -or ($maj -eq 12 -and $min -lt 2)) { New-OracleResult 'VULNERABLE' "Oracle $maj.$min uses a password hash algorithm below SHA-256 (10g=MD5/11g=SHA-1/12.1=SHA-1). Upgrade to 12.2+ for SHA-512." $r.Output $r.Command } elseif (($maj -eq 12 -and $min -ge 2) -or $maj -ge 18) { New-OracleResult 'GOOD' "Oracle $maj.$min uses a SHA-256 or stronger password hash algorithm (SHA-512)." $r.Output $r.Command } else { New-OracleResult 'MANUAL' "Oracle $maj.$min password hash algorithm could not be determined automatically; confirm PASSWORD_VERSIONS manually." $r.Output $r.Command } } 'password hash algorithm strength' }
        'D-09' { return Invoke-OracleSqlCheck $state "SELECT resource_name||'='||limit FROM dba_profiles WHERE resource_name IN ('FAILED_LOGIN_ATTEMPTS','PASSWORD_LOCK_TIME') ORDER BY profile,resource_name;" { param($r) if ($r.Output -match '(?im)FAILED_LOGIN_ATTEMPTS=(UNLIMITED|0)') { New-OracleResult 'VULNERABLE' 'Oracle failed-login lockout profile controls are weak.' $r.Output $r.Command } else { New-OracleResult 'GOOD' 'Oracle failed-login lockout profile evidence was collected.' $r.Output $r.Command } } 'failed login lockout policy' }
        'D-10' { $lines = @(Get-OracleConfigLines $state '(?i)HOST\s*=|TCP\.VALIDNODE_CHECKING|TCP\.INVITED_NODES|TCP\.EXCLUDED_NODES'); $active = @($lines | Where-Object { ($_ -replace '^.*:\d+:\s*', '') -notmatch '^#' }); $validnodeOn = @($active | Where-Object { $_ -match '(?i)TCP\.VALIDNODE_CHECKING\s*=\s*(YES|ON|TRUE)' }).Count -gt 0; $nodeSet = @($active | Where-Object { $_ -match '(?i)TCP\.(INVITED|EXCLUDED)_NODES\s*=\s*\(' }).Count -gt 0; if ($validnodeOn -and $nodeSet) { return New-OracleResult 'GOOD' 'Oracle listener/sqlnet restricts access by IP (tcp.validnode_checking=yes with an invited/excluded node list).' ($active -join "`n") 'Inspect listener.ora/sqlnet.ora remote access controls' }; if ($active.Count -gt 0) { return New-OracleResult 'VULNERABLE' "Oracle remote access is not restricted to designated IPs (validnode_checking=$validnodeOn, invited/excluded_nodes=$nodeSet). Set tcp.validnode_checking=yes and tcp.invited_nodes." ($active -join "`n") 'Inspect listener.ora/sqlnet.ora remote access controls' }; return New-OracleResult 'MANUAL' 'Oracle remote access restriction evidence was not found; confirm listener binding and firewall policy.' (($lines + $evidence) -join "`n") 'Inspect listener.ora/sqlnet.ora remote access controls' }
        'D-11' { return Invoke-OracleSqlCheck $state "SELECT grantee||' '||owner||'.'||table_name||' '||privilege FROM dba_tab_privs WHERE (owner='SYS' OR table_name LIKE 'DBA_%') AND privilege <> 'EXECUTE' AND grantee NOT IN ('PUBLIC','AQ_ADMINISTRATOR_ROLE','AQ_USER_ROLE','AURORA`$JIS`$UTILITY`$','OSE`$HTTP`$ADMIN','TRACESVR','CTXSYS','DBA','DELETE_CATALOG_ROLE','EXECUTE_CATALOG_ROLE','EXP_FULL_DATABASE','GATHER_SYSTEM_STATISTICS','HS_ADMIN_ROLE','IMP_FULL_DATABASE','LOGSTDBY_ADMINISTRATOR','MDSYS','ODM','OEM_MONITOR','OLAPSYS','ORDSYS','OUTLN','RECOVERY_CATALOG_OWNER','SELECT_CATALOG_ROLE','SNMPAGENT','SYS','SYSTEM','WKSYS','WKUSER','WMSYS','WM_ADMIN_ROLE','XDB','LBACSYS','PERFSTAT','XDBADMIN','DBSNMP','SYSMAN') AND grantee NOT IN (SELECT grantee FROM dba_role_privs WHERE granted_role='DBA') AND ROWNUM <= 100;" { param($r) if ($r.Output -match '(?m)\S') { New-OracleResult 'VULNERABLE' 'Non-DBA Oracle system object privileges were found (KISA D-11 whitelist applied).' $r.Output $r.Command } else { New-OracleResult 'GOOD' 'No non-DBA Oracle system object privilege evidence was returned (KISA D-11 whitelist applied).' 'No rows returned.' $r.Command } } 'system table access restriction' }
        'D-12' { $ver = Get-OracleVersionPair $state; if ($ver -and (($ver.Major -eq 12 -and $ver.Minor -ge 2) -or $ver.Major -ge 18)) { return New-OracleResult 'N/A' "Oracle $($ver.Major).$($ver.Minor) does not support listener passwords (removed in 12c Release 2); use Oracle Wallet or OS authentication instead." $ver.Output $ver.Command }; $lines = @(Get-OracleConfigLines $state '(?i)PASSWORDS_.*=|ADMIN_RESTRICTIONS_.*='); $active = @($lines | Where-Object { ($_ -replace '^.*:\d+:\s*', '') -notmatch '^#' }); if ($active -match '(?i)PASSWORDS_.*=') { return New-OracleResult 'GOOD' 'Oracle listener password evidence (PASSWORDS_<listener>=) was found in listener.ora.' ($lines -join "`n") 'Inspect listener.ora password settings' }; if (-not $ver) { return New-OracleResult 'MANUAL' 'Oracle version could not be determined and no listener password was found; verify version and listener password manually.' (($lines + $evidence) -join "`n") 'Inspect listener.ora password settings' }; return New-OracleResult 'VULNERABLE' "Oracle $($ver.Major).$($ver.Minor) listener password (PASSWORDS_<listener>=) was not found in listener.ora." (($lines + $evidence) -join "`n") 'Inspect listener.ora password settings' }
        'D-13' { $oracleDrivers = @(@('HKLM:\SOFTWARE\ODBC\ODBCINST.INI','HKLM:\SOFTWARE\WOW6432Node\ODBC\ODBCINST.INI') | ForEach-Object { Get-ChildItem $_ -ErrorAction SilentlyContinue } | Where-Object { $_.PSChildName -match '(?i)Oracle' } | Select-Object -ExpandProperty PSChildName -Unique); if ($oracleDrivers.Count -gt 0) { return New-OracleResult 'MANUAL' 'Oracle ODBC drivers/data sources were found. Confirm only required DSNs/drivers remain.' ($oracleDrivers -join "`n") 'Inspect Windows ODBC registry driver entries (native + WOW6432Node)' }; $nonMsDrivers = @(@('HKLM:\SOFTWARE\ODBC\ODBCINST.INI','HKLM:\SOFTWARE\WOW6432Node\ODBC\ODBCINST.INI') | ForEach-Object { Get-ChildItem $_ -ErrorAction SilentlyContinue } | Where-Object { $_.PSChildName -notmatch '(?i)Oracle|Microsoft|SQL Server' } | Select-Object -ExpandProperty PSChildName -Unique); if ($nonMsDrivers.Count -gt 0) { return New-OracleResult 'MANUAL' 'Non-Microsoft, non-Oracle ODBC drivers were found on this Oracle DB server; confirm they are required (criteria_bad: 불필요한 ODBC가 설치된 경우).' ($nonMsDrivers -join "`n") 'Inspect Windows ODBC registry driver entries (native + WOW6432Node)' }; return New-OracleResult 'MANUAL' 'No Oracle or non-Microsoft ODBC driver entries were found in scanned paths (native + WOW6432Node), but ODBC data sources/DSNs (ODBC.INI) and OLE-DB providers (HKLM:\\SOFTWARE\\Classes\\OLEDB) were not scanned. Whether any installed ODBC/OLE-DB is unnecessary (criteria_bad: 불필요한 ODBC/OLE-DB가 설치된 경우) requires manual judgement. Manually confirm no unnecessary ODBC/OLE-DB data sources or providers remain.' 'No Oracle or non-Microsoft ODBC driver entries returned; ODBC DSNs and OLE-DB providers require manual confirmation.' 'Inspect Windows ODBC registry driver entries (native + WOW6432Node); also verify OLE-DB providers and ODBC DSNs manually.' }
        'D-14' { $targets = @($state.OracleHomes + $state.ConfigFiles + $state.InitFiles | Select-Object -Unique); $acl = @(foreach ($path in $targets) { Get-OracleBroadAclEvidence -Path $path -Role 'OraclePath' }); $aclUnknown = @($acl | Where-Object { $_.Access -eq 'Unknown' }); $aclBroad = @($acl | Where-Object { $_.Access -eq 'Write' }); if ($aclBroad.Count -gt 0) { return New-OracleResult 'VULNERABLE' 'Broad local write ACL evidence was found on Oracle paths (general user can modify major Oracle files).' (($aclBroad | ForEach-Object { "$($_.Path) => $($_.Principal) $($_.Access) ($($_.Rights))" }) -join "`n") 'Get-Acl Oracle directories/files' }; if ($targets.Count -eq 0) { return New-OracleResult 'MANUAL' 'Oracle paths were not found for ACL assessment.' $evidence 'Get-Acl Oracle directories/files' }; if ($aclUnknown.Count -gt 0) { return New-OracleResult 'MANUAL' 'Oracle path ACLs could not be read automatically (access denied/locked); confirm only administrators can modify the major Oracle files.' (($aclUnknown | ForEach-Object { "$($_.Path) => $($_.Rights)" }) -join "`n") 'Get-Acl Oracle directories/files' }; return New-OracleResult 'GOOD' 'No broad local write ACL entries were found on assessed Oracle paths.' ($targets -join ', ') 'Get-Acl Oracle directories/files' }
        'D-15' { $lines = @(Get-OracleConfigLines $state '(?i)ADMIN_RESTRICTIONS_.*=|TRACE_LEVEL_|LOG_DIRECTORY_|TRACE_DIRECTORY_'); $active = @($lines | Where-Object { ($_ -replace '^.*:\d+:\s*', '') -notmatch '^#' }); $adminOn = @($active | Where-Object { $_ -match '(?i)ADMIN_RESTRICTIONS_.*=\s*ON' }).Count -gt 0; if ($adminOn) { $aclTargets = [System.Collections.Generic.List[string]]::new(); foreach ($cfg in @($state.ConfigFiles | Where-Object { $_ -match '(?i)listener\.ora$' })) { if (-not $aclTargets.Contains($cfg)) { $aclTargets.Add($cfg) | Out-Null }; $parent = Split-Path -Parent $cfg; if ($parent -and -not $aclTargets.Contains($parent)) { $aclTargets.Add($parent) | Out-Null } }; $aclEvidence = @(foreach ($path in $aclTargets) { Get-OracleBroadAclEvidence -Path $path -Role 'ListenerConfig' }); $aclUnknown = @($aclEvidence | Where-Object { $_.Access -eq 'Unknown' }); $aclBroad = @($aclEvidence | Where-Object { $_.Access -eq 'Write' }); if ($aclBroad.Count -gt 0) { return New-OracleResult 'VULNERABLE' 'Oracle listener admin restriction (ADMIN_RESTRICTIONS=ON) is active, but listener config files/directory grant write access to a broad principal, so a general user can edit listener.ora and disable the control.' (($active -join "`n") + "`n" + (($aclBroad | ForEach-Object { "$($_.Path) => $($_.Principal) $($_.Access) ($($_.Rights))" }) -join "`n")) 'Inspect listener.ora admin restrictions; Get-Acl listener config files/directory' }; if ($aclTargets.Count -eq 0 -or $aclUnknown.Count -gt 0) { return New-OracleResult 'MANUAL' 'Oracle listener admin restriction (ADMIN_RESTRICTIONS=ON) is active, but listener config file/directory permissions could not be assessed automatically; confirm only administrators can modify listener.ora.' (($active -join "`n") + "`n" + (($aclUnknown | ForEach-Object { "$($_.Path) => $($_.Rights)" }) -join "`n")) 'Inspect listener.ora admin restrictions; Get-Acl listener config files/directory' }; return New-OracleResult 'GOOD' 'Oracle listener admin restriction is active (ADMIN_RESTRICTIONS=ON) and listener config files/directory are not writable by a broad principal.' (($active -join "`n") + "`n" + ($aclTargets -join ', ')) 'Inspect listener.ora admin restrictions; Get-Acl listener config files/directory' }; if ($active.Count -gt 0) { return New-OracleResult 'VULNERABLE' 'Oracle listener configuration is present but admin restriction (ADMIN_RESTRICTIONS=ON) is not active.' ($active -join "`n") 'Inspect listener.ora admin restrictions' }; return New-OracleResult 'MANUAL' 'Oracle listener admin restriction evidence (listener.ora) was not found; confirm ADMIN_RESTRICTIONS and listener file permissions manually.' (($lines + $evidence) -join "`n") 'Inspect listener.ora admin restrictions' }
        'D-16' { return New-OracleResult 'N/A' 'SQL Server Windows authentication mode control is not applicable to Oracle Database.' 'Oracle authentication is controlled by Oracle users, OS authentication, sqlnet.ora, and profiles.' 'Map DBMS authentication-mode guideline applicability' }
        'D-17' { return Invoke-OracleSqlCheck $state "SELECT 'OWNER:'||owner FROM dba_tables WHERE table_name='AUD`$' UNION ALL SELECT 'GRANT:'||grantee||' '||owner||'.'||table_name||' '||privilege FROM dba_tab_privs WHERE table_name LIKE 'AUD`$%' AND grantee NOT IN ('SYS','SYSTEM','DBA','AUDIT_ADMIN','DELETE_CATALOG_ROLE','SELECT_CATALOG_ROLE','EXECUTE_CATALOG_ROLE','AUDIT_VIEWER','EXP_FULL_DATABASE','IMP_FULL_DATABASE') AND grantee NOT IN (SELECT grantee FROM dba_role_privs WHERE granted_role='DBA') AND ROWNUM <= 100;" { param($r) $ownerLines = @(($r.Output -split '\r?\n') | Where-Object { $_ -match '(?i)^OWNER:' }); $grantLines = @(($r.Output -split '\r?\n') | Where-Object { $_ -match '(?i)^GRANT:\S' }); if ($grantLines.Count -gt 0) { New-OracleResult 'VULNERABLE' 'Oracle AUD$ privileges granted to non-administrative principals were found (KISA D-17 catalog-role allowlist applied).' $r.Output $r.Command } elseif ($ownerLines.Count -gt 0) { $bad = @($ownerLines | Where-Object { $_ -notmatch '(?i)^OWNER:(SYS|SYSTEM)\s*$' }); if ($bad.Count -gt 0) { New-OracleResult 'VULNERABLE' 'Oracle AUD$ table owner is not SYS/SYSTEM (KISA D-17 reference: ownership must be administrative).' $r.Output $r.Command } else { New-OracleResult 'GOOD' 'Oracle AUD$ table is owned by SYS/SYSTEM and no non-administrative grantees remain (KISA D-17 reference query).' $r.Output $r.Command } } else { New-OracleResult 'MANUAL' 'Oracle AUD$ ownership evidence was not returned; confirm audit table ownership and access manually.' $r.Output $r.Command } } 'audit table DBA-only access' }
        'D-18' { return Invoke-OracleSqlCheck $state "SELECT granted_role FROM dba_role_privs WHERE grantee='PUBLIC';" { param($r) if ($r.Output -match '(?m)\S') { New-OracleResult 'VULNERABLE' 'Oracle roles granted to PUBLIC were found (DBA/application role set to PUBLIC).' $r.Output $r.Command } else { New-OracleResult 'GOOD' 'No roles granted to PUBLIC were returned (DBA/application role not set to PUBLIC).' 'No rows returned.' $r.Command } } 'public role restriction' }
        'D-19' { return Invoke-OracleSqlCheck $state "SELECT name||'='||value FROM v`$parameter WHERE name IN ('os_roles','remote_os_authent','remote_os_roles');" { param($r) if ($r.Output -match '(?im)=TRUE') { New-OracleResult 'VULNERABLE' 'Oracle OS role/remote OS authentication parameters are enabled.' $r.Output $r.Command } else { New-OracleResult 'GOOD' 'Oracle OS role/remote OS authentication parameters appear disabled.' $r.Output $r.Command } } 'OS role and remote OS authentication restriction' }
        'D-20' { return Invoke-OracleSqlCheck $state "SELECT owner||'.'||object_name FROM dba_objects WHERE owner NOT IN ('SYS','SYSTEM','OUTLN','DBSNMP','XDB','WMSYS','CTXSYS','MDSYS','ORDSYS','ORDDATA') AND object_type IN ('TABLE','PROCEDURE','PACKAGE') AND ROWNUM <= 100;" { param($r) if ($r.Output -match '(?m)\S') { New-OracleResult 'MANUAL' 'Application-owned Oracle objects were found; confirm owners are authorized.' $r.Output $r.Command } else { New-OracleResult 'GOOD' 'No non-default Oracle object owner evidence was returned.' 'No rows returned.' $r.Command } } 'unauthorized object owner restriction' }
        'D-21' { return Invoke-OracleSqlCheck $state "SELECT grantee||' '||owner||'.'||table_name||' '||privilege FROM dba_tab_privs WHERE grantable='YES' AND owner NOT IN ('SYS','MDSYS','ORDPLUGINS','ORDSYS','SYSTEM','WMSYS','SDB','LBACSYS') AND grantee NOT IN ('SYS','SYSTEM','DBA') AND grantee NOT IN (SELECT grantee FROM dba_role_privs WHERE granted_role='DBA') AND ROWNUM <= 100;" { param($r) if ($r.Output -match '(?m)\S') { New-OracleResult 'MANUAL' 'Oracle object privileges with WITH GRANT OPTION were found outside KISA D-21 owner/DBA-role allowlist; confirm whether each grantee is a ROLE (양호) or a general user account (취약).' $r.Output $r.Command } else { New-OracleResult 'GOOD' 'No Oracle object privileges with WITH GRANT OPTION outside KISA D-21 owner/DBA-role allowlist were returned.' 'No rows returned.' $r.Command } } 'GRANT OPTION restriction' }
        'D-22' { return Invoke-OracleSqlCheck $state "SELECT name||'='||value FROM v`$parameter WHERE name='resource_limit';" { param($r) if ($r.Output -match '(?im)=TRUE') { New-OracleResult 'GOOD' 'Oracle RESOURCE_LIMIT is enabled.' $r.Output $r.Command } else { New-OracleResult 'VULNERABLE' 'Oracle RESOURCE_LIMIT is not enabled.' $r.Output $r.Command } } 'resource limit function' }
        'D-23' { return New-OracleResult 'N/A' 'SQL Server xp_cmdshell control is not applicable to Oracle Database.' 'Oracle has no xp_cmdshell feature.' 'Map DBMS command-shell guideline applicability' }
        'D-24' { return New-OracleResult 'N/A' 'SQL Server registry extended procedure control is not applicable to Oracle Database.' 'Oracle does not expose SQL Server registry extended procedures.' 'Map DBMS registry-procedure guideline applicability' }
        'D-25' { return Invoke-OracleSqlCheck $state "SELECT banner FROM v`$version WHERE banner LIKE 'Oracle%';" { param($r) New-OracleResult 'MANUAL' 'Oracle was found. Compare detected version and patch level against current Oracle Critical Patch Update guidance.' $r.Output $r.Command } 'vendor patch status' }
        'D-26' { return Invoke-OracleSqlCheck $state "SELECT name||'='||value FROM v`$parameter WHERE name IN ('audit_trail','unified_audit_sga_queue_size');" { param($r) if ($r.Output -match '(?im)audit_trail=(NONE|FALSE)') { New-OracleResult 'VULNERABLE' 'Oracle audit trail appears disabled.' $r.Output $r.Command } else { New-OracleResult 'MANUAL' 'Oracle audit evidence was collected; confirm it satisfies institutional audit retention and event policy.' $r.Output $r.Command } } 'audit logging policy' }
        default { return New-OracleResult 'MANUAL' "No Oracle Windows diagnostic rule is defined for $ItemId." $evidence 'Oracle Windows generic discovery' }
    }
}
