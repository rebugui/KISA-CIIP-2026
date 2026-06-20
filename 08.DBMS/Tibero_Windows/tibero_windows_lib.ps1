#Requires -Version 5.1

function Add-TiberoUniquePath {
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

function Get-TiberoWindowsServices {
    try {
        @(Get-CimInstance Win32_Service -ErrorAction Stop | Where-Object {
            $_.Name -match '(?i)tibero|tbsvr|tblistener' -or $_.DisplayName -match '(?i)tibero|tbsvr|tblistener'
        })
    } catch { @() }
}

function Get-TiberoWindowsProcesses {
    try {
        @(Get-CimInstance Win32_Process -ErrorAction Stop | Where-Object {
            $_.Name -match '(?i)^(tbsvr|tblistener|tbsql|tbboot|tbdown)\.exe$'
        })
    } catch { @() }
}

function Get-TiberoCliPath {
    foreach ($cmd in @('tbsql.exe', 'tbsql')) {
        $found = Get-Command $cmd -ErrorAction SilentlyContinue
        if ($found) { return $found.Source }
    }
    foreach ($root in @($env:TB_HOME, $env:ProgramFiles, ${env:ProgramFiles(x86)}, 'C:\TmaxData', 'C:\Tibero', 'C:\tibero')) {
        if ([string]::IsNullOrWhiteSpace($root) -or -not (Test-Path -LiteralPath $root -PathType Container)) { continue }
        $candidate = Get-ChildItem -LiteralPath $root -Recurse -File -Filter 'tbsql.exe' -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -match '(?i)\\bin\\tbsql\.exe$' } |
            Select-Object -First 1
        if ($candidate) { return $candidate.FullName }
    }
    return $null
}

function Get-TiberoWindowsState {
    $services = @(Get-TiberoWindowsServices)
    $processes = @(Get-TiberoWindowsProcesses)
    $homes = [System.Collections.Generic.List[string]]::new()
    Add-TiberoUniquePath -Paths $homes -Candidate $env:TB_HOME -PathType Container
    foreach ($obj in @($services + $processes)) {
        $cmd = if ($obj.PathName) { [string]$obj.PathName } else { [string]$obj.CommandLine }
        if ($cmd -match '(?i)"([^"]*\\bin\\(?:tbsvr|tblistener|tbsql)\.exe)"') {
            Add-TiberoUniquePath -Paths $homes -Candidate (Split-Path -Parent (Split-Path -Parent $Matches[1])) -PathType Container
        }
        elseif ($cmd -match '(?i)(\S*\\bin\\(?:tbsvr|tblistener|tbsql)\.exe)') {
            Add-TiberoUniquePath -Paths $homes -Candidate (Split-Path -Parent (Split-Path -Parent $Matches[1])) -PathType Container
        }
    }

    $configs = [System.Collections.Generic.List[string]]::new()
    foreach ($home in $homes) {
        foreach ($candidate in @(
            (Join-Path $home 'config\tbdsn.tbr'),
            (Join-Path $home 'client\config\tbdsn.tbr')
        )) {
            Add-TiberoUniquePath -Paths $configs -Candidate $candidate -PathType Leaf
        }
        Get-ChildItem -LiteralPath (Join-Path $home 'config') -File -Filter '*.tip' -ErrorAction SilentlyContinue |
            Select-Object -First 40 |
            ForEach-Object { Add-TiberoUniquePath -Paths $configs -Candidate $_.FullName -PathType Leaf }
    }

    $installedEvidence = ($services.Count -gt 0 -or $processes.Count -gt 0 -or $homes.Count -gt 0)
    [pscustomobject]@{
        Services = $services
        Processes = $processes
        TiberoHomes = @($homes)
        ConfigFiles = @($configs)
        CliPath = if ($installedEvidence) { Get-TiberoCliPath } else { $null }
        Installed = $installedEvidence
    }
}

function Get-TiberoWindowsEvidence {
    param($State)
    @(
        $State.Services | ForEach-Object { "Service $($_.Name) [$($_.State)] $($_.StartName): $($_.PathName)" }
        $State.Processes | ForEach-Object { "Process $($_.ProcessId): $($_.CommandLine)" }
        if ($State.TiberoHomes.Count -gt 0) { "TiberoHomes: $($State.TiberoHomes -join ', ')" }
        if ($State.ConfigFiles.Count -gt 0) { "ConfigFiles: $($State.ConfigFiles -join ', ')" }
        if ($State.CliPath) { "CliPath: $($State.CliPath)" }
    ) -join "`n"
}

function New-TiberoResult {
    param([string]$FinalResult, [string]$Summary, [string]$CommandOutput, [string]$CommandExecuted)
    $status = switch ($FinalResult) {
        'GOOD' { '양호' }
        'VULNERABLE' { '취약' }
        'N/A' { 'N/A' }
        default { '수동진단' }
    }
    [pscustomobject]@{ FinalResult = $FinalResult; Status = $status; Summary = $Summary; CommandOutput = $CommandOutput; CommandExecuted = $CommandExecuted }
}

function New-TiberoNotInstalledResult {
    New-TiberoResult 'N/A' 'Tibero for Windows service/process/home evidence was not found.' 'No Tibero service, tbsvr.exe/tblistener.exe process, or TB_HOME evidence found.' 'Get-CimInstance Win32_Service/Win32_Process; inspect TB_HOME'
}

function Invoke-TiberoQuery {
    param($State, [string]$Query)
    if (-not $State.CliPath) {
        return [pscustomobject]@{ Ok = $false; Output = 'tbsql.exe client was not found.'; Command = 'tbsql client discovery' }
    }
    if ($env:TIBERO_CONNECT_STRING) {
        $conn = $env:TIBERO_CONNECT_STRING
        $display = 'TIBERO_CONNECT_STRING'
    }
    elseif (($env:DB_USER -or $env:TIBERO_USER) -and ($env:DB_PASSWORD -or $env:TIBERO_PASSWORD)) {
        $user = if ($env:DB_USER) { $env:DB_USER } else { $env:TIBERO_USER }
        $password = if ($env:DB_PASSWORD) { $env:DB_PASSWORD } else { $env:TIBERO_PASSWORD }
        $hostName = if ($env:DB_HOST) { $env:DB_HOST } elseif ($env:TIBERO_HOST) { $env:TIBERO_HOST } else { 'localhost' }
        $port = if ($env:DB_PORT) { $env:DB_PORT } elseif ($env:TIBERO_PORT) { $env:TIBERO_PORT } else { '8629' }
        $service = if ($env:DB_NAME) { $env:DB_NAME } elseif ($env:TB_SID) { $env:TB_SID } else { 'tibero' }
        $conn = "$user/$password@${hostName}:$port/$service"
        $display = "$user/***@${hostName}:$port/$service"
    }
    else {
        $conn = 'sys/tibero'
        $display = 'sys/***'
    }
    $inputText = "set heading off feedback off pagesize 500 linesize 32767`n$Query`nexit`n"
    $output = $inputText | & $State.CliPath $conn 2>&1
    $exit = $LASTEXITCODE
    $text = (($output | Out-String).Trim())
    $ok = ($exit -eq 0 -and $text -notmatch '(?i)TBR-\d+|ERROR|failed')
    [pscustomobject]@{ Ok = $ok; Output = $text; Command = "$($State.CliPath) $display" }
}

function Invoke-TiberoSqlCheck {
    param($State, [string]$Query, [scriptblock]$Judge, [string]$Description)
    $result = Invoke-TiberoQuery -State $State -Query $Query
    if (-not $result.Ok) {
        return New-TiberoResult 'MANUAL' "Tibero was found, but SQL evidence for $Description could not be collected automatically." ("Discovery evidence:`n$(Get-TiberoWindowsEvidence -State $State)`n`nSQL output:`n$($result.Output)") $result.Command
    }
    & $Judge $result
}

function Get-TiberoConfigLines {
    param($State, [string]$Pattern)
    foreach ($file in $State.ConfigFiles) {
        $lines = @(Select-String -LiteralPath $file -Pattern $Pattern -ErrorAction SilentlyContinue)
        foreach ($line in $lines) { "${file}:$($line.LineNumber): $($line.Line.Trim())" }
    }
}

function Get-TiberoActiveConfigLines {
    param($State, [string]$Pattern)
    foreach ($file in $State.ConfigFiles) {
        $lines = @(Select-String -LiteralPath $file -Pattern $Pattern -ErrorAction SilentlyContinue)
        foreach ($line in $lines) {
            $trimmed = $line.Line.Trim()
            # Skip commented-out directives (first non-space char is '#' or ';', or a Tibero '--' SQL-style comment)
            if ($trimmed -match '^\s*(#|;|--)') { continue }
            "${file}:$($line.LineNumber): $trimmed"
        }
    }
}

function Test-TiberoBroadPrincipal {
    param([System.Security.Principal.IdentityReference]$Identity)
    try { $sid = $Identity.Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { $sid = [string]$Identity }
    return ($sid -eq 'S-1-1-0') -or ($sid -eq 'S-1-5-11') -or ($sid -eq 'S-1-5-32-545') -or ($sid -eq 'S-1-5-32-546') -or ($sid -match '-513$') -or (([string]$Identity) -match '(?i)Everyone|Authenticated Users|BUILTIN\\Users|Guests|Domain Users')
}

function Get-TiberoBroadAclEvidence {
    param([string]$Path, [string]$Role)
    $writeRights = @([System.Security.AccessControl.FileSystemRights]::FullControl, [System.Security.AccessControl.FileSystemRights]::Modify, [System.Security.AccessControl.FileSystemRights]::Write, [System.Security.AccessControl.FileSystemRights]::WriteData, [System.Security.AccessControl.FileSystemRights]::AppendData, [System.Security.AccessControl.FileSystemRights]::CreateFiles, [System.Security.AccessControl.FileSystemRights]::CreateDirectories, [System.Security.AccessControl.FileSystemRights]::Delete, [System.Security.AccessControl.FileSystemRights]::ChangePermissions, [System.Security.AccessControl.FileSystemRights]::TakeOwnership)
    try { $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop } catch { return [pscustomobject]@{ Path = $Path; Role = $Role; Access = 'Unknown'; Principal = 'N/A'; Rights = "ACL read failed: $($_.Exception.Message)" } }
    foreach ($rule in $acl.Access) {
        if ($rule.AccessControlType -ne 'Allow' -or -not (Test-TiberoBroadPrincipal -Identity $rule.IdentityReference)) { continue }
        foreach ($right in $writeRights) {
            if (($rule.FileSystemRights -band $right) -eq $right) {
                [pscustomobject]@{ Path = $Path; Role = $Role; Access = 'Write'; Principal = [string]$rule.IdentityReference; Rights = [string]$rule.FileSystemRights }
                break
            }
        }
    }
}

function Invoke-TiberoWindowsCheck {
    param([string]$ItemId, [string]$ItemName)
    $state = Get-TiberoWindowsState
    if (-not $state.Installed) { return New-TiberoNotInstalledResult }
    $evidence = Get-TiberoWindowsEvidence -State $state

    switch ($ItemId) {
        'D-01' { return Invoke-TiberoSqlCheck $state "SELECT username||' '||account_status FROM dba_users WHERE username IN ('SYS','SYSCAT','SYSGIS','OUTLN','TIBERO','TBSAMPLE');" { param($r) if ($r.Output -match '(?im)\s+OPEN') { New-TiberoResult 'MANUAL' 'Default Tibero accounts are open; confirm password change, lock policy, and approved use.' $r.Output $r.Command } elseif ($r.Output -match '(?m)\S') { New-TiberoResult 'GOOD' 'Default Tibero account evidence was collected without obvious open-account risk.' $r.Output $r.Command } else { New-TiberoResult 'GOOD' 'No default Tibero account evidence was returned.' 'No rows returned.' $r.Command } } 'default account password policy' }
        'D-02' { return Invoke-TiberoSqlCheck $state "SELECT username||' '||account_status FROM dba_users WHERE username IN ('TBSAMPLE','SAMPLE','TEST','DEMO') OR username LIKE 'TEST%';" { param($r) if ($r.Output -match '(?im)\s+OPEN') { New-TiberoResult 'VULNERABLE' 'Unnecessary Tibero sample/test accounts are open.' $r.Output $r.Command } elseif ($r.Output -match '(?m)\S') { New-TiberoResult 'MANUAL' 'Sample/test Tibero accounts exist; confirm they are locked or approved.' $r.Output $r.Command } else { New-TiberoResult 'GOOD' 'No obvious sample/test Tibero accounts were returned.' 'No rows returned.' $r.Command } } 'unnecessary account removal' }
        'D-03' { return Invoke-TiberoSqlCheck $state "SELECT resource_name||'='||limit FROM dba_profiles WHERE profile='DEFAULT' AND resource_name IN ('PASSWORD_LIFE_TIME','PASSWORD_VERIFY_FUNCTION','FAILED_LOGIN_ATTEMPTS','PASSWORD_LOCK_TIME');" { param($r) if ($r.Output -notmatch '(?m)\S') { New-TiberoResult 'VULNERABLE' 'Tibero DEFAULT profile returned no password lifetime/complexity/lockout policy rows; the control is not configured.' 'No rows returned (no DEFAULT profile password policy configured).' $r.Command } elseif ($r.Output -match '(?im)PASSWORD_VERIFY_FUNCTION=NULL|PASSWORD_VERIFY_FUNCTION=\s*$|PASSWORD_LIFE_TIME=UNLIMITED|FAILED_LOGIN_ATTEMPTS=UNLIMITED') { New-TiberoResult 'VULNERABLE' 'Tibero DEFAULT profile password lifetime/complexity/lockout controls are weak.' $r.Output $r.Command } elseif ($r.Output -notmatch '(?im)PASSWORD_VERIFY_FUNCTION\s*=') { New-TiberoResult 'VULNERABLE' 'Tibero DEFAULT profile is missing a PASSWORD_VERIFY_FUNCTION row; no password complexity verification is configured.' $r.Output $r.Command } else { New-TiberoResult 'GOOD' 'Tibero DEFAULT profile password controls appear configured.' $r.Output $r.Command } } 'password lifetime and complexity' }
        'D-04' { return Invoke-TiberoSqlCheck $state "SELECT grantee FROM dba_role_privs WHERE granted_role='DBA' ORDER BY grantee;" { param($r) if ($r.Output -match '(?m)\S') { New-TiberoResult 'MANUAL' 'Tibero DBA role grantees exist; confirm only approved administrators are included.' $r.Output $r.Command } else { New-TiberoResult 'GOOD' 'No Tibero DBA role grantee evidence was returned.' 'No rows returned.' $r.Command } } 'administrator privilege restriction' }
        'D-05' { return Invoke-TiberoSqlCheck $state "SELECT resource_name||'='||limit FROM dba_profiles WHERE resource_name IN ('PASSWORD_REUSE_TIME','PASSWORD_REUSE_MAX') ORDER BY profile,resource_name;" { param($r) if ($r.Output -notmatch '(?m)\S') { New-TiberoResult 'VULNERABLE' 'Tibero returned no PASSWORD_REUSE_TIME/PASSWORD_REUSE_MAX policy rows; the password-reuse control is not configured.' 'No rows returned (no password-reuse policy configured).' $r.Command } elseif ($r.Output -match '(?im)=UNLIMITED|=DEFAULT|=NULL|=\s*$') { New-TiberoResult 'MANUAL' 'Tibero password reuse controls require profile-by-profile review.' $r.Output $r.Command } else { New-TiberoResult 'GOOD' 'Tibero password reuse profile limits were collected without obvious unlimited evidence.' $r.Output $r.Command } } 'password reuse policy' }
        'D-06' { return Invoke-TiberoSqlCheck $state "SELECT username FROM dba_users WHERE username IN ('DBA','ADMIN','OPER','SHARED') OR username LIKE 'APP_%' ORDER BY username;" { param($r) if ($r.Output -match '(?m)\S') { New-TiberoResult 'MANUAL' 'Shared or privileged-looking Tibero accounts were found; confirm individual account assignment policy.' $r.Output $r.Command } else { New-TiberoResult 'GOOD' 'No obvious shared Tibero account names were returned.' 'No rows returned.' $r.Command } } 'individual DB account assignment' }
        'D-07' { return New-TiberoResult 'N/A' 'D-07 (root/administrator-equivalent service account restriction) does not target Tibero per the KISA CIIP 2026 guideline metadata (target: Oracle, MySQL, Altibase, Cubrid).' 'Tibero is out of scope for D-07; no service-account judgment is rendered.' 'Map DBMS service-account guideline applicability' }
        'D-08' { $lines = @(Get-TiberoConfigLines $state '(?i)ENCRYPT|SSL|WALLET|CERT'); if ($lines.Count -gt 0) { return New-TiberoResult 'MANUAL' 'Tibero encryption-related configuration evidence was found; confirm approved transport encryption policy.' ($lines -join "`n") 'Inspect Tibero config encryption settings' }; return New-TiberoResult 'MANUAL' 'Tibero network encryption evidence was not found; confirm transport encryption policy manually.' $evidence 'Inspect Tibero config encryption settings' }
        'D-09' { return Invoke-TiberoSqlCheck $state "SELECT resource_name||'='||limit FROM dba_profiles WHERE resource_name IN ('FAILED_LOGIN_ATTEMPTS','PASSWORD_LOCK_TIME') ORDER BY profile,resource_name;" { param($r) if ($r.Output -notmatch '(?m)\S') { New-TiberoResult 'VULNERABLE' 'Tibero returned no FAILED_LOGIN_ATTEMPTS/PASSWORD_LOCK_TIME policy rows; the login-failure lockout control is not configured.' 'No rows returned (no failed-login lockout policy configured).' $r.Command } elseif ($r.Output -match '(?im)FAILED_LOGIN_ATTEMPTS\s*=\s*UNLIMITED') { New-TiberoResult 'VULNERABLE' 'Tibero failed-login lockout profile controls are weak (FAILED_LOGIN_ATTEMPTS is UNLIMITED; no login-attempt limit).' $r.Output $r.Command } elseif ($r.Output -match '(?im)FAILED_LOGIN_ATTEMPTS\s*=\s*\d+') { New-TiberoResult 'GOOD' 'Tibero failed-login lockout profile evidence shows a concrete numeric FAILED_LOGIN_ATTEMPTS limit.' $r.Output $r.Command } else { New-TiberoResult 'MANUAL' 'Tibero failed-login lockout evidence does not show a concrete numeric FAILED_LOGIN_ATTEMPTS limit (value is unset, DEFAULT, blank, or only PASSWORD_LOCK_TIME was returned). Resolve the effective per-profile FAILED_LOGIN_ATTEMPTS and confirm a login-attempt limit is set; treat unset/DEFAULT/UNLIMITED as a finding.' $r.Output $r.Command } } 'failed login lockout policy' }
        'D-10' { $activeLines = @(Get-TiberoActiveConfigLines $state '(?i)LSNR_INVITED_IP|LSNR_DENIED_IP|LISTENER_PORT|LSNR_PORT'); $evidenceLines = @(Get-TiberoConfigLines $state '(?i)LSNR_INVITED_IP|LSNR_DENIED_IP|LISTENER_PORT|LSNR_PORT'); if ($activeLines -match '(?i)LSNR_INVITED_IP\s*=\s*\S') { return New-TiberoResult 'GOOD' 'Tibero listener IP restriction (active, non-commented LSNR_INVITED_IP with a value) was found.' ($activeLines -join "`n") 'Inspect Tibero listener access controls' }; if ($activeLines -match '(?i)LSNR_DENIED_IP\s*=\s*\S') { return New-TiberoResult 'MANUAL' 'Tibero listener has LSNR_DENIED_IP (denylist) but no LSNR_INVITED_IP (allowlist); a denylist alone permits all IPs except those explicitly denied, which does not satisfy the IP-restriction criteria. Confirm the firewall or allowlist policy.' ($activeLines -join "`n") 'Inspect Tibero listener access controls' }; return New-TiberoResult 'MANUAL' 'No active Tibero listener IP restriction was found (only commented or empty directives, if any); confirm firewall/listener policy.' (($evidenceLines + $evidence) -join "`n") 'Inspect Tibero listener access controls' }
        'D-11' { return Invoke-TiberoSqlCheck $state "SELECT grantee||' '||owner||'.'||table_name||' '||privilege FROM dba_tab_privs WHERE owner IN ('SYS','SYSCAT') AND grantee NOT IN ('SYS','SYSCAT','DBA') AND ROWNUM <= 100;" { param($r) if ($r.Output -match '(?m)\S') { New-TiberoResult 'VULNERABLE' 'Non-DBA Tibero system object privileges were found.' $r.Output $r.Command } else { New-TiberoResult 'GOOD' 'No non-DBA Tibero system object privilege evidence was returned.' 'No rows returned.' $r.Command } } 'system table access restriction' }
        'D-12' { return New-TiberoResult 'N/A' 'Oracle listener password control is not directly applicable to Tibero.' 'Tibero listener access is handled through Tibero listener configuration such as LSNR_INVITED_IP/LSNR_DENIED_IP and OS/service controls.' 'Map DBMS listener-password guideline applicability' }
        'D-13' { $drivers = @(Get-ChildItem 'HKLM:\SOFTWARE\ODBC\ODBCINST.INI' -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match '(?i)Tibero' } | Select-Object -ExpandProperty PSChildName); if ($drivers.Count -gt 0) { return New-TiberoResult 'MANUAL' 'Tibero ODBC drivers/data sources were found. Confirm only required DSNs/drivers remain.' ($drivers -join "`n") 'Inspect Windows ODBC registry driver entries' }; return New-TiberoResult 'GOOD' 'No Tibero ODBC driver entries were found in the inspected registry path.' 'No Tibero ODBC entries returned.' 'Inspect Windows ODBC registry driver entries' }
        'D-14' { return New-TiberoResult 'N/A' 'D-14 (main configuration/password file access-permission restriction) does not target Tibero per the KISA CIIP 2026 guideline metadata (target: Oracle, PostgreSQL, Cubrid).' 'Tibero is out of scope for D-14; no file-ACL judgment is rendered.' 'Map DBMS file-permission guideline applicability' }
        'D-15' { $lines = @(Get-TiberoConfigLines $state '(?i)AUDIT_FILE_DEST|AUDIT_FILE_SIZE|TRACE|LOG'); if ($lines.Count -gt 0) { return New-TiberoResult 'MANUAL' 'Tibero listener/log/trace configuration evidence was found; confirm write access is DBA-only.' ($lines -join "`n") 'Inspect Tibero log/trace configuration' }; return New-TiberoResult 'MANUAL' 'Tibero log/trace restriction evidence was not conclusive.' $evidence 'Inspect Tibero log/trace configuration' }
        'D-16' { return New-TiberoResult 'N/A' 'SQL Server Windows authentication mode control is not applicable to Tibero.' 'Tibero authentication is controlled by Tibero users, profiles, and DB/OS configuration.' 'Map DBMS authentication-mode guideline applicability' }
        'D-17' { return Invoke-TiberoSqlCheck $state "SELECT grantee||' '||owner||'.'||table_name||' '||privilege FROM dba_tab_privs WHERE table_name LIKE '%AUDIT%' AND grantee NOT IN ('SYS','SYSCAT','DBA') AND ROWNUM <= 100;" { param($r) if ($r.Output -match '(?m)\S') { New-TiberoResult 'VULNERABLE' 'Tibero audit table privileges granted to non-administrative principals were found.' $r.Output $r.Command } else { New-TiberoResult 'GOOD' 'No non-administrative Tibero audit table privilege evidence was returned.' 'No rows returned.' $r.Command } } 'audit table DBA-only access' }
        'D-18' { return Invoke-TiberoSqlCheck $state "SELECT granted_role FROM dba_role_privs WHERE grantee='PUBLIC' AND granted_role IN ('DBA');" { param($r) if ($r.Output -match '(?m)\S') { New-TiberoResult 'VULNERABLE' 'Tibero DBA-level role grants to PUBLIC were found.' $r.Output $r.Command } else { New-TiberoResult 'GOOD' 'No Tibero DBA-level role grants to PUBLIC were returned.' 'No rows returned.' $r.Command } } 'public role restriction' }
        'D-19' { return New-TiberoResult 'N/A' 'Oracle OS_ROLES/REMOTE_OS_AUTHENTICATION/REMOTE_OS_ROLES controls are not directly applicable to Tibero.' 'Tibero does not expose Oracle OS role parameters with the same semantics.' 'Map Oracle OS role guideline applicability' }
        'D-20' { return Invoke-TiberoSqlCheck $state "SELECT owner||'.'||object_name FROM dba_objects WHERE owner NOT IN ('SYS','SYSCAT','OUTLN') AND ROWNUM <= 100;" { param($r) if ($r.Output -match '(?m)\S') { New-TiberoResult 'MANUAL' 'Application-owned Tibero objects were found; confirm owners are authorized.' $r.Output $r.Command } else { New-TiberoResult 'GOOD' 'No non-default Tibero object owner evidence was returned.' 'No rows returned.' $r.Command } } 'unauthorized object owner restriction' }
        'D-21' { return Invoke-TiberoSqlCheck $state "SELECT grantee||' '||owner||'.'||table_name||' '||privilege FROM dba_tab_privs WHERE grantable='YES' AND grantee NOT IN ('SYS','SYSCAT') AND grantee NOT IN (SELECT grantee FROM dba_role_privs WHERE granted_role='DBA') AND ROWNUM <= 100;" { param($r) if ($r.Output -match '(?m)\S') { New-TiberoResult 'VULNERABLE' 'Tibero object privileges with grant option were found.' $r.Output $r.Command } else { New-TiberoResult 'GOOD' 'No Tibero object privileges with grant option were returned.' 'No rows returned.' $r.Command } } 'GRANT OPTION restriction' }
        'D-22' { $lines = @(Get-TiberoConfigLines $state '(?i)RESOURCE_LIMIT|RESOURCE_MANAGER|MAX_SESSION|MEMORY_TARGET'); if ($lines.Count -gt 0) { return New-TiberoResult 'MANUAL' 'Tibero resource-limit configuration evidence was found; confirm institutional threshold policy.' ($lines -join "`n") 'Inspect Tibero resource-limit configuration' }; return New-TiberoResult 'MANUAL' 'Tibero resource-limit evidence was not conclusive; confirm DB/profile resource policy.' $evidence 'Inspect Tibero resource-limit configuration' }
        'D-23' { return New-TiberoResult 'N/A' 'SQL Server xp_cmdshell control is not applicable to Tibero.' 'Tibero has no xp_cmdshell feature.' 'Map DBMS command-shell guideline applicability' }
        'D-24' { return New-TiberoResult 'N/A' 'SQL Server registry extended procedure control is not applicable to Tibero.' 'Tibero does not expose SQL Server registry extended procedures.' 'Map DBMS registry-procedure guideline applicability' }
        'D-25' { return Invoke-TiberoSqlCheck $state "SELECT * FROM v`$version;" { param($r) New-TiberoResult 'MANUAL' 'Tibero was found. Compare detected version and patch level against current TmaxTibero patch guidance.' $r.Output $r.Command } 'vendor patch status' }
        'D-26' { $lines = @(Get-TiberoConfigLines $state '(?i)AUDIT_TRAIL|AUDIT_SYS_OPERATIONS|AUDIT_FILE_DEST|AUDIT_FILE_SIZE'); if ($lines -match '(?i)AUDIT_TRAIL\s*=\s*(OS|DB|YES)|AUDIT_SYS_OPERATIONS\s*=\s*Y') { return New-TiberoResult 'MANUAL' 'Tibero audit configuration evidence was found; confirm retention and audited events satisfy policy.' ($lines -join "`n") 'Inspect Tibero audit configuration' }; return New-TiberoResult 'MANUAL' 'No Tibero audit configuration evidence was found in .tip/tbdsn config; Tibero object/system-privilege auditing is established via SQL AUDIT statements stored in the data dictionary, so review dictionary/SQL audit options to confirm the audit-log policy.' (($lines + $evidence) -join "`n") 'Inspect Tibero audit configuration; review dictionary/SQL audit options' }
        default { return New-TiberoResult 'MANUAL' "No Tibero Windows diagnostic rule is defined for $ItemId." $evidence 'Tibero Windows generic discovery' }
    }
}
