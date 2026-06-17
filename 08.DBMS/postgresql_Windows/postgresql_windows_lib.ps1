#Requires -Version 5.1

function Add-PostgreSqlUniquePath {
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

function Get-PostgreSqlWindowsServices {
    try {
        @(Get-CimInstance Win32_Service -ErrorAction Stop | Where-Object {
            $_.Name -match '(?i)postgres|pgsql' -or $_.DisplayName -match '(?i)postgres|pgsql'
        })
    } catch { @() }
}

function Get-PostgreSqlWindowsProcesses {
    try {
        @(Get-CimInstance Win32_Process -ErrorAction Stop | Where-Object {
            $_.Name -match '(?i)^postgres\.exe$'
        })
    } catch { @() }
}

function Get-PostgreSqlCliPath {
    $found = Get-Command 'psql.exe' -ErrorAction SilentlyContinue
    if ($found) { return $found.Source }
    foreach ($root in @($env:ProgramFiles, ${env:ProgramFiles(x86)}, 'C:\ProgramData', 'C:\tools')) {
        if ([string]::IsNullOrWhiteSpace($root) -or -not (Test-Path -LiteralPath $root -PathType Container)) { continue }
        $candidate = Get-ChildItem -LiteralPath $root -Recurse -File -Filter 'psql.exe' -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -match '(?i)\\bin\\psql\.exe$' } |
            Select-Object -First 1
        if ($candidate) { return $candidate.FullName }
    }
    return $null
}

function Get-PostgreSqlDataDirs {
    $dirs = [System.Collections.Generic.List[string]]::new()
    foreach ($service in Get-PostgreSqlWindowsServices) {
        $pathName = [string]$service.PathName
        if ($pathName -match '(?i)-D\s+"([^"]+)"') { Add-PostgreSqlUniquePath -Paths $dirs -Candidate $Matches[1] -PathType Container }
        elseif ($pathName -match '(?i)-D\s+([^\s]+)') { Add-PostgreSqlUniquePath -Paths $dirs -Candidate $Matches[1] -PathType Container }
    }
    foreach ($process in Get-PostgreSqlWindowsProcesses) {
        $cmd = [string]$process.CommandLine
        if ($cmd -match '(?i)-D\s+"([^"]+)"') { Add-PostgreSqlUniquePath -Paths $dirs -Candidate $Matches[1] -PathType Container }
        elseif ($cmd -match '(?i)-D\s+([^\s]+)') { Add-PostgreSqlUniquePath -Paths $dirs -Candidate $Matches[1] -PathType Container }
    }
    foreach ($root in @("$env:ProgramFiles\PostgreSQL", "${env:ProgramFiles(x86)}\PostgreSQL", 'C:\ProgramData\PostgreSQL')) {
        if ([string]::IsNullOrWhiteSpace($root) -or -not (Test-Path -LiteralPath $root -PathType Container)) { continue }
        foreach ($dir in @(Get-ChildItem -LiteralPath $root -Directory -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq 'data' } | Select-Object -First 20)) {
            Add-PostgreSqlUniquePath -Paths $dirs -Candidate $dir.FullName -PathType Container
        }
    }
    return @($dirs)
}

function Get-PostgreSqlWindowsState {
    $services = @(Get-PostgreSqlWindowsServices)
    $processes = @(Get-PostgreSqlWindowsProcesses)
    $dataDirs = @(Get-PostgreSqlDataDirs)
    $configs = [System.Collections.Generic.List[string]]::new()
    $hbas = [System.Collections.Generic.List[string]]::new()
    $logs = [System.Collections.Generic.List[string]]::new()
    foreach ($dir in $dataDirs) {
        Add-PostgreSqlUniquePath -Paths $configs -Candidate (Join-Path $dir 'postgresql.conf') -PathType Leaf
        Add-PostgreSqlUniquePath -Paths $hbas -Candidate (Join-Path $dir 'pg_hba.conf') -PathType Leaf
        Add-PostgreSqlUniquePath -Paths $hbas -Candidate (Join-Path $dir 'pg_ident.conf') -PathType Leaf
        Add-PostgreSqlUniquePath -Paths $logs -Candidate (Join-Path $dir 'log') -PathType Container
        Add-PostgreSqlUniquePath -Paths $logs -Candidate (Join-Path $dir 'pg_log') -PathType Container
    }
    [pscustomobject]@{
        Services = $services
        Processes = $processes
        DataDirs = $dataDirs
        ConfigFiles = @($configs)
        HbaFiles = @($hbas)
        LogDirs = @($logs)
        CliPath = Get-PostgreSqlCliPath
        Installed = ($services.Count -gt 0 -or $processes.Count -gt 0 -or $dataDirs.Count -gt 0)
    }
}

function Get-PostgreSqlWindowsEvidence {
    param($State)
    @(
        $State.Services | ForEach-Object { "Service $($_.Name) [$($_.State)] $($_.StartName): $($_.PathName)" }
        $State.Processes | ForEach-Object { "Process $($_.ProcessId): $($_.CommandLine)" }
        if ($State.DataDirs.Count -gt 0) { "DataDirs: $($State.DataDirs -join ', ')" }
        if ($State.ConfigFiles.Count -gt 0) { "ConfigFiles: $($State.ConfigFiles -join ', ')" }
        if ($State.HbaFiles.Count -gt 0) { "HbaFiles: $($State.HbaFiles -join ', ')" }
        if ($State.CliPath) { "CliPath: $($State.CliPath)" }
    ) -join "`n"
}

function Invoke-PostgreSqlQuery {
    param($State, [string]$Query)
    if (-not $State.CliPath) {
        return [pscustomobject]@{ Ok = $false; Output = 'psql.exe client was not found.'; Command = 'psql client discovery' }
    }
    $user = if ($env:DB_USER) { $env:DB_USER } elseif ($env:PGUSER) { $env:PGUSER } else { 'postgres' }
    $password = if ($env:DB_PASSWORD) { $env:DB_PASSWORD } else { $env:PGPASSWORD }
    $pgHost = if ($env:DB_HOST) { $env:DB_HOST } elseif ($env:PGHOST) { $env:PGHOST } else { 'localhost' }
    $port = if ($env:DB_PORT) { $env:DB_PORT } elseif ($env:PGPORT) { $env:PGPORT } else { '5432' }
    $db = if ($env:DB_NAME) { $env:DB_NAME } elseif ($env:PGDATABASE) { $env:PGDATABASE } else { 'postgres' }
    $oldPwd = $env:PGPASSWORD
    if ($password) { $env:PGPASSWORD = $password }
    try {
        $args = @('-X','-A','-t','-q','-h',$pgHost,'-p',$port,'-U',$user,'-d',$db,'-c',$Query)
        $output = & $State.CliPath @args 2>&1
        $exit = $LASTEXITCODE
    }
    finally {
        if ($null -ne $oldPwd) { $env:PGPASSWORD = $oldPwd } else { Remove-Item Env:\PGPASSWORD -ErrorAction SilentlyContinue }
    }
    [pscustomobject]@{ Ok = ($exit -eq 0); Output = (($output | Out-String).Trim()); Command = "$($State.CliPath) -h $pgHost -p $port -U $user -d $db -c <query>" }
}

function Test-PostgreSqlBroadPrincipal {
    param([System.Security.Principal.IdentityReference]$Identity)
    try { $sid = $Identity.Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { $sid = [string]$Identity }
    return ($sid -eq 'S-1-1-0') -or ($sid -eq 'S-1-5-11') -or ($sid -eq 'S-1-5-32-545') -or ($sid -eq 'S-1-5-32-546') -or ($sid -match '-513$') -or (([string]$Identity) -match '(?i)Everyone|Authenticated Users|BUILTIN\\Users|Guests|Domain Users')
}

function Test-PostgreSqlAnyRight {
    param([System.Security.AccessControl.FileSystemRights]$Rights, [System.Security.AccessControl.FileSystemRights[]]$Expected)
    foreach ($right in $Expected) { if (($Rights -band $right) -eq $right) { return $true } }
    return $false
}

function Get-PostgreSqlBroadAclEvidence {
    param([string]$Path, [string]$Role)
    $readRights = @([System.Security.AccessControl.FileSystemRights]::Read, [System.Security.AccessControl.FileSystemRights]::ReadAndExecute, [System.Security.AccessControl.FileSystemRights]::ListDirectory)
    $writeRights = @([System.Security.AccessControl.FileSystemRights]::FullControl, [System.Security.AccessControl.FileSystemRights]::Modify, [System.Security.AccessControl.FileSystemRights]::Write, [System.Security.AccessControl.FileSystemRights]::WriteData, [System.Security.AccessControl.FileSystemRights]::AppendData, [System.Security.AccessControl.FileSystemRights]::CreateFiles, [System.Security.AccessControl.FileSystemRights]::CreateDirectories, [System.Security.AccessControl.FileSystemRights]::Delete, [System.Security.AccessControl.FileSystemRights]::ChangePermissions, [System.Security.AccessControl.FileSystemRights]::TakeOwnership)
    try { $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop } catch { return [pscustomobject]@{ Path = $Path; Role = $Role; Access = 'Unknown'; Principal = 'N/A'; Rights = "ACL read failed: $($_.Exception.Message)" } }
    foreach ($rule in $acl.Access) {
        if ($rule.AccessControlType -ne 'Allow' -or -not (Test-PostgreSqlBroadPrincipal -Identity $rule.IdentityReference)) { continue }
        $hasWrite = Test-PostgreSqlAnyRight -Rights $rule.FileSystemRights -Expected $writeRights
        $hasRead = Test-PostgreSqlAnyRight -Rights $rule.FileSystemRights -Expected $readRights
        if ($hasWrite -or $hasRead) {
            [pscustomobject]@{ Path = $Path; Role = $Role; Access = if ($hasWrite) { 'Write' } else { 'Read' }; Principal = [string]$rule.IdentityReference; Rights = [string]$rule.FileSystemRights }
        }
    }
}

function New-PostgreSqlResult {
    param([string]$FinalResult, [string]$Summary, [string]$CommandOutput, [string]$CommandExecuted)
    $status = switch ($FinalResult) { 'GOOD' { '양호' } 'VULNERABLE' { '취약' } 'N/A' { 'N/A' } default { '수동진단' } }
    [pscustomobject]@{ FinalResult = $FinalResult; Status = $status; Summary = $Summary; CommandOutput = $CommandOutput; CommandExecuted = $CommandExecuted }
}

function New-PostgreSqlNotInstalledResult {
    New-PostgreSqlResult 'N/A' 'PostgreSQL for Windows service/process/configuration was not found.' 'No PostgreSQL service, process, or data directory evidence found.' 'Get-CimInstance Win32_Service/Win32_Process; known PostgreSQL paths'
}

function Invoke-PostgreSqlSqlCheck {
    param($State, [string]$Query, [scriptblock]$Judge, [string]$Description)
    $result = Invoke-PostgreSqlQuery -State $State -Query $Query
    if (-not $result.Ok) {
        return New-PostgreSqlResult 'MANUAL' "PostgreSQL was found, but SQL evidence for $Description could not be collected automatically." ("Discovery evidence:`n$(Get-PostgreSqlWindowsEvidence -State $State)`n`nSQL output:`n$($result.Output)") $result.Command
    }
    & $Judge $result
}

function Invoke-PostgreSqlWindowsCheck {
    param([string]$ItemId, [string]$ItemName)
    $state = Get-PostgreSqlWindowsState
    if (-not $state.Installed) { return New-PostgreSqlNotInstalledResult }
    $configText = @($state.ConfigFiles | ForEach-Object { "# FILE: $_`n" + (Get-Content -LiteralPath $_ -Raw -ErrorAction SilentlyContinue) }) -join "`n"
    $hbaText = @($state.HbaFiles | ForEach-Object { "# FILE: $_`n" + (Get-Content -LiteralPath $_ -Raw -ErrorAction SilentlyContinue) }) -join "`n"
    $evidence = Get-PostgreSqlWindowsEvidence -State $state

    switch ($ItemId) {
        'D-01' { return Invoke-PostgreSqlSqlCheck $state "SELECT rolname, rolcanlogin, rolpassword IS NULL AS empty_password FROM pg_authid WHERE rolname IN ('postgres','admin','test') OR rolname LIKE 'test%';" { param($r) if ($r.Output -match 'postgres\|t\|t|test') { New-PostgreSqlResult 'VULNERABLE' 'Default/test PostgreSQL account evidence or empty password evidence was found.' $r.Output $r.Command } elseif ($r.Output -match '(?m)\S') { New-PostgreSqlResult 'MANUAL' 'A default PostgreSQL account exists with a password set, but rolpassword IS NULL cannot prove it differs from the installer/deployment default; manually verify the default account initial password was changed (or the account locked) per criteria_bad (기본 계정 초기 비밀번호 미변경 여부 수동 확인 필요).' $r.Output $r.Command } else { New-PostgreSqlResult 'GOOD' 'No default/test PostgreSQL account row was returned (no default account left in default state).' $r.Output $r.Command } } 'default account password policy' }
        'D-02' { return Invoke-PostgreSqlSqlCheck $state "SELECT rolname FROM pg_roles WHERE rolname LIKE 'test%' OR rolname IN ('guest','demo');" { param($r) if ($r.Output -match '(?m)\S') { New-PostgreSqlResult 'VULNERABLE' 'Unnecessary PostgreSQL accounts were found.' $r.Output $r.Command } else { New-PostgreSqlResult 'MANUAL' '불필요한 계정 존재 여부는 기관의 계정 인가 정책에 의존하므로 전체 계정 목록을 수동 확인 필요 (자동 양호 판단 불가).' $r.Output $r.Command } } 'unnecessary account removal' }
        'D-03' { return Invoke-PostgreSqlSqlCheck $state "SELECT rolname, rolvaliduntil FROM pg_authid WHERE rolcanlogin;" { param($r) $expiryConcern = ($r.Output -match '(?m)\|$|infinity'); $preload = Invoke-PostgreSqlQuery -State $state -Query "SHOW shared_preload_libraries;"; $combinedOutput = "비밀번호 만료(rolvaliduntil) 점검:`n$($r.Output)`n`nshared_preload_libraries 점검:`n$(if ($preload.Ok) { $preload.Output } else { $preload.Output })"; $combinedCommand = "$($r.Command) ; $($preload.Command)"; if (-not $preload.Ok) { New-PostgreSqlResult 'MANUAL' 'PostgreSQL 비밀번호 만료(사용기간) 정보는 수집되었으나 shared_preload_libraries 조회 실패로 복잡도(passwordcheck) 강제 여부를 검증할 수 없어 자동 양호 판단 불가; 복잡도 강제 여부를 수동 확인 필요.' $combinedOutput $combinedCommand } elseif ($preload.Output -notmatch '(?i)passwordcheck') { New-PostgreSqlResult 'VULNERABLE' 'passwordcheck 가 shared_preload_libraries 에 로드되지 않아 비밀번호 복잡도가 강제되지 않음(취약); criteria_good 은 사용기간과 복잡도 설정을 모두 요구함.' $combinedOutput $combinedCommand } elseif ($expiryConcern) { New-PostgreSqlResult 'VULNERABLE' '비밀번호 복잡도(passwordcheck)는 강제되나 일부 로그인 롤의 비밀번호 사용기간(rolvaliduntil)이 무한/미설정되어 사용기간 정책이 적용되지 않음(취약); criteria_good 은 사용기간과 복잡도 설정을 모두 요구함.' $combinedOutput $combinedCommand } else { New-PostgreSqlResult 'GOOD' '비밀번호 사용기간(rolvaliduntil 유한) 및 복잡도(passwordcheck 로드)가 모두 설정됨.' $combinedOutput $combinedCommand } } 'password lifetime and complexity policy' }
        'D-04' { return Invoke-PostgreSqlSqlCheck $state "SELECT rolname FROM pg_roles WHERE rolsuper OR rolcreaterole OR rolcreatedb;" { param($r) if (($r.Output -replace '(?m)^postgres\s*$','' -replace '\s','') -eq '') { New-PostgreSqlResult 'GOOD' 'PostgreSQL admin roles exist only for the default superuser (postgres) as expected.' $r.Output $r.Command } elseif ($r.Output -match '(?m)\S') { New-PostgreSqlResult 'VULNERABLE' 'Non-default PostgreSQL administrative roles were found.' $r.Output $r.Command } else { New-PostgreSqlResult 'GOOD' 'No PostgreSQL administrative role evidence was returned.' 'No rows returned.' $r.Command } } 'administrator privilege restriction' }
        'D-05' { return New-PostgreSqlResult 'MANUAL' 'PostgreSQL does not enforce password reuse by core setting. Confirm password reuse policy via external auth/PAM/AD or extension.' $evidence 'Review PostgreSQL/external authentication password reuse controls' }
        'D-06' { return Invoke-PostgreSqlSqlCheck $state "SELECT count(*) FROM pg_roles WHERE rolcanlogin=true AND rolname NOT IN ('postgres');" { param($r) if ($r.Output -notmatch '^\d+$') { New-PostgreSqlResult 'MANUAL' 'PostgreSQL login role evidence could not be parsed; confirm individual account assignment policy manually (개별 계정 사용 여부 수동 확인 필요).' $r.Output $r.Command } elseif ([int]$r.Output -gt 0) { New-PostgreSqlResult 'GOOD' 'postgres 외 개별 사용자 계정이 부여되어 있습니다 (사용자별 계정 사용 중).' $r.Output $r.Command } else { New-PostgreSqlResult 'VULNERABLE' 'postgres 외 개별 사용자 계정이 없어 공용 계정(postgres) 공유 사용으로 판단됩니다. 사용자별 계정을 생성하여 사용하세요.' $r.Output $r.Command } } 'individual DB account assignment' }
        'D-07' { return New-PostgreSqlResult 'N/A' '해당 항목은 PostgreSQL 대상 아님 (guideline_metadata.json target: Oracle DB, MySQL, Altibase, Cubrid).' 'D-07 target excludes PostgreSQL.' 'guideline_metadata.json target lookup' }
        'D-08' { return Invoke-PostgreSqlSqlCheck $state "SHOW password_encryption;" { param($r) if ($r.Output -match '(?i)scram-sha-256') { New-PostgreSqlResult 'GOOD' 'PostgreSQL password hashing uses scram-sha-256 (SHA-256 이상).' $r.Output $r.Command } elseif ($r.Output -match '(?i)md5') { New-PostgreSqlResult 'VULNERABLE' 'PostgreSQL password hashing uses md5 (SHA-256 미만); change to scram-sha-256.' $r.Output $r.Command } else { New-PostgreSqlResult 'MANUAL' 'PostgreSQL password_encryption evidence could not be determined; verify hash algorithm policy.' $r.Output $r.Command } } 'password hash algorithm' }
        'D-09' { return New-PostgreSqlResult 'MANUAL' 'PostgreSQL login-failure lockout generally requires external auth or extension. Confirm institutional lockout control.' $evidence 'Review PostgreSQL authentication lockout controls' }
        'D-10' { if ($state.HbaFiles.Count -eq 0 -or [string]::IsNullOrWhiteSpace($hbaText)) { return New-PostgreSqlResult 'MANUAL' 'PostgreSQL pg_hba.conf was not discovered, so remote-access rules could not be evaluated; confirm the host access policy manually.' (("HbaFiles discovered: $($state.HbaFiles.Count)`n" + $evidence)) 'Parse pg_hba.conf remote access rules' }; if ($hbaText -match '(?im)^\s*host(ssl|nossl|gssenc|nogssenc)?\s+\S+\s+\S+\s+(0\.0\.0\.0/0|::/0)\s+') { return New-PostgreSqlResult 'VULNERABLE' 'pg_hba.conf allows broad remote database access.' $hbaText 'Parse pg_hba.conf remote access rules' }; if ($hbaText -match '(?im)^\s*host(ssl|nossl|gssenc|nogssenc)?\s+') { return New-PostgreSqlResult 'MANUAL' 'PostgreSQL host access rules exist; confirm each source CIDR is approved.' $hbaText 'Parse pg_hba.conf remote access rules' }; return New-PostgreSqlResult 'GOOD' 'No broad PostgreSQL host access rule evidence was found.' $hbaText 'Parse pg_hba.conf remote access rules' }
        'D-11' { return Invoke-PostgreSqlSqlCheck $state "SELECT grantee, table_name, privilege_type FROM information_schema.role_table_grants WHERE table_schema='pg_catalog' AND grantee NOT IN ('postgres','PUBLIC') AND privilege_type IN ('INSERT','UPDATE','DELETE','TRUNCATE','REFERENCES','TRIGGER');" { param($r) if ($r.Output -match '(?m)\S') { New-PostgreSqlResult 'VULNERABLE' 'Non-DBA write privileges on PostgreSQL system catalog tables were found.' $r.Output $r.Command } else { New-PostgreSqlResult 'GOOD' 'No non-DBA system catalog write privilege evidence was returned.' 'No rows returned.' $r.Command } } 'system table access restriction' }
        'D-12' { return New-PostgreSqlResult 'N/A' 'Oracle listener password control is not applicable to PostgreSQL.' 'PostgreSQL uses pg_hba.conf/listen_addresses instead of Oracle listener password.' 'Map DBMS listener-password guideline applicability' }
        'D-13' { $drivers = @(@('HKLM:\SOFTWARE\ODBC\ODBCINST.INI','HKLM:\SOFTWARE\WOW6432Node\ODBC\ODBCINST.INI') | ForEach-Object { Get-ChildItem $_ -ErrorAction SilentlyContinue } | Where-Object { $_.PSChildName -match '(?i)postgres|psql' } | Select-Object -ExpandProperty PSChildName -Unique); if ($drivers.Count -gt 0) { return New-PostgreSqlResult 'MANUAL' 'PostgreSQL ODBC drivers/data sources were found. Confirm only required DSNs/drivers remain.' ($drivers -join "`n") 'Inspect Windows ODBC registry driver entries (native + WOW6432Node)' }; return New-PostgreSqlResult 'GOOD' 'No PostgreSQL ODBC driver entries were found in the inspected registry paths.' 'No PostgreSQL ODBC entries returned.' 'Inspect Windows ODBC registry driver entries (native + WOW6432Node)' }
        'D-14' { $targets = @($state.ConfigFiles + $state.HbaFiles + $state.DataDirs | Select-Object -Unique); if ($targets.Count -eq 0) { return New-PostgreSqlResult 'MANUAL' 'PostgreSQL config/hba/data paths were not discovered, so file ACLs could not be evaluated; confirm the access permissions of the configuration, password, and data files manually.' $evidence 'Get-Acl PostgreSQL config files and data directories' }; $acl = foreach ($path in $targets) { Get-PostgreSqlBroadAclEvidence -Path $path -Role 'PostgreSqlPath' }; $bad = @($acl | Where-Object { $_.Access -eq 'Write' }); if ($bad.Count -gt 0) { return New-PostgreSqlResult 'VULNERABLE' 'Broad local write ACL evidence was found on PostgreSQL files/directories.' (($bad | ForEach-Object { "$($_.Path) => $($_.Principal) $($_.Access) ($($_.Rights))" }) -join "`n") 'Get-Acl PostgreSQL config files and data directories' }; $unknown = @($acl | Where-Object { $_.Access -eq 'Unknown' }); if ($unknown.Count -gt 0) { return New-PostgreSqlResult 'MANUAL' 'PostgreSQL file/directory ACLs could not be read automatically; confirm only administrators can modify the configuration, password, and data files manually.' (($unknown | ForEach-Object { "$($_.Path) => $($_.Rights)" }) -join "`n") 'Get-Acl PostgreSQL config files and data directories' }; if ($acl) { return New-PostgreSqlResult 'MANUAL' 'Broad local read ACL evidence was found on PostgreSQL paths; confirm sensitive files are excluded.' (($acl | ForEach-Object { "$($_.Path) => $($_.Principal) $($_.Access) ($($_.Rights))" }) -join "`n") 'Get-Acl PostgreSQL config files and data directories' }; return New-PostgreSqlResult 'GOOD' 'No broad local user ACL entries were found on assessed PostgreSQL paths.' ($targets -join ', ') 'Get-Acl PostgreSQL config files and data directories' }
        'D-15' { return New-PostgreSqlResult 'N/A' 'Oracle listener log/trace modification control is not applicable to PostgreSQL.' 'PostgreSQL has no Oracle listener component.' 'Map DBMS listener-log guideline applicability' }
        'D-16' { return New-PostgreSqlResult 'N/A' 'SQL Server Windows authentication mode control is not applicable to PostgreSQL.' 'PostgreSQL does not use SQL Server Windows authentication mode.' 'Map DBMS Windows-auth guideline applicability' }
        'D-17' { return New-PostgreSqlResult 'N/A' 'AuditTable DBA-only access control is Oracle-specific and not directly applicable to PostgreSQL.' 'PostgreSQL audit storage depends on logging/pgaudit implementation.' 'Map DBMS AuditTable guideline applicability' }
        'D-18' { return New-PostgreSqlResult 'N/A' '해당 항목은 PostgreSQL 대상 아님 (guideline_metadata.json target: Oracle DB, Altibase, Tibero, Cubrid).' 'D-18 target excludes PostgreSQL.' 'guideline_metadata.json target lookup' }
        'D-19' { return New-PostgreSqlResult 'N/A' 'OS_ROLES and REMOTE_OS_AUTHENTICATION controls are Oracle-specific and not applicable to PostgreSQL.' 'PostgreSQL does not expose OS_ROLES/REMOTE_OS_AUTHENTICATION/REMOTE_OS_ROLES parameters.' 'Map Oracle OS role guideline applicability' }
        'D-20' { return Invoke-PostgreSqlSqlCheck $state "SELECT relowner::regrole AS owner, COUNT(*) AS object_count FROM pg_class WHERE relowner NOT IN (SELECT usesysid FROM pg_user WHERE usesuper = TRUE) AND relkind IN ('r','v','m','f','p') GROUP BY relowner ORDER BY object_count DESC;" { param($r) if ($r.Output -match '(?m)\S') { New-PostgreSqlResult 'VULNERABLE' 'PostgreSQL objects owned by a non-superuser were found (ObjectOwner가 일반 사용자에게도 존재).' $r.Output $r.Command } else { New-PostgreSqlResult 'GOOD' 'No non-superuser PostgreSQL object owner evidence was returned (ObjectOwner가 관리자 계정으로 제한).' 'No rows returned.' $r.Command } } 'unauthorized object owner restriction' }
        'D-21' { return New-PostgreSqlResult 'N/A' '해당 항목은 PostgreSQL 대상 아님 (guideline_metadata.json target: Oracle DB, MySQL, Altibase, Tibero).' 'D-21 target excludes PostgreSQL.' 'guideline_metadata.json target lookup' }
        'D-22' { if ($configText -match '(?im)^\s*(statement_timeout|idle_in_transaction_session_timeout|temp_file_limit)\s*=\s*[^0#]') { return New-PostgreSqlResult 'GOOD' 'PostgreSQL resource limit settings were found.' $configText 'Parse postgresql.conf resource limit settings' }; return New-PostgreSqlResult 'MANUAL' 'PostgreSQL resource limit evidence is missing or incomplete; confirm institutional resource policy.' $configText 'Parse postgresql.conf resource limit settings' }
        'D-23' { return New-PostgreSqlResult 'N/A' 'SQL Server xp_cmdshell control is not applicable to PostgreSQL.' 'PostgreSQL has no xp_cmdshell feature.' 'Map SQL Server xp_cmdshell guideline applicability' }
        'D-24' { return New-PostgreSqlResult 'N/A' 'SQL Server registry procedure permission control is not applicable to PostgreSQL.' 'PostgreSQL has no SQL Server registry procedures.' 'Map SQL Server registry procedure guideline applicability' }
        'D-25' { return Invoke-PostgreSqlSqlCheck $state "SELECT version();" { param($r) New-PostgreSqlResult 'MANUAL' 'PostgreSQL was found. Compare detected version and patch policy against current vendor security advisories.' $r.Output $r.Command } 'vendor patch status' }
        'D-26' { if ($configText -match '(?im)^\s*logging_collector\s*=\s*on\b|^\s*log_statement\s*=\s*''?(all|ddl|mod)') { return New-PostgreSqlResult 'MANUAL' 'PostgreSQL logging settings were found, but logging is not equivalent to audit policy compliance; confirm the audit logging policy and pgaudit configuration manually (감사 정책 수동 확인 필요).' $configText 'Parse postgresql.conf logging settings' }; return New-PostgreSqlResult 'MANUAL' 'PostgreSQL audit logging evidence is incomplete; confirm institutional audit logging policy and pgaudit configuration (감사 정책 수동 확인 필요).' $configText 'Parse postgresql.conf logging settings' }
        default { return New-PostgreSqlResult 'MANUAL' "No PostgreSQL Windows diagnostic rule is defined for $ItemId." $evidence 'PostgreSQL Windows generic discovery' }
    }
}
