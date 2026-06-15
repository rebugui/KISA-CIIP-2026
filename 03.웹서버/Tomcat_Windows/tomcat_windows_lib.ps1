#Requires -Version 5.1

function Add-TomcatUniquePath {
    param(
        [System.Collections.Generic.List[string]]$Paths,
        [string]$Candidate,
        [string]$PathType = 'Any'
    )

    if ([string]::IsNullOrWhiteSpace($Candidate)) { return }
    try {
        $resolved = [System.IO.Path]::GetFullPath($Candidate.Trim('"'))
    }
    catch {
        return
    }

    $exists = switch ($PathType) {
        'Leaf' { Test-Path -LiteralPath $resolved -PathType Leaf }
        'Container' { Test-Path -LiteralPath $resolved -PathType Container }
        default { Test-Path -LiteralPath $resolved }
    }
    if ($exists -and -not $Paths.Contains($resolved)) {
        $Paths.Add($resolved) | Out-Null
    }
}

function Get-TomcatWindowsServices {
    try {
        @(Get-CimInstance Win32_Service -ErrorAction Stop | Where-Object {
            $_.Name -match '(?i)tomcat|catalina' -or $_.DisplayName -match '(?i)tomcat|catalina'
        })
    }
    catch { @() }
}

function Get-TomcatWindowsProcesses {
    try {
        @(Get-CimInstance Win32_Process -ErrorAction Stop | Where-Object {
            $_.Name -match '(?i)^(tomcat\d*w?|java|javaw)\.exe$' -and
            ($_.CommandLine -match '(?i)tomcat|catalina|org\.apache\.catalina')
        })
    }
    catch { @() }
}

function Get-TomcatHomeCandidates {
    $homes = [System.Collections.Generic.List[string]]::new()
    foreach ($envName in 'CATALINA_HOME','CATALINA_BASE','TOMCAT_HOME') {
        Add-TomcatUniquePath -Paths $homes -Candidate ([Environment]::GetEnvironmentVariable($envName)) -PathType Container
    }

    foreach ($root in @($env:ProgramFiles, ${env:ProgramFiles(x86)}, 'C:\Apache', 'C:\Tomcat', 'C:\tools', 'C:\ProgramData')) {
        if ([string]::IsNullOrWhiteSpace($root) -or -not (Test-Path -LiteralPath $root -PathType Container)) { continue }
        foreach ($dir in @(Get-ChildItem -LiteralPath $root -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '(?i)tomcat|apache-tomcat' })) {
            Add-TomcatUniquePath -Paths $homes -Candidate $dir.FullName -PathType Container
        }
        foreach ($dir in @(Get-ChildItem -LiteralPath $root -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '(?i)Apache Software Foundation' })) {
            foreach ($child in @(Get-ChildItem -LiteralPath $dir.FullName -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '(?i)tomcat' })) {
                Add-TomcatUniquePath -Paths $homes -Candidate $child.FullName -PathType Container
            }
        }
    }

    foreach ($service in Get-TomcatWindowsServices) {
        $pathName = [string]$service.PathName
        if ($pathName -match '(?i)(?:--Classpath|--StartPath|--StopPath|--JvmOptions)\s+"?([^"]*tomcat[^"]*)"?') {
            Add-TomcatUniquePath -Paths $homes -Candidate $Matches[1] -PathType Container
        }
        if ($pathName -match '(?i)"([^"]*\\bin\\(?:tomcat\d*w?|catalina|service)\.exe)"') {
            Add-TomcatUniquePath -Paths $homes -Candidate (Split-Path -Parent (Split-Path -Parent $Matches[1])) -PathType Container
        }
        elseif ($pathName -match '(?i)(\S*\\bin\\(?:tomcat\d*w?|catalina|service)\.exe)') {
            Add-TomcatUniquePath -Paths $homes -Candidate (Split-Path -Parent (Split-Path -Parent $Matches[1])) -PathType Container
        }
    }

    foreach ($process in Get-TomcatWindowsProcesses) {
        $cmd = [string]$process.CommandLine
        if ($cmd -match '(?i)-Dcatalina\.base="?([^"\s]+)"?') {
            Add-TomcatUniquePath -Paths $homes -Candidate $Matches[1] -PathType Container
        }
        if ($cmd -match '(?i)-Dcatalina\.home="?([^"\s]+)"?') {
            Add-TomcatUniquePath -Paths $homes -Candidate $Matches[1] -PathType Container
        }
    }

    return @($homes)
}

function Get-TomcatWindowsState {
    $services = @(Get-TomcatWindowsServices)
    $processes = @(Get-TomcatWindowsProcesses)
    $homes = @(Get-TomcatHomeCandidates)
    $serverXml = [System.Collections.Generic.List[string]]::new()
    $tomcatUsersXml = [System.Collections.Generic.List[string]]::new()
    $webXml = [System.Collections.Generic.List[string]]::new()
    $contextXml = [System.Collections.Generic.List[string]]::new()
    $webapps = [System.Collections.Generic.List[string]]::new()
    $logs = [System.Collections.Generic.List[string]]::new()
    $temp = [System.Collections.Generic.List[string]]::new()

    foreach ($home in $homes) {
        Add-TomcatUniquePath -Paths $serverXml -Candidate (Join-Path $home 'conf\server.xml') -PathType Leaf
        Add-TomcatUniquePath -Paths $tomcatUsersXml -Candidate (Join-Path $home 'conf\tomcat-users.xml') -PathType Leaf
        Add-TomcatUniquePath -Paths $webXml -Candidate (Join-Path $home 'conf\web.xml') -PathType Leaf
        Add-TomcatUniquePath -Paths $contextXml -Candidate (Join-Path $home 'conf\context.xml') -PathType Leaf
        Add-TomcatUniquePath -Paths $webapps -Candidate (Join-Path $home 'webapps') -PathType Container
        Add-TomcatUniquePath -Paths $logs -Candidate (Join-Path $home 'logs') -PathType Container
        Add-TomcatUniquePath -Paths $temp -Candidate (Join-Path $home 'temp') -PathType Container
    }

    foreach ($webappRoot in @($webapps)) {
        foreach ($file in @(Get-ChildItem -LiteralPath $webappRoot -Recurse -File -Filter 'web.xml' -ErrorAction SilentlyContinue | Select-Object -First 100)) {
            Add-TomcatUniquePath -Paths $webXml -Candidate $file.FullName -PathType Leaf
        }
    }

    [pscustomobject]@{
        Services = $services
        Processes = $processes
        Homes = $homes
        ServerXml = @($serverXml)
        TomcatUsersXml = @($tomcatUsersXml)
        WebXml = @($webXml)
        ContextXml = @($contextXml)
        Webapps = @($webapps)
        Logs = @($logs)
        Temp = @($temp)
        Installed = ($services.Count -gt 0 -or $processes.Count -gt 0 -or $homes.Count -gt 0)
    }
}

function Get-TomcatText {
    param([string[]]$Files)
    @($Files | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | ForEach-Object {
        "`n# FILE: $_`n" + (Get-Content -LiteralPath $_ -Raw -ErrorAction Stop)
    }) -join "`n"
}

function Get-TomcatWindowsEvidence {
    param($State)
    @(
        $State.Services | ForEach-Object { "Service $($_.Name) [$($_.State)] $($_.StartName): $($_.PathName)" }
        $State.Processes | ForEach-Object { "Process $($_.ProcessId): $($_.CommandLine)" }
        if ($State.Homes.Count -gt 0) { "Homes: $($State.Homes -join ', ')" }
    ) -join "`n"
}

function Test-TomcatBroadPrincipal {
    param([System.Security.Principal.IdentityReference]$Identity)
    try { $sid = $Identity.Translate([System.Security.Principal.SecurityIdentifier]).Value }
    catch { $sid = [string]$Identity }

    return ($sid -eq 'S-1-1-0') -or ($sid -eq 'S-1-5-11') -or ($sid -eq 'S-1-5-32-545') -or ($sid -eq 'S-1-5-32-546') -or ($sid -match '-513$') -or (([string]$Identity) -match '(?i)Everyone|Authenticated Users|BUILTIN\\Users|Guests|Domain Users')
}

function Test-TomcatAnyRight {
    param(
        [System.Security.AccessControl.FileSystemRights]$Rights,
        [System.Security.AccessControl.FileSystemRights[]]$Expected
    )
    foreach ($right in $Expected) {
        if (($Rights -band $right) -eq $right) { return $true }
    }
    return $false
}

function Get-TomcatBroadAclEvidence {
    param(
        [string]$Path,
        [string]$Role
    )
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

    try { $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop }
    catch {
        return [pscustomobject]@{ Path = $Path; Role = $Role; Access = 'Unknown'; Principal = 'N/A'; Rights = "ACL read failed: $($_.Exception.Message)" }
    }

    foreach ($rule in $acl.Access) {
        if ($rule.AccessControlType -ne 'Allow' -or -not (Test-TomcatBroadPrincipal -Identity $rule.IdentityReference)) { continue }
        $hasWrite = Test-TomcatAnyRight -Rights $rule.FileSystemRights -Expected $writeRights
        $hasRead = Test-TomcatAnyRight -Rights $rule.FileSystemRights -Expected $readRights
        if ($hasWrite -or $hasRead) {
            [pscustomobject]@{
                Path = $Path
                Role = $Role
                Access = if ($hasWrite) { 'Write' } else { 'Read' }
                Principal = [string]$rule.IdentityReference
                Rights = [string]$rule.FileSystemRights
            }
        }
    }
}

function New-TomcatResult {
    param(
        [string]$FinalResult,
        [string]$Summary,
        [string]$CommandOutput,
        [string]$CommandExecuted
    )
    $status = switch ($FinalResult) {
        'GOOD' { '양호' }
        'VULNERABLE' { '취약' }
        'N/A' { 'N/A' }
        default { '수동진단' }
    }
    [pscustomobject]@{
        FinalResult = $FinalResult
        Status = $status
        Summary = $Summary
        CommandOutput = $CommandOutput
        CommandExecuted = $CommandExecuted
    }
}

function New-TomcatNotInstalledResult {
    New-TomcatResult -FinalResult 'N/A' -Summary 'Tomcat for Windows service/process/configuration was not found.' -CommandOutput 'No Tomcat service, Tomcat process, or known Tomcat home path found.' -CommandExecuted 'Get-CimInstance Win32_Service/Win32_Process; known Tomcat home paths'
}

function Invoke-TomcatWindowsCheck {
    param(
        [string]$ItemId,
        [string]$ItemName
    )

    $state = Get-TomcatWindowsState
    if (-not $state.Installed) { return New-TomcatNotInstalledResult }

    $serverText = Get-TomcatText -Files $state.ServerXml
    $usersText = Get-TomcatText -Files $state.TomcatUsersXml
    $webText = Get-TomcatText -Files $state.WebXml
    $contextText = Get-TomcatText -Files $state.ContextXml
    $allText = @($serverText, $usersText, $webText, $contextText) -join "`n"
    $evidencePrefix = Get-TomcatWindowsEvidence -State $state

    switch ($ItemId) {
        'WEB-01' {
            if ($state.TomcatUsersXml.Count -eq 0) { return New-TomcatResult 'MANUAL' 'Tomcat was found, but tomcat-users.xml was not located.' $evidencePrefix 'Locate tomcat-users.xml and inspect default administrator account names' }
            $matches = @([regex]::Matches($usersText, '(?i)<user\b[^>]*username\s*=\s*"(admin|tomcat|root|manager)"[^>]*') | ForEach-Object { $_.Value.Trim() })
            if ($matches.Count -gt 0) { return New-TomcatResult 'VULNERABLE' 'Default or easily guessed Tomcat administrator account names were found.' ($matches -join "`n") 'Parse tomcat-users.xml usernames' }
            return New-TomcatResult 'GOOD' 'No default Tomcat administrator account names were found in tomcat-users.xml.' "Files: $($state.TomcatUsersXml -join ', ')" 'Parse tomcat-users.xml usernames'
        }
        'WEB-02' {
            if ($state.TomcatUsersXml.Count -eq 0) { return New-TomcatResult 'MANUAL' 'Tomcat was found, but tomcat-users.xml was not located.' $evidencePrefix 'Locate tomcat-users.xml and inspect password policy' }
            $weak = @([regex]::Matches($usersText, '(?is)<user\b[^>]*username\s*=\s*"([^"]+)"[^>]*password\s*=\s*"([^"]*)"[^>]*') | Where-Object {
                $u = $_.Groups[1].Value; $p = $_.Groups[2].Value
                $p -eq $u -or $p -match '^(?i)(admin|tomcat|password|1234|12345|123456|qwerty|manager|root|changeme)$'
            } | ForEach-Object { $_.Value.Trim() })
            if ($weak.Count -gt 0) { return New-TomcatResult 'VULNERABLE' 'Weak Tomcat user passwords were found in tomcat-users.xml.' ($weak -join "`n") 'Parse tomcat-users.xml password attributes' }
            $users = @([regex]::Matches($usersText, '(?is)<user\b[^>]*password\s*=') | ForEach-Object { $_.Value })
            if ($users.Count -gt 0) { return New-TomcatResult 'MANUAL' 'Tomcat user password attributes exist. Static checks found no common weak password, but complexity and rotation policy require manual review.' "Password-bearing user entries: $($users.Count)" 'Parse tomcat-users.xml password attributes' }
            return New-TomcatResult 'GOOD' 'No local Tomcat password attributes were found in tomcat-users.xml.' "Files: $($state.TomcatUsersXml -join ', ')" 'Parse tomcat-users.xml password attributes'
        }
        'WEB-03' {
            if ($state.TomcatUsersXml.Count -eq 0) { return New-TomcatResult 'MANUAL' 'Tomcat was found, but tomcat-users.xml was not located.' $evidencePrefix 'Inspect tomcat-users.xml ACLs' }
            $acl = foreach ($file in $state.TomcatUsersXml) { Get-TomcatBroadAclEvidence -Path $file -Role 'PasswordFile' }
            $bad = @($acl | Where-Object { $_.Access -eq 'Write' -or $_.Access -eq 'Read' -or $_.Access -eq 'Unknown' })
            if ($bad.Count -gt 0) { return New-TomcatResult 'VULNERABLE' 'tomcat-users.xml has broad local user ACL evidence.' (($bad | ForEach-Object { "$($_.Path) => $($_.Principal) $($_.Access) ($($_.Rights))" }) -join "`n") 'Get-Acl tomcat-users.xml' }
            return New-TomcatResult 'GOOD' 'No broad local user ACL entries were found on tomcat-users.xml.' "Files: $($state.TomcatUsersXml -join ', ')" 'Get-Acl tomcat-users.xml'
        }
        'WEB-04' {
            $listings = @([regex]::Matches($webText, '(?is)<param-name>\s*listings\s*</param-name>\s*<param-value>\s*(true|false)\s*</param-value>') | ForEach-Object { $_.Groups[1].Value })
            if ($listings -contains 'true') { return New-TomcatResult 'VULNERABLE' 'Tomcat directory listings are enabled.' ($listings -join ', ') 'Parse web.xml listings init-param' }
            if ($listings -contains 'false') { return New-TomcatResult 'GOOD' 'Tomcat directory listings are explicitly disabled.' ($listings -join ', ') 'Parse web.xml listings init-param' }
            return New-TomcatResult 'MANUAL' 'No explicit Tomcat directory listing setting was found; verify DefaultServlet listings policy manually.' "web.xml files: $($state.WebXml -join ', ')" 'Parse web.xml listings init-param'
        }
        'WEB-05' {
            $cgi = @([regex]::Matches($webText, '(?is)<servlet-name>\s*cgi\s*</servlet-name>|org\.apache\.catalina\.servlets\.CGIServlet|cgiPathPrefix|enableCmdLineArguments') | ForEach-Object { $_.Value.Trim() } | Select-Object -Unique)
            if ($cgi.Count -gt 0) { return New-TomcatResult 'VULNERABLE' 'Tomcat CGI servlet configuration evidence was found.' ($cgi -join "`n") 'Parse web.xml CGI servlet configuration' }
            return New-TomcatResult 'GOOD' 'No active Tomcat CGI servlet configuration evidence was found.' "web.xml files: $($state.WebXml -join ', ')" 'Parse web.xml CGI servlet configuration'
        }
        'WEB-06' {
            $allowLinking = @([regex]::Matches($contextText, '(?i)allowLinking\s*=\s*"true"') | ForEach-Object { $_.Value })
            if ($allowLinking.Count -gt 0) { return New-TomcatResult 'VULNERABLE' 'Tomcat allowLinking is enabled and may allow traversal through linked paths.' ($allowLinking -join "`n") 'Parse context.xml allowLinking' }
            return New-TomcatResult 'GOOD' 'No Tomcat allowLinking=true evidence was found in context configuration.' "context.xml files: $($state.ContextXml -join ', ')" 'Parse context.xml allowLinking'
        }
        'WEB-07' {
            $findings = [System.Collections.Generic.List[string]]::new()
            foreach ($root in $state.Webapps) {
                foreach ($name in 'docs','examples','sample','samples','test','backup','tmp') {
                    $candidate = Join-Path $root $name
                    if (Test-Path -LiteralPath $candidate) { $findings.Add($candidate) | Out-Null }
                }
                foreach ($file in @(Get-ChildItem -LiteralPath $root -Recurse -File -ErrorAction SilentlyContinue -Include '*.bak','*.old','*.orig','*readme*','*install*' | Select-Object -First 50)) {
                    $findings.Add($file.FullName) | Out-Null
                }
            }
            if ($findings.Count -gt 0) { return New-TomcatResult 'VULNERABLE' 'Unnecessary Tomcat sample, documentation, test, or backup files were found.' ($findings -join "`n") 'Inspect Tomcat webapps for unnecessary files' }
            if ($state.Webapps.Count -gt 0) { return New-TomcatResult 'GOOD' 'No unnecessary Tomcat sample, documentation, test, or backup files were found under webapps.' "Webapps: $($state.Webapps -join ', ')" 'Inspect Tomcat webapps for unnecessary files' }
            return New-TomcatResult 'MANUAL' 'Tomcat was found, but webapps paths were not located.' $evidencePrefix 'Inspect Tomcat webapps for unnecessary files'
        }
        'WEB-08' {
            $limits = @([regex]::Matches($serverText, '(?i)(maxPostSize|maxSavePostSize)\s*=\s*"([^"]+)"') | ForEach-Object { "$($_.Groups[1].Value)=$($_.Groups[2].Value)" })
            $bad = @($limits | Where-Object { $_ -match '=(-1|0)$' })
            if ($bad.Count -gt 0 -or $limits.Count -eq 0) { return New-TomcatResult 'VULNERABLE' 'Tomcat upload/request size limits are missing or unlimited.' (($limits + "server.xml files: $($state.ServerXml -join ', ')") -join "`n") 'Parse server.xml maxPostSize/maxSavePostSize' }
            return New-TomcatResult 'GOOD' 'Tomcat upload/request size limits are configured.' ($limits -join "`n") 'Parse server.xml maxPostSize/maxSavePostSize'
        }
        'WEB-09' {
            $accounts = @($state.Services | ForEach-Object { $_.StartName } | Where-Object { $_ })
            foreach ($process in $state.Processes) {
                try {
                    $owner = Invoke-CimMethod -InputObject $process -MethodName GetOwner -ErrorAction Stop
                    if ($owner.ReturnValue -eq 0) { $accounts += if ($owner.Domain) { "$($owner.Domain)\$($owner.User)" } else { $owner.User } }
                } catch {}
            }
            $accounts = @($accounts | Select-Object -Unique)
            $high = @($accounts | Where-Object { $_ -match '^(?i)(LocalSystem|NT AUTHORITY\\SYSTEM)$' -or $_ -match '(?i)(^|\\)Administrator(s)?$' })
            if ($high.Count -gt 0) { return New-TomcatResult 'VULNERABLE' 'Tomcat appears to run with an administrator-equivalent Windows account.' ($accounts -join ', ') 'Inspect Tomcat service StartName and process owner' }
            if ($accounts.Count -gt 0) { return New-TomcatResult 'GOOD' 'Tomcat service/process account evidence is not administrator-equivalent.' ($accounts -join ', ') 'Inspect Tomcat service StartName and process owner' }
            return New-TomcatResult 'MANUAL' 'Tomcat was found, but service/process account evidence could not be determined.' $evidencePrefix 'Inspect Tomcat service StartName and process owner'
        }
        'WEB-10' {
            $proxy = @([regex]::Matches($serverText, '(?i)(proxyName|proxyPort|AJP/1\.3|protocol\s*=\s*"AJP|secretRequired\s*=\s*"false")') | ForEach-Object { $_.Value.Trim() } | Select-Object -Unique)
            if ($proxy -match 'secretRequired\s*=\s*"false"|AJP/1\.3|protocol\s*=\s*"AJP') { return New-TomcatResult 'MANUAL' 'Tomcat proxy/AJP configuration evidence was found. Verify it is required, bound to trusted interfaces, and protected by a secret.' ($proxy -join "`n") 'Parse server.xml proxy and AJP connector settings' }
            return New-TomcatResult 'GOOD' 'No Tomcat proxy/AJP connector evidence was found.' "server.xml files: $($state.ServerXml -join ', ')" 'Parse server.xml proxy and AJP connector settings'
        }
        'WEB-11' {
            $appBase = @([regex]::Matches($serverText, '(?i)appBase\s*=\s*"([^"]+)"') | ForEach-Object { $_.Groups[1].Value })
            $default = @($appBase | Where-Object { $_ -match '(?i)^webapps$|\\webapps$|/webapps$' })
            if ($default.Count -gt 0) { return New-TomcatResult 'MANUAL' 'Tomcat uses the default webapps path. Confirm a hardened separate service path is required by local policy.' ($appBase -join "`n") 'Parse server.xml Host appBase' }
            if ($appBase.Count -gt 0) { return New-TomcatResult 'GOOD' 'Tomcat Host appBase uses a non-default web service path.' ($appBase -join "`n") 'Parse server.xml Host appBase' }
            return New-TomcatResult 'MANUAL' 'Tomcat appBase could not be determined from server.xml.' "server.xml files: $($state.ServerXml -join ', ')" 'Parse server.xml Host appBase'
        }
        'WEB-12' {
            $links = [System.Collections.Generic.List[string]]::new()
            foreach ($root in $state.Webapps) {
                foreach ($item in @(Get-ChildItem -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue | Where-Object { ($_.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or $_.Extension -match '(?i)^\.lnk$' } | Select-Object -First 50)) {
                    $links.Add($item.FullName) | Out-Null
                }
            }
            $allowLinking = @([regex]::Matches($contextText, '(?i)allowLinking\s*=\s*"true"') | ForEach-Object { $_.Value })
            if ($links.Count -gt 0 -or $allowLinking.Count -gt 0) { return New-TomcatResult 'VULNERABLE' 'Tomcat webapps contain links/reparse points or allowLinking=true.' (($links + $allowLinking) -join "`n") 'Inspect Tomcat webapps links and context allowLinking' }
            return New-TomcatResult 'GOOD' 'No Tomcat webapp links/reparse points or allowLinking=true evidence was found.' "Webapps: $($state.Webapps -join ', ')" 'Inspect Tomcat webapps links and context allowLinking'
        }
        'WEB-13' {
            $sensitive = @([regex]::Matches($webText, '(?i)(jdbc|datasource|password|url|username|ResourceLink|JNDI)') | ForEach-Object { $_.Value } | Select-Object -Unique)
            $constraints = @([regex]::Matches($webText, '(?i)<security-constraint|<auth-constraint') | ForEach-Object { $_.Value })
            if ($sensitive.Count -gt 0 -and $constraints.Count -eq 0) { return New-TomcatResult 'MANUAL' 'Potential DB/config exposure evidence exists without obvious web.xml security constraints. Verify sensitive files are not web-accessible.' ($sensitive -join "`n") 'Parse web.xml for sensitive config and access constraints' }
            # The mere presence of a <security-constraint>/<auth-constraint> does NOT prove it
            # covers the DB-connection files (its <url-pattern> may target unrelated resources),
            # so a bare constraint cannot be statically confirmed as GOOD.
            if ($constraints.Count -gt 0) { return New-TomcatResult 'MANUAL' 'Tomcat web.xml contains a security-constraint, but it cannot be statically confirmed that the constraint url-pattern actually covers the DB-connection/sensitive files. Verify the constraint protects the sensitive resources.' "Constraints: $($constraints.Count)" 'Parse web.xml for access constraints' }
            return New-TomcatResult 'MANUAL' 'No explicit access constraint evidence was found. Confirm DB/config files are outside web roots or protected.' "web.xml files: $($state.WebXml -join ', ')" 'Parse web.xml for sensitive config and access constraints'
        }
        'WEB-14' {
            $targets = @($state.ServerXml + $state.TomcatUsersXml + $state.WebXml + $state.ContextXml + $state.Webapps | Select-Object -Unique)
            $acl = foreach ($path in $targets) { if (Test-Path -LiteralPath $path) { Get-TomcatBroadAclEvidence -Path $path -Role 'TomcatPath' } }
            $bad = @($acl | Where-Object { $_.Access -eq 'Write' -or $_.Access -eq 'Unknown' })
            if ($bad.Count -gt 0) { return New-TomcatResult 'VULNERABLE' 'Broad local write or unknown ACL evidence was found on Tomcat paths.' (($bad | ForEach-Object { "$($_.Path) => $($_.Principal) $($_.Access) ($($_.Rights))" }) -join "`n") 'Get-Acl Tomcat config and web paths' }
            if ($acl) { return New-TomcatResult 'MANUAL' 'Broad local read ACL evidence was found on Tomcat paths; confirm sensitive files are excluded.' (($acl | ForEach-Object { "$($_.Path) => $($_.Principal) $($_.Access) ($($_.Rights))" }) -join "`n") 'Get-Acl Tomcat config and web paths' }
            return New-TomcatResult 'GOOD' 'No broad local user ACL entries were found on assessed Tomcat paths.' "Assessed paths: $($targets -join ', ')" 'Get-Acl Tomcat config and web paths'
        }
        'WEB-15' {
            # Stock Tomcat conf/web.xml ships the CGI/SSI/Invoker servlet definitions COMMENTED OUT
            # (disabled by default). Only ACTIVE (non-commented) script mappings are unnecessary
            # mappings per the criteria, so strip XML comments before matching to avoid false VULNERABLE.
            $webTextActive = [regex]::Replace($webText, '(?s)<!--.*?-->', '')
            $mapping = @([regex]::Matches($webTextActive, '(?is)<servlet-name>\s*(cgi|invoker|ssi)\s*</servlet-name>|CGIServlet|SSIServlet|InvokerServlet') | ForEach-Object { $_.Value.Trim() } | Select-Object -Unique)
            if ($mapping.Count -gt 0) { return New-TomcatResult 'VULNERABLE' 'Unnecessary Tomcat servlet/script mapping evidence was found.' ($mapping -join "`n") 'Parse web.xml script servlet mappings' }
            # web.xml이 존재/판독되지 않으면(빈 WebXml) 정상 설정과 부재/판독불가를 구분할 수 없으므로 MANUAL 처리
            if ($state.WebXml.Count -eq 0 -or [string]::IsNullOrWhiteSpace($webText)) { return New-TomcatResult 'MANUAL' 'No readable Tomcat web.xml was found; cannot confirm absence of unnecessary script mappings. Verify web.xml manually.' "web.xml files: $($state.WebXml -join ', ')" 'Parse web.xml script servlet mappings' }
            return New-TomcatResult 'GOOD' 'No CGI, SSI, or invoker servlet mapping evidence was found.' "web.xml files: $($state.WebXml -join ', ')" 'Parse web.xml script servlet mappings'
        }
        'WEB-16' {
            $serverAttrs = @([regex]::Matches($serverText, '(?i)server\s*=\s*"([^"]+)"') | ForEach-Object { $_.Groups[1].Value })
            $default = @($serverAttrs | Where-Object { $_ -match '(?i)Apache-Coyote|Tomcat|Catalina' })
            if ($default.Count -gt 0 -or $serverAttrs.Count -eq 0) { return New-TomcatResult 'VULNERABLE' 'Tomcat server header is default or not explicitly masked.' ($serverAttrs -join ', ') 'Parse server.xml Connector server attribute' }
            return New-TomcatResult 'GOOD' 'Tomcat Connector server header appears to be masked.' ($serverAttrs -join ', ') 'Parse server.xml Connector server attribute'
        }
        'WEB-17' {
            $virtuals = @($state.Webapps | ForEach-Object { Get-ChildItem -LiteralPath $_ -Directory -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName })
            $unnecessary = @($virtuals | Where-Object { $_ -match '(?i)\\(docs|examples|sample|samples|test|backup|tmp|old)(\\|$)' })
            if ($unnecessary.Count -gt 0) { return New-TomcatResult 'VULNERABLE' 'Unnecessary Tomcat virtual directories were found.' ($unnecessary -join "`n") 'Inspect Tomcat webapps virtual directories' }
            if ($virtuals.Count -gt 0) { return New-TomcatResult 'MANUAL' 'Tomcat webapp directories exist. Confirm each deployed virtual directory is required.' ($virtuals -join "`n") 'Inspect Tomcat webapps virtual directories' }
            return New-TomcatResult 'GOOD' 'No Tomcat webapp virtual directories were found.' "Webapps: $($state.Webapps -join ', ')" 'Inspect Tomcat webapps virtual directories'
        }
        'WEB-18' {
            $dav = @([regex]::Matches($webText, '(?is)<servlet-name>\s*webdav\s*</servlet-name>|WebdavServlet|readonly\s*</param-name>\s*<param-value>\s*false') | ForEach-Object { $_.Value.Trim() })
            if ($dav.Count -gt 0) { return New-TomcatResult 'VULNERABLE' 'Tomcat WebDAV servlet or writable WebDAV evidence was found.' ($dav -join "`n") 'Parse web.xml WebDAV servlet settings' }
            return New-TomcatResult 'GOOD' 'No Tomcat WebDAV servlet evidence was found.' "web.xml files: $($state.WebXml -join ', ')" 'Parse web.xml WebDAV servlet settings'
        }
        'WEB-19' {
            # 가이드라인 Step 1: SSIServlet(<servlet-name>SSIServlet</servlet-name>)뿐 아니라
            # SSIFilter(<filter-name>SSIFilter</filter-name>)도 동등한 SSI 활성화 메커니즘이므로 함께 점검
            # 단, Tomcat 기본 conf/web.xml은 SSI servlet/filter 정의를 주석(<!-- -->) 처리하여 비활성 상태로 배포하므로
            # 주석을 제거한 활성 설정만 매칭해야 비활성(criteria_good) 상태를 취약으로 오탐하지 않음
            $webTextActive = [regex]::Replace($webText, '(?s)<!--.*?-->', '')
            $ssi = @([regex]::Matches($webTextActive, '(?is)<servlet-name>\s*ssi\s*</servlet-name>|SSIServlet|<filter-name>\s*SSIFilter\s*</filter-name>|SSIFilter') | ForEach-Object { $_.Value.Trim() } | Select-Object -Unique)
            if ($ssi.Count -gt 0) { return New-TomcatResult 'VULNERABLE' 'Tomcat SSI servlet/filter evidence was found.' ($ssi -join "`n") 'Parse web.xml SSI servlet/filter settings' }
            # web.xml이 존재/판독되지 않으면(빈 WebXml) 정상 설정과 부재/판독불가를 구분할 수 없으므로 MANUAL 처리
            if ($state.WebXml.Count -eq 0 -or [string]::IsNullOrWhiteSpace($webText)) { return New-TomcatResult 'MANUAL' 'No readable Tomcat web.xml was found; cannot confirm absence of SSI servlet/filter. Verify web.xml manually.' "web.xml files: $($state.WebXml -join ', ')" 'Parse web.xml SSI servlet/filter settings' }
            return New-TomcatResult 'GOOD' 'No Tomcat SSI servlet or filter evidence was found.' "web.xml files: $($state.WebXml -join ', ')" 'Parse web.xml SSI servlet/filter settings'
        }
        'WEB-20' {
            $ssl = @([regex]::Matches($serverText, '(?is)<Connector\b[^>]*(SSLEnabled\s*=\s*"true"|scheme\s*=\s*"https"|secure\s*=\s*"true")[^>]*>') | ForEach-Object { $_.Value.Trim() })
            $weak = @($ssl | Where-Object { $_ -match '(?i)SSLv2|SSLv3|TLSv1(\.0|\.1)?' -and $_ -notmatch '(?i)TLSv1\.2|TLSv1\.3' })
            if ($ssl.Count -eq 0) { return New-TomcatResult 'VULNERABLE' 'No Tomcat SSL/TLS Connector evidence was found.' "server.xml files: $($state.ServerXml -join ', ')" 'Parse server.xml SSL/TLS Connector settings' }
            if ($weak.Count -gt 0) { return New-TomcatResult 'VULNERABLE' 'Tomcat SSL/TLS Connector appears to allow weak protocols.' ($weak -join "`n") 'Parse server.xml SSL/TLS Connector settings' }
            return New-TomcatResult 'GOOD' 'Tomcat SSL/TLS Connector evidence was found without obvious weak protocol evidence.' ($ssl -join "`n") 'Parse server.xml SSL/TLS Connector settings'
        }
        'WEB-21' {
            # redirectPort alone is NOT redirection evidence: every plain HTTP Connector
            # ships redirectPort="8443" by default with no SSL/redirect actually enforced.
            # Real HTTPS enforcement = a CONFIDENTIAL transport-guarantee (security-constraint)
            # OR an actual SSL Connector (SSLEnabled="true" / scheme="https" / secure="true").
            $confidential = @([regex]::Matches($webText, '(?i)<transport-guarantee>\s*CONFIDENTIAL\s*</transport-guarantee>') | ForEach-Object { $_.Value.Trim() })
            $sslConnector = @([regex]::Matches($serverText, '(?is)<Connector\b[^>]*(SSLEnabled\s*=\s*"true"|scheme\s*=\s*"https"|secure\s*=\s*"true")[^>]*>') | ForEach-Object { $_.Value.Trim() })
            if ($confidential.Count -gt 0 -or $sslConnector.Count -gt 0) { return New-TomcatResult 'GOOD' 'Tomcat HTTPS enforcement evidence was found (CONFIDENTIAL transport-guarantee or an SSL/HTTPS Connector).' (($confidential + $sslConnector) -join "`n") 'Parse web.xml transport-guarantee and server.xml SSL Connector' }
            return New-TomcatResult 'MANUAL' 'No Tomcat HTTPS enforcement evidence was found (redirectPort alone is a default attribute and is not sufficient). Confirm HTTPS redirection is enforced by a security-constraint, an SSL Connector, a reverse proxy, or network control.' "server.xml/web.xml files inspected" 'Parse web.xml transport-guarantee and server.xml SSL Connector'
        }
        'WEB-22' {
            $errors = @([regex]::Matches($webText, '(?is)<error-page>.*?</error-page>') | ForEach-Object { $_.Value.Trim() })
            if ($errors.Count -ge 4) { return New-TomcatResult 'GOOD' 'Tomcat custom error page mappings cover multiple error conditions.' "error-page entries: $($errors.Count)" 'Parse web.xml error-page mappings' }
            if ($errors.Count -gt 0) { return New-TomcatResult 'MANUAL' 'Some Tomcat custom error page mappings exist; confirm all major errors are covered.' "error-page entries: $($errors.Count)" 'Parse web.xml error-page mappings' }
            return New-TomcatResult 'VULNERABLE' 'No Tomcat custom error page mappings were found.' "web.xml files: $($state.WebXml -join ', ')" 'Parse web.xml error-page mappings'
        }
        'WEB-23' {
            $ldap = @([regex]::Matches($serverText, '(?is)<Realm\b[^>]*(JNDIRealm|ldap|connectionURL)[^>]*>') | ForEach-Object { $_.Value.Trim() })
            if ($ldap.Count -eq 0) { return New-TomcatResult 'N/A' 'No Tomcat LDAP/JNDI Realm evidence was found.' "server.xml files: $($state.ServerXml -join ', ')" 'Parse server.xml LDAP/JNDI Realm settings' }
            # Allowlist mirror of the Linux WEB23_check.sh: a Realm is SAFE only when its digest
            # attribute is an explicit SHA-256/384/512 (or SSHA-256/384/512) value. Any other case —
            # a weak/aliased digest (MD5/SHA-1/SHA1/NONE/PLAIN, or the SHA-1-class aliases SHA/SSHA),
            # or no digest attribute at all — is treated as weak/missing => VULNERABLE.
            $weak = @($ldap | Where-Object { $_ -notmatch '(?i)digest\s*=\s*"\s*(SHA-?256|SHA-?384|SHA-?512|SSHA-?256|SSHA-?384|SSHA-?512)\s*"' })
            if ($weak.Count -gt 0) { return New-TomcatResult 'VULNERABLE' 'Tomcat LDAP/JNDI Realm digest algorithm is missing or weak.' ($weak -join "`n") 'Parse server.xml LDAP/JNDI Realm digest settings' }
            return New-TomcatResult 'GOOD' 'Tomcat LDAP/JNDI Realm digest algorithm evidence was found and is not obviously weak.' ($ldap -join "`n") 'Parse server.xml LDAP/JNDI Realm digest settings'
        }
        'WEB-24' {
            $multipart = @([regex]::Matches($webText, '(?is)<multipart-config>.*?</multipart-config>') | ForEach-Object { $_.Value.Trim() })
            $uploadPaths = @([regex]::Matches($webText, '(?is)<location>\s*([^<]+)\s*</location>') | ForEach-Object { $_.Groups[1].Value.Trim() })
            if ($multipart.Count -eq 0) { return New-TomcatResult 'MANUAL' 'No Tomcat multipart-config upload path evidence was found. Confirm application upload paths manually.' "web.xml files: $($state.WebXml -join ', ')" 'Parse web.xml multipart-config upload paths' }
            $inside = @($uploadPaths | Where-Object { $_ -match '(?i)webapps|^\\?$|^\.$' })
            if ($inside.Count -gt 0) { return New-TomcatResult 'VULNERABLE' 'Tomcat upload path evidence appears to use a web root or relative/default path.' ($multipart -join "`n") 'Parse web.xml multipart-config upload paths' }
            return New-TomcatResult 'MANUAL' 'Tomcat multipart upload configuration exists. Confirm the resolved upload path is outside web roots and has restricted ACLs.' ($multipart -join "`n") 'Parse web.xml multipart-config upload paths'
        }
        'WEB-25' {
            $version = [System.Collections.Generic.List[string]]::new()
            foreach ($home in $state.Homes) {
                foreach ($jar in @(Get-ChildItem -LiteralPath (Join-Path $home 'lib') -Filter 'catalina.jar' -File -ErrorAction SilentlyContinue)) {
                    try { $version.Add("$($jar.FullName): $((Get-Item -LiteralPath $jar.FullName).VersionInfo.ProductVersion)") | Out-Null } catch {}
                }
            }
            return New-TomcatResult 'MANUAL' 'Tomcat was found. Compare detected version and patch policy against current Apache Tomcat security advisories.' (($version + $evidencePrefix) -join "`n") 'Collect Tomcat Windows service/process/version evidence for vendor advisory comparison'
        }
        'WEB-26' {
            $acl = foreach ($path in $state.Logs) { Get-TomcatBroadAclEvidence -Path $path -Role 'LogPath' }
            $bad = @($acl | Where-Object { $_.Access -eq 'Write' -or $_.Access -eq 'Unknown' })
            if ($state.Logs.Count -eq 0) { return New-TomcatResult 'MANUAL' 'Tomcat log paths could not be resolved.' $evidencePrefix 'Inspect Tomcat logs directory ACLs' }
            if ($bad.Count -gt 0) { return New-TomcatResult 'VULNERABLE' 'Tomcat log paths have broad local write or unknown ACL evidence.' (($bad | ForEach-Object { "$($_.Path) => $($_.Principal) $($_.Access) ($($_.Rights))" }) -join "`n") 'Inspect Tomcat logs directory ACLs' }
            if ($acl) { return New-TomcatResult 'MANUAL' 'Tomcat log paths have broad local read ACL evidence; confirm whether this is required.' (($acl | ForEach-Object { "$($_.Path) => $($_.Principal) $($_.Access) ($($_.Rights))" }) -join "`n") 'Inspect Tomcat logs directory ACLs' }
            return New-TomcatResult 'GOOD' 'No broad local user ACL entries were found on resolved Tomcat log paths.' "Logs: $($state.Logs -join ', ')" 'Inspect Tomcat logs directory ACLs'
        }
        default {
            return New-TomcatResult 'MANUAL' "No Tomcat Windows diagnostic rule is defined for $ItemId." $evidencePrefix 'Tomcat Windows generic discovery'
        }
    }
}
