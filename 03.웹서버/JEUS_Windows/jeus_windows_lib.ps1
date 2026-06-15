#Requires -Version 5.1

function Add-JeusUniquePath {
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

function Get-JeusWindowsServices {
    try {
        @(Get-CimInstance Win32_Service -ErrorAction Stop | Where-Object {
            $_.Name -match '(?i)jeus|webadmin|jeusadmin' -or $_.DisplayName -match '(?i)jeus|webadmin|jeusadmin'
        })
    } catch { @() }
}

function Get-JeusWindowsProcesses {
    try {
        @(Get-CimInstance Win32_Process -ErrorAction Stop | Where-Object {
            $_.Name -match '(?i)^(java|jeus|jeusadmin|webadmin)\.exe$' -and $_.CommandLine -match '(?i)jeus|webadmin'
        })
    } catch { @() }
}

function Get-JeusCommandPath {
    foreach ($cmd in @('jeusadmin.exe', 'jeusadmin')) {
        $found = Get-Command $cmd -ErrorAction SilentlyContinue
        if ($found) { return $found.Source }
    }
    foreach ($root in @($env:JEUS_HOME, $env:ProgramFiles, ${env:ProgramFiles(x86)}, 'C:\TmaxSoft', 'C:\JEUS')) {
        if ([string]::IsNullOrWhiteSpace($root) -or -not (Test-Path -LiteralPath $root -PathType Container)) { continue }
        $candidate = Get-ChildItem -LiteralPath $root -Recurse -File -Filter 'jeusadmin*' -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -match '(?i)\\bin\\jeusadmin(\.exe)?$' } |
            Select-Object -First 1
        if ($candidate) { return $candidate.FullName }
    }
    return $null
}

function Get-JeusWindowsState {
    $services = @(Get-JeusWindowsServices)
    $processes = @(Get-JeusWindowsProcesses)
    $homes = [System.Collections.Generic.List[string]]::new()
    Add-JeusUniquePath -Paths $homes -Candidate $env:JEUS_HOME -PathType Container
    foreach ($obj in @($services + $processes)) {
        $cmd = if ($obj.PathName) { [string]$obj.PathName } else { [string]$obj.CommandLine }
        if ($cmd -match '(?i)-Djeus\.home=([^\s"]+)') { Add-JeusUniquePath -Paths $homes -Candidate $Matches[1] -PathType Container }
        if ($cmd -match '(?i)"([^"]*\\bin\\(?:jeus|jeusadmin|startDomainAdminServer)\.exe)"') {
            Add-JeusUniquePath -Paths $homes -Candidate (Split-Path -Parent (Split-Path -Parent $Matches[1])) -PathType Container
        }
        elseif ($cmd -match '(?i)(\S*\\bin\\(?:jeus|jeusadmin|startDomainAdminServer)\.exe)') {
            Add-JeusUniquePath -Paths $homes -Candidate (Split-Path -Parent (Split-Path -Parent $Matches[1])) -PathType Container
        }
    }

    $configs = [System.Collections.Generic.List[string]]::new()
    $logs = [System.Collections.Generic.List[string]]::new()
    foreach ($home in $homes) {
        foreach ($candidate in @(
            (Join-Path $home 'domains'),
            (Join-Path $home 'config'),
            (Join-Path $home 'conf'),
            (Join-Path $home 'webhome')
        )) {
            if (Test-Path -LiteralPath $candidate -PathType Container) {
                Get-ChildItem -LiteralPath $candidate -Recurse -File -Include 'domain.xml','web.xml','webcommon.xml','jeus-web-dd.xml','accounts.xml','policies.xml' -ErrorAction SilentlyContinue |
                    Select-Object -First 500 |
                    ForEach-Object { Add-JeusUniquePath -Paths $configs -Candidate $_.FullName -PathType Leaf }
            }
        }
        foreach ($candidate in @((Join-Path $home 'logs'), (Join-Path $home 'domains'))) {
            if (Test-Path -LiteralPath $candidate -PathType Container) {
                Get-ChildItem -LiteralPath $candidate -Recurse -Directory -Filter 'logs' -ErrorAction SilentlyContinue |
                    Select-Object -First 100 |
                    ForEach-Object { Add-JeusUniquePath -Paths $logs -Candidate $_.FullName -PathType Container }
            }
        }
    }

    $installedEvidence = ($services.Count -gt 0 -or $processes.Count -gt 0 -or $homes.Count -gt 0)
    [pscustomobject]@{
        Services = $services
        Processes = $processes
        JeusHomes = @($homes)
        ConfigFiles = @($configs)
        LogDirs = @($logs)
        AdminPath = if ($installedEvidence) { Get-JeusCommandPath } else { $null }
        Installed = $installedEvidence
    }
}

function Get-JeusWindowsEvidence {
    param($State)
    @(
        $State.Services | ForEach-Object { "Service $($_.Name) [$($_.State)] $($_.StartName): $($_.PathName)" }
        $State.Processes | ForEach-Object { "Process $($_.ProcessId): $($_.CommandLine)" }
        if ($State.JeusHomes.Count -gt 0) { "JeusHomes: $($State.JeusHomes -join ', ')" }
        if ($State.ConfigFiles.Count -gt 0) { "ConfigFiles: $($State.ConfigFiles -join ', ')" }
        if ($State.LogDirs.Count -gt 0) { "LogDirs: $($State.LogDirs -join ', ')" }
        if ($State.AdminPath) { "AdminPath: $($State.AdminPath)" }
    ) -join "`n"
}

function New-JeusResult {
    param([string]$FinalResult, [string]$Summary, [string]$CommandOutput, [string]$CommandExecuted)
    $status = switch ($FinalResult) {
        'GOOD' { '양호' }
        'VULNERABLE' { '취약' }
        'N/A' { 'N/A' }
        default { '수동진단' }
    }
    [pscustomobject]@{ FinalResult = $FinalResult; Status = $status; Summary = $Summary; CommandOutput = $CommandOutput; CommandExecuted = $CommandExecuted }
}

function New-JeusNotInstalledResult {
    New-JeusResult 'N/A' 'JEUS for Windows service/process/home evidence was not found.' 'No JEUS service, JEUS java process, or JEUS_HOME evidence found.' 'Get-CimInstance Win32_Service/Win32_Process; inspect JEUS_HOME'
}

function Get-JeusConfigLines {
    param($State, [string]$Pattern)
    foreach ($file in $State.ConfigFiles) {
        $lines = @(Select-String -LiteralPath $file -Pattern $Pattern -ErrorAction SilentlyContinue)
        foreach ($line in $lines) { "${file}:$($line.LineNumber): $($line.Line.Trim())" }
    }
}

function Get-JeusStrippedConfigText {
    # Returns each config file's content with XML comments (including multi-line
    # <!-- ... --> spans) removed, so presence/value tests are not fooled by
    # commented-out directives. Mirrors the WEB-22 [regex]::Replace strip.
    param($State)
    $parts = foreach ($file in $State.ConfigFiles) {
        $raw = try { Get-Content -LiteralPath $file -Raw -ErrorAction SilentlyContinue } catch { $null }
        if (-not $raw) { continue }
        [regex]::Replace($raw, '(?s)<!--.*?-->', '')
    }
    ($parts -join "`n")
}

function Test-JeusBroadPrincipal {
    param([System.Security.Principal.IdentityReference]$Identity)
    try { $sid = $Identity.Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { $sid = [string]$Identity }
    return ($sid -eq 'S-1-1-0') -or ($sid -eq 'S-1-5-11') -or ($sid -eq 'S-1-5-32-545') -or ($sid -eq 'S-1-5-32-546') -or ($sid -match '-513$') -or (([string]$Identity) -match '(?i)Everyone|Authenticated Users|BUILTIN\\Users|Guests|Domain Users')
}

function Get-JeusBroadAclEvidence {
    param([string]$Path, [string]$Role)
    try { $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop } catch { return [pscustomobject]@{ Path = $Path; Role = $Role; Access = 'Unknown'; Principal = 'N/A'; Rights = "ACL read failed: $($_.Exception.Message)" } }
    # criteria_bad covers ANY general-user access (read OR write) on password, config or
    # log paths. Flag any Allow ACE held by a broad principal (Everyone, BUILTIN\Users,
    # Authenticated Users, Domain Users, Guests) regardless of right class. Read-only
    # broad access (e.g. Everyone:Read on accounts.xml or log dirs) is a violation too.
    $writeRights = @([System.Security.AccessControl.FileSystemRights]::FullControl, [System.Security.AccessControl.FileSystemRights]::Modify, [System.Security.AccessControl.FileSystemRights]::Write, [System.Security.AccessControl.FileSystemRights]::WriteData, [System.Security.AccessControl.FileSystemRights]::AppendData, [System.Security.AccessControl.FileSystemRights]::CreateFiles, [System.Security.AccessControl.FileSystemRights]::CreateDirectories, [System.Security.AccessControl.FileSystemRights]::Delete, [System.Security.AccessControl.FileSystemRights]::ChangePermissions, [System.Security.AccessControl.FileSystemRights]::TakeOwnership)
    foreach ($rule in $acl.Access) {
        if ($rule.AccessControlType -ne 'Allow' -or -not (Test-JeusBroadPrincipal -Identity $rule.IdentityReference)) { continue }
        $hasWrite = $false
        foreach ($right in $writeRights) {
            if (($rule.FileSystemRights -band $right) -eq $right) { $hasWrite = $true; break }
        }
        $accessKind = if ($hasWrite) { 'Write' } else { 'Read' }
        [pscustomobject]@{ Path = $Path; Role = $Role; Access = $accessKind; Principal = [string]$rule.IdentityReference; Rights = [string]$rule.FileSystemRights }
    }
}

function Invoke-JeusAclCheck {
    param($State, [string[]]$Targets, [string]$Role)
    $paths = @($Targets | Where-Object { $_ } | Select-Object -Unique)
    $acl = foreach ($path in $paths) { Get-JeusBroadAclEvidence -Path $path -Role $Role }
    if ($acl) {
        return New-JeusResult 'VULNERABLE' "Broad general-user access (read or write) or unknown ACL evidence was found on JEUS $Role paths." (($acl | ForEach-Object { "$($_.Path) => $($_.Principal) $($_.Access) ($($_.Rights))" }) -join "`n") "Get-Acl JEUS $Role paths"
    }
    if ($paths.Count -eq 0) { return New-JeusResult 'MANUAL' "JEUS $Role paths were not found for ACL assessment." (Get-JeusWindowsEvidence -State $State) "Get-Acl JEUS $Role paths" }
    New-JeusResult 'GOOD' "No broad general-user access ACL entries were found on assessed JEUS $Role paths." ($paths -join ', ') "Get-Acl JEUS $Role paths"
}

function Invoke-JeusWindowsCheck {
    param([string]$ItemId, [string]$ItemName)
    $state = Get-JeusWindowsState
    if (-not $state.Installed) { return New-JeusNotInstalledResult }
    $evidence = Get-JeusWindowsEvidence -State $state

    switch ($ItemId) {
        'WEB-01' { $lines = @(Get-JeusConfigLines $state '(?i)<user|<account|administrator|Administrators'); if (@($lines | Where-Object { $_ -match '(?i)<name>\s*administrator\s*</name>|name\s*=\s*["'''']administrator["'''']' }).Count -gt 0) { return New-JeusResult 'VULNERABLE' 'Default JEUS administrator account name evidence was found.' ($lines -join "`n") 'Inspect JEUS accounts.xml/security domain users' }; if ($lines.Count -gt 0) { return New-JeusResult 'MANUAL' 'JEUS account/group evidence was found (e.g. the default Administrators group/role) but no default administrator account name was confirmed; verify the administrator account name is not a default/guessable value.' ($lines -join "`n") 'Inspect JEUS accounts.xml/security domain users' }; return New-JeusResult 'MANUAL' 'JEUS account configuration was not found; confirm administrator account name manually.' $evidence 'Inspect JEUS accounts.xml/security domain users' }
        'WEB-02' { return New-JeusResult 'MANUAL' 'JEUS administrator password complexity depends on security-domain policy and password store state. Confirm policy and password age manually.' $evidence 'Inspect JEUS password policy/accounts.xml' }
        'WEB-03' { $targets = @($state.ConfigFiles | Where-Object { $_ -match '(?i)accounts\.xml|policies\.xml' }); return Invoke-JeusAclCheck $state $targets 'security account/policy' }
        'WEB-04' { $lines = @(Get-JeusConfigLines $state '(?i)<allow-indexing>\s*true|<allow-indexing>\s*false|listings'); if ($lines -match '(?i)<allow-indexing>\s*true|listings\s*=\s*true') { return New-JeusResult 'VULNERABLE' 'JEUS directory listing appears enabled.' ($lines -join "`n") 'Inspect jeus-web-dd.xml/web.xml directory listing settings' }; if ($lines -match '(?i)<allow-indexing>\s*false|listings\s*=\s*false') { return New-JeusResult 'GOOD' 'JEUS directory listing disable evidence was found.' ($lines -join "`n") 'Inspect jeus-web-dd.xml/web.xml directory listing settings' }; return New-JeusResult 'MANUAL' 'JEUS directory listing evidence was not conclusive.' $evidence 'Inspect jeus-web-dd.xml/web.xml directory listing settings' }
        'WEB-05' { return New-JeusResult 'N/A' 'CGI/ISAPI execution restriction item is not targeted to JEUS in the guideline metadata.' 'WEB-05 target excludes JEUS.' 'Map web service CGI/ISAPI guideline applicability' }
        'WEB-06' { return New-JeusResult 'N/A' 'Upper-directory access restriction item is not targeted to JEUS in the guideline metadata.' 'WEB-06 target excludes JEUS.' 'Map web service upper-directory guideline applicability' }
        'WEB-07' { if ($state.JeusHomes.Count -eq 0) { return New-JeusResult 'MANUAL' 'JEUS is installed (service/process evidence) but JEUS_HOME could not be resolved, so the unnecessary-file search space is empty. Confirm sample/manual/default files manually.' $evidence 'Search JEUS samples/docs/manuals' }; $samplePaths = foreach ($home in $state.JeusHomes) { Get-ChildItem -LiteralPath $home -Recurse -Directory -ErrorAction SilentlyContinue | Where-Object { $_.FullName -match '(?i)\\(samples?|examples?|docs\\manuals|web-manager)' } | Select-Object -First 50 -ExpandProperty FullName }; if ($samplePaths) { return New-JeusResult 'VULNERABLE' 'JEUS sample/manual/default management directories were found.' ($samplePaths -join "`n") 'Search JEUS samples/docs/manuals' }; return New-JeusResult 'GOOD' 'No JEUS sample/manual/default management directories were found in inspected homes.' $evidence 'Search JEUS samples/docs/manuals' }
        'WEB-08' { $lines = @(Get-JeusConfigLines $state '(?i)max-file-size|max-request-size|maxPostSize|multipart-config'); $stripped = Get-JeusStrippedConfigText $state; if ($stripped -match '(?i)(max-file-size|max-request-size|maxPostSize)[^0-9-]*[1-9][0-9]*') { return New-JeusResult 'GOOD' 'JEUS upload/request size limit evidence (non-zero numeric value, outside comment spans) was found.' ($lines -join "`n") 'Inspect web.xml multipart upload limits' }; if ($stripped -match '(?i)max-file-size|max-request-size|maxPostSize|multipart-config') { return New-JeusResult 'VULNERABLE' 'JEUS multipart/upload configuration was present but had no real non-zero size limit (empty or zero value).' ($lines -join "`n") 'Inspect web.xml multipart upload limits' }; return New-JeusResult 'VULNERABLE' 'JEUS upload/request size limit evidence was not found (absent or only commented-out definitions).' $evidence 'Inspect web.xml multipart upload limits' }
        'WEB-09' { $accounts = @($state.Services | ForEach-Object { $_.StartName } | Where-Object { $_ }); if ($accounts -match '^(?i)(LocalSystem|NT AUTHORITY\\SYSTEM)$|Administrator') { return New-JeusResult 'VULNERABLE' 'JEUS Windows service appears to run with administrator-equivalent OS privileges.' ($accounts -join ', ') 'Inspect JEUS Windows service StartName' }; if ($accounts.Count -gt 0) { return New-JeusResult 'GOOD' 'JEUS Windows service account is not administrator-equivalent.' ($accounts -join ', ') 'Inspect JEUS Windows service StartName' }; return New-JeusResult 'MANUAL' 'JEUS service account could not be determined.' $evidence 'Inspect JEUS Windows service StartName' }
        'WEB-10' { $lines = @(Get-JeusConfigLines $state '(?i)ReverseProxy|proxy|PathPrefix|ServerAddress'); if ($lines.Count -gt 0) { return New-JeusResult 'MANUAL' 'JEUS proxy/reverse-proxy evidence was found; confirm only required proxy mappings remain.' ($lines -join "`n") 'Inspect JEUS proxy mappings' }; return New-JeusResult 'GOOD' 'No JEUS proxy/reverse-proxy evidence was found in inspected configs.' $evidence 'Inspect JEUS proxy mappings' }
        'WEB-11' { $lines = @(Get-JeusConfigLines $state '(?i)docBase|appBase|webhome|context-root'); if ($lines.Count -gt 0) { return New-JeusResult 'MANUAL' 'JEUS web root/path evidence was found; confirm service path is separated from install/system directories.' ($lines -join "`n") 'Inspect JEUS web path settings' }; return New-JeusResult 'MANUAL' 'JEUS web service path evidence was not conclusive.' $evidence 'Inspect JEUS web path settings' }
        'WEB-12' { $lines = @(Get-JeusConfigLines $state '(?i)<aliasing>|<alias>|<alias-name>|<real-path>'); $stripped = Get-JeusStrippedConfigText $state; if ($stripped -match '(?i)<aliasing>|<alias>|<alias-name>|<real-path>') { return New-JeusResult 'VULNERABLE' 'JEUS active alias/link mapping evidence (outside comment spans) was found.' ($lines -join "`n") 'Inspect JEUS aliasing settings' }; return New-JeusResult 'GOOD' 'No active JEUS alias/link mapping evidence was found in inspected configs (commented-out definitions are treated as disabled).' $evidence 'Inspect JEUS aliasing settings' }
        'WEB-13' { $lines = @(Get-JeusConfigLines $state '(?i)DataSource|db|jdbc|password'); if ($lines.Count -gt 0) { return New-JeusResult 'MANUAL' 'JEUS DB/resource configuration evidence was found; confirm unnecessary DB connection resources and exposed secrets are removed, and that the config file ACL restricts general-user access.' ($lines -join "`n") 'Inspect JEUS domain.xml/resource configs' }; $aclEvidence = foreach ($cfg in @($state.ConfigFiles)) { Get-JeusBroadAclEvidence -Path $cfg -Role 'db-config' }; if ($aclEvidence) { return New-JeusResult 'VULNERABLE' 'No DB keyword matched, but JEUS configuration files grant broad general-user ACL access; DB connection files must be access-restricted.' (($aclEvidence | ForEach-Object { "$($_.Path) => $($_.Principal) $($_.Access) ($($_.Rights))" }) -join "`n") 'Get-Acl JEUS config files for DB-file ACL' }; return New-JeusResult 'MANUAL' 'No DB/resource keyword matched inspected configs; DB usage may rely on non-standard naming. Confirm no unnecessary DB connection file exists and that any DB config file ACL restricts general-user access.' $evidence 'Inspect JEUS domain.xml/resource configs' }
        'WEB-14' { return Invoke-JeusAclCheck $state @($state.ConfigFiles + $state.JeusHomes) 'config/root' }
        'WEB-15' { $lines = @(Get-JeusConfigLines $state '(?i)<servlet-mapping>|<url-pattern>|cgi|admin|manager|invoker'); if ($lines -match '(?i)cgi|invoker|manager|admin') { return New-JeusResult 'MANUAL' 'JEUS servlet mapping evidence (high-risk keyword) was found; confirm unnecessary mappings are removed.' ($lines -join "`n") 'Inspect JEUS servlet mappings' }; if ($lines.Count -gt 0) { return New-JeusResult 'MANUAL' 'JEUS servlet mappings were found; necessity cannot be determined automatically. Review the listed mappings and remove unnecessary ones.' ($lines -join "`n") 'Inspect JEUS servlet mappings' }; if ($state.ConfigFiles.Count -eq 0) { return New-JeusResult 'MANUAL' 'JEUS is installed but no servlet-mapping config files could be inspected (JEUS_HOME/config unresolved); zero files were examined, so absence of unnecessary mappings cannot be claimed. Review servlet mappings manually.' $evidence 'Inspect JEUS servlet mappings' }; return New-JeusResult 'GOOD' 'No JEUS servlet mapping evidence was found in inspected configs.' $evidence 'Inspect JEUS servlet mappings' }
        'WEB-16' { $lines = @(Get-JeusConfigLines $state '(?i)serverInfo=false|server-header|ServerTokens'); if ($lines -match '(?i)serverInfo=false') { return New-JeusResult 'GOOD' 'JEUS server header suppression evidence was found.' ($lines -join "`n") 'Inspect JEUS serverInfo/header settings' }; return New-JeusResult 'MANUAL' 'JEUS server header suppression evidence was not conclusive.' $evidence 'Inspect JEUS serverInfo/header settings' }
        'WEB-17' { return New-JeusResult 'N/A' 'Virtual directory cleanup item is not targeted to JEUS in the guideline metadata.' 'WEB-17 target excludes JEUS.' 'Map web service virtual-directory guideline applicability' }
        'WEB-18' { return New-JeusResult 'N/A' 'WebDAV disablement item is not targeted to JEUS in the guideline metadata.' 'WEB-18 target excludes JEUS.' 'Map WebDAV guideline applicability' }
        'WEB-19' { return New-JeusResult 'N/A' 'SSI restriction item is not targeted to JEUS in the guideline metadata.' 'WEB-19 target excludes JEUS.' 'Map SSI guideline applicability' }
        'WEB-20' { return New-JeusResult 'N/A' 'SSL/TLS activation item is not targeted to JEUS in the guideline metadata.' 'WEB-20 target excludes JEUS.' 'Map SSL/TLS guideline applicability' }
        'WEB-21' { return New-JeusResult 'N/A' 'HTTP-to-HTTPS redirection item is not targeted to JEUS in the guideline metadata.' 'WEB-21 target excludes JEUS.' 'Map HTTP redirection guideline applicability' }
        'WEB-22' { $activeLocation = $false; $sawErrorPage = $false; $ep = @(); foreach ($file in $state.ConfigFiles) { $raw = try { Get-Content -LiteralPath $file -Raw -ErrorAction SilentlyContinue } catch { $null }; if (-not $raw) { continue }; $stripped = [regex]::Replace($raw, '(?s)<!--.*?-->', ''); if ($stripped -match '(?i)<error-page>') { $sawErrorPage = $true }; if ($stripped -match '(?i)<location>\s*[^<\s][^<]*</location>') { $activeLocation = $true; $ep += ("{0}: active <location> present (outside comment spans)" -f $file) } }; if ($activeLocation) { return New-JeusResult 'GOOD' 'JEUS custom error-page with a designated location value (outside comment spans) was found.' ($ep -join "`n") 'Inspect JEUS error-page settings' }; if ($sawErrorPage) { return New-JeusResult 'MANUAL' 'JEUS error-page element was found but no active <location> value was confirmed (definition may be commented out). Verify the error page is designated and functional.' $evidence 'Inspect JEUS error-page settings' }; return New-JeusResult 'VULNERABLE' 'JEUS custom error-page evidence was not found (only commented-out or empty definitions).' $evidence 'Inspect JEUS error-page settings' }
        'WEB-23' { return New-JeusResult 'N/A' 'LDAP digest algorithm item targets Tomcat only in the guideline metadata; JEUS is out of scope.' 'WEB-23 target excludes JEUS.' 'Map LDAP digest guideline applicability' }
        'WEB-24' { $lines = @(Get-JeusConfigLines $state '(?i)uploadDir|multipart-config|file-upload|tempdir'); if ($lines.Count -gt 0) { return New-JeusResult 'MANUAL' 'JEUS upload path evidence was found; confirm upload path is separated and ACL-restricted.' ($lines -join "`n") 'Inspect JEUS upload path settings' }; return New-JeusResult 'MANUAL' 'JEUS upload path evidence was not conclusive.' $evidence 'Inspect JEUS upload path settings' }
        'WEB-25' { if ($state.AdminPath) { $output = & $state.AdminPath -version 2>&1 | Out-String; return New-JeusResult 'MANUAL' 'JEUS was found. Compare detected version against current TmaxSoft security/patch guidance.' $output "$($state.AdminPath) -version" }; return New-JeusResult 'MANUAL' 'JEUS was found, but jeusadmin was not found. Confirm version and patch level manually.' $evidence 'jeusadmin -version discovery' }
        'WEB-26' { $logFiles = foreach ($dir in @($state.LogDirs)) { Get-ChildItem -LiteralPath $dir -Recurse -File -ErrorAction SilentlyContinue | Select-Object -First 200 -ExpandProperty FullName }; $targets = @($state.LogDirs) + @($logFiles); return Invoke-JeusAclCheck $state $targets 'log' }
        default { return New-JeusResult 'MANUAL' "No JEUS Windows diagnostic rule is defined for $ItemId." $evidence 'JEUS Windows generic discovery' }
    }
}
