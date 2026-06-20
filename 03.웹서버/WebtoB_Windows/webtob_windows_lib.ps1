#Requires -Version 5.1

function Add-WebtoBUniquePath {
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

function Get-WebtoBWindowsServices {
    try {
        @(Get-CimInstance Win32_Service -ErrorAction Stop | Where-Object {
            $_.Name -match '(?i)webtob|wsm|hth|wscfl' -or $_.DisplayName -match '(?i)webtob'
        })
    } catch { @() }
}

function Get-WebtoBWindowsProcesses {
    try {
        @(Get-CimInstance Win32_Process -ErrorAction Stop | Where-Object {
            $_.Name -match '(?i)^(hth|wsm|wsboot|wsdown|wscfl|webtob)\.exe$'
        })
    } catch { @() }
}

function Get-WebtoBCommandPath {
    param([string[]]$Names)
    foreach ($name in $Names) {
        $found = Get-Command $name -ErrorAction SilentlyContinue
        if ($found) { return $found.Source }
    }
    foreach ($root in @($env:WEBTOB, $env:ProgramFiles, ${env:ProgramFiles(x86)}, 'C:\TmaxSoft', 'C:\WebtoB')) {
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

function Get-WebtoBWindowsState {
    $services = @(Get-WebtoBWindowsServices)
    $processes = @(Get-WebtoBWindowsProcesses)
    $homes = [System.Collections.Generic.List[string]]::new()
    Add-WebtoBUniquePath -Paths $homes -Candidate $env:WEBTOB -PathType Container
    foreach ($obj in @($services + $processes)) {
        $cmd = if ($obj.PathName) { [string]$obj.PathName } else { [string]$obj.CommandLine }
        if ($cmd -match '(?i)"([^"]*\\bin\\(?:hth|wsm|wsboot|wscfl|webtob)\.exe)"') {
            Add-WebtoBUniquePath -Paths $homes -Candidate (Split-Path -Parent (Split-Path -Parent $Matches[1])) -PathType Container
        }
        elseif ($cmd -match '(?i)(\S*\\bin\\(?:hth|wsm|wsboot|wscfl|webtob)\.exe)') {
            Add-WebtoBUniquePath -Paths $homes -Candidate (Split-Path -Parent (Split-Path -Parent $Matches[1])) -PathType Container
        }
    }
    $configs = [System.Collections.Generic.List[string]]::new()
    $logs = [System.Collections.Generic.List[string]]::new()
    foreach ($home in $homes) {
        foreach ($candidate in @((Join-Path $home 'config\http.m'), (Join-Path $home 'conf\http.m'), (Join-Path $home 'config\rewrite_ssl.conf'))) {
            Add-WebtoBUniquePath -Paths $configs -Candidate $candidate -PathType Leaf
        }
        foreach ($candidate in @((Join-Path $home 'log'), (Join-Path $home 'logs'))) {
            Add-WebtoBUniquePath -Paths $logs -Candidate $candidate -PathType Container
        }
    }
    $installedEvidence = ($services.Count -gt 0 -or $processes.Count -gt 0 -or $homes.Count -gt 0)
    [pscustomobject]@{
        Services = $services
        Processes = $processes
        WebtoBHomes = @($homes)
        ConfigFiles = @($configs)
        LogDirs = @($logs)
        WscflPath = if ($installedEvidence) { Get-WebtoBCommandPath -Names @('wscfl.exe', 'wscfl') } else { $null }
        Installed = $installedEvidence
    }
}

function Get-WebtoBWindowsEvidence {
    param($State)
    @(
        $State.Services | ForEach-Object { "Service $($_.Name) [$($_.State)] $($_.StartName): $($_.PathName)" }
        $State.Processes | ForEach-Object { "Process $($_.ProcessId): $($_.CommandLine)" }
        if ($State.WebtoBHomes.Count -gt 0) { "WebtoBHomes: $($State.WebtoBHomes -join ', ')" }
        if ($State.ConfigFiles.Count -gt 0) { "ConfigFiles: $($State.ConfigFiles -join ', ')" }
        if ($State.LogDirs.Count -gt 0) { "LogDirs: $($State.LogDirs -join ', ')" }
        if ($State.WscflPath) { "WscflPath: $($State.WscflPath)" }
    ) -join "`n"
}

function New-WebtoBResult {
    param([string]$FinalResult, [string]$Summary, [string]$CommandOutput, [string]$CommandExecuted)
    $status = switch ($FinalResult) { 'GOOD' { '양호' } 'VULNERABLE' { '취약' } 'N/A' { 'N/A' } default { '수동진단' } }
    [pscustomobject]@{ FinalResult = $FinalResult; Status = $status; Summary = $Summary; CommandOutput = $CommandOutput; CommandExecuted = $CommandExecuted }
}

function New-WebtoBNotInstalledResult {
    New-WebtoBResult 'N/A' 'WebtoB for Windows service/process/home evidence was not found.' 'No WebtoB service, process, or WEBTOB home evidence found.' 'Get-CimInstance Win32_Service/Win32_Process; inspect WEBTOB env'
}

function Get-WebtoBConfigLines {
    param($State, [string]$Pattern)
    foreach ($file in $State.ConfigFiles) {
        $lines = @(Select-String -LiteralPath $file -Pattern $Pattern -ErrorAction SilentlyContinue)
        foreach ($line in $lines) { "${file}:$($line.LineNumber): $($line.Line.Trim())" }
    }
}

# Comment-aware variant of Get-WebtoBConfigLines. Skips lines whose first
# non-whitespace character is '#' (WebtoB http.m comment syntax) so commented-out
# directives do not produce false evidence.
function Get-WebtoBActiveConfigLines {
    param($State, [string]$Pattern)
    foreach ($file in $State.ConfigFiles) {
        $lines = @(Select-String -LiteralPath $file -Pattern $Pattern -ErrorAction SilentlyContinue)
        foreach ($line in $lines) {
            if ($line.Line -match '^\s*#') { continue }
            "${file}:$($line.LineNumber): $($line.Line.Trim())"
        }
    }
}

function Test-WebtoBBroadPrincipal {
    param([System.Security.Principal.IdentityReference]$Identity)
    try { $sid = $Identity.Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { $sid = [string]$Identity }
    return ($sid -eq 'S-1-1-0') -or ($sid -eq 'S-1-5-11') -or ($sid -eq 'S-1-5-32-545') -or ($sid -eq 'S-1-5-32-546') -or ($sid -match '-513$') -or (([string]$Identity) -match '(?i)Everyone|Authenticated Users|BUILTIN\\Users|Guests|Domain Users')
}

function Get-WebtoBBroadAclEvidence {
    param([string]$Path, [string]$Role)
    # Oracle (WEB-14/WEB-26) criteria_bad: ANY general-user access, including
    # READ. Any Allow ACE granted to a broad principal (Everyone, BUILTIN\Users,
    # Authenticated Users, Domain Users, etc.) is a finding regardless of whether
    # the right is write or read. We classify the access for the evidence string
    # but flag both read and write.
    $writeRights = @([System.Security.AccessControl.FileSystemRights]::FullControl, [System.Security.AccessControl.FileSystemRights]::Modify, [System.Security.AccessControl.FileSystemRights]::Write, [System.Security.AccessControl.FileSystemRights]::WriteData, [System.Security.AccessControl.FileSystemRights]::AppendData, [System.Security.AccessControl.FileSystemRights]::CreateFiles, [System.Security.AccessControl.FileSystemRights]::CreateDirectories, [System.Security.AccessControl.FileSystemRights]::Delete, [System.Security.AccessControl.FileSystemRights]::ChangePermissions, [System.Security.AccessControl.FileSystemRights]::TakeOwnership)
    $readRights = @([System.Security.AccessControl.FileSystemRights]::Read, [System.Security.AccessControl.FileSystemRights]::ReadData, [System.Security.AccessControl.FileSystemRights]::ReadAndExecute, [System.Security.AccessControl.FileSystemRights]::ListDirectory, [System.Security.AccessControl.FileSystemRights]::ExecuteFile)
    try { $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop } catch { return [pscustomobject]@{ Path = $Path; Role = $Role; Access = 'Unknown'; Principal = 'N/A'; Rights = "ACL read failed: $($_.Exception.Message)" } }
    foreach ($rule in $acl.Access) {
        if ($rule.AccessControlType -ne 'Allow' -or -not (Test-WebtoBBroadPrincipal -Identity $rule.IdentityReference)) { continue }
        $hasWrite = $false
        foreach ($right in $writeRights) { if (($rule.FileSystemRights -band $right) -eq $right) { $hasWrite = $true; break } }
        $hasRead = $false
        foreach ($right in $readRights) { if (($rule.FileSystemRights -band $right) -eq $right) { $hasRead = $true; break } }
        if ($hasWrite -or $hasRead) {
            $access = if ($hasWrite) { 'Write' } else { 'Read' }
            [pscustomobject]@{ Path = $Path; Role = $Role; Access = $access; Principal = [string]$rule.IdentityReference; Rights = [string]$rule.FileSystemRights }
        }
    }
}

function Invoke-WebtoBAclCheck {
    param($State, [string[]]$Targets, [string]$Role)
    $paths = @($Targets | Where-Object { $_ } | Select-Object -Unique)
    $acl = @(foreach ($path in $paths) { Get-WebtoBBroadAclEvidence -Path $path -Role $Role })
    $broad = @($acl | Where-Object { $_.Access -ne 'Unknown' })
    $unknown = @($acl | Where-Object { $_.Access -eq 'Unknown' })
    if ($broad.Count -gt 0) { return New-WebtoBResult 'VULNERABLE' "Broad general-user access (read or write) ACL evidence was found on WebtoB $Role paths." (($broad | ForEach-Object { "$($_.Path) => $($_.Principal) $($_.Access) ($($_.Rights))" }) -join "`n") "Get-Acl WebtoB $Role paths" }
    if ($unknown.Count -gt 0) { return New-WebtoBResult 'MANUAL' "WebtoB $Role path ACLs could not be read; general-user access could not be determined. Manually verify ACLs on the listed paths." (($unknown | ForEach-Object { "$($_.Path) => $($_.Rights)" }) -join "`n") "Get-Acl WebtoB $Role paths" }
    if ($paths.Count -eq 0) { return New-WebtoBResult 'MANUAL' "WebtoB $Role paths were not found for ACL assessment." (Get-WebtoBWindowsEvidence -State $State) "Get-Acl WebtoB $Role paths" }
    New-WebtoBResult 'GOOD' "No broad general-user access ACL entries were found on assessed WebtoB $Role paths." ($paths -join ', ') "Get-Acl WebtoB $Role paths"
}

function Invoke-WebtoBWindowsCheck {
    param([string]$ItemId, [string]$ItemName)
    $state = Get-WebtoBWindowsState
    if (-not $state.Installed) { return New-WebtoBNotInstalledResult }
    $evidence = Get-WebtoBWindowsEvidence -State $state

    switch ($ItemId) {
        'WEB-01' { return New-WebtoBResult 'N/A' 'Default administrator web-console account item is not targeted to WebtoB in the guideline metadata.' 'WEB-01 target excludes WebtoB.' 'Map WebtoB account guideline applicability' }
        'WEB-02' { return New-WebtoBResult 'N/A' 'Administrator password complexity item is not targeted to WebtoB in the guideline metadata.' 'WEB-02 target excludes WebtoB.' 'Map WebtoB password guideline applicability' }
        'WEB-03' { return New-WebtoBResult 'N/A' 'Password file ACL item is not targeted to WebtoB in the guideline metadata.' 'WEB-03 target excludes WebtoB.' 'Map WebtoB password-file guideline applicability' }
        'WEB-04' { $lines = @(Get-WebtoBActiveConfigLines $state '(?i)Options\s*=.*Indexes|-Indexes'); if ($lines -match '(?i)Options\s*=.*(?<!-)Indexes') { return New-WebtoBResult 'VULNERABLE' 'WebtoB directory indexing appears enabled.' ($lines -join "`n") 'Inspect http.m Options Indexes' }; if ($lines -match '(?i)-Indexes') { return New-WebtoBResult 'GOOD' 'WebtoB directory indexing disable evidence was found.' ($lines -join "`n") 'Inspect http.m Options Indexes' }; return New-WebtoBResult 'MANUAL' 'WebtoB directory indexing evidence was not conclusive.' $evidence 'Inspect http.m Options Indexes' }
        'WEB-05' { $lines = @(Get-WebtoBActiveConfigLines $state '(?i)SVRTYPE\s*=\s*CGI'); if ($lines.Count -gt 0) { return New-WebtoBResult 'MANUAL' 'WebtoB active CGI execution mapping (SVRTYPE=CGI) was found; confirm CGI scripts are restricted to a designated directory (e.g. /cgi-bin) and that no upload directory permits CGI execution.' ($lines -join "`n") 'Inspect http.m CGI settings' }; if (@($state.ConfigFiles).Count -eq 0) { return New-WebtoBResult 'MANUAL' 'WebtoB appears installed but no http.m config file could be read; CGI execution restriction could not be determined. Manually inspect http.m CGI settings.' $evidence 'Inspect http.m CGI settings' }; return New-WebtoBResult 'GOOD' 'No active WebtoB CGI execution mapping evidence was found.' $evidence 'Inspect http.m CGI settings' }
        'WEB-06' { $lines = @(Get-WebtoBActiveConfigLines $state '(?i)UpperDirRestrict\s*=\s*N|UpperDirRestrict\s*=\s*Y'); if ($lines -match '(?i)UpperDirRestrict\s*=\s*N') { return New-WebtoBResult 'VULNERABLE' 'WebtoB upper-directory restriction appears disabled.' ($lines -join "`n") 'Inspect http.m UpperDirRestrict' }; if ($lines -match '(?i)UpperDirRestrict\s*=\s*Y') { return New-WebtoBResult 'GOOD' 'WebtoB upper-directory restriction evidence was found.' ($lines -join "`n") 'Inspect http.m UpperDirRestrict' }; return New-WebtoBResult 'MANUAL' 'WebtoB upper-directory restriction evidence was not conclusive.' $evidence 'Inspect http.m UpperDirRestrict' }
        'WEB-07' { if (@($state.WebtoBHomes).Count -eq 0) { return New-WebtoBResult 'MANUAL' 'WebtoB appears installed but its home directory could not be derived; manually inspect for sample/manual files.' $evidence 'Search WebtoB samples/docs/manuals' }; $samplePaths = foreach ($home in $state.WebtoBHomes) { Get-ChildItem -LiteralPath $home -Recurse -Directory -ErrorAction SilentlyContinue | Where-Object { $_.FullName -match '(?i)\\(samples?|examples?|docs\\manuals)' } | Select-Object -First 50 -ExpandProperty FullName }; if ($samplePaths) { return New-WebtoBResult 'VULNERABLE' 'WebtoB sample/manual directories were found.' ($samplePaths -join "`n") 'Search WebtoB samples/docs/manuals' }; return New-WebtoBResult 'GOOD' 'No WebtoB sample/manual directories were found in inspected homes.' $evidence 'Search WebtoB samples/docs/manuals' }
        'WEB-08' { $lines = @(Get-WebtoBActiveConfigLines $state '(?i)LimitRequestBody'); $effective = @($lines | Where-Object { $_ -match '(?i)LimitRequestBody\s*=?\s*(\d+)' -and [int]$Matches[1] -gt 0 }); if ($effective.Count -gt 0) { return New-WebtoBResult 'GOOD' 'WebtoB upload/download size limit (non-zero LimitRequestBody) evidence was found.' ($effective -join "`n") 'Inspect http.m LimitRequestBody' }; if ($lines.Count -gt 0) { return New-WebtoBResult 'VULNERABLE' 'WebtoB LimitRequestBody is present but set to 0 (unlimited) or has no enforceable value; upload/download size is not effectively limited.' ($lines -join "`n") 'Inspect http.m LimitRequestBody' }; if (@($state.ConfigFiles).Count -eq 0) { return New-WebtoBResult 'MANUAL' 'WebtoB appears installed but no http.m config file could be read; upload/download size limit could not be determined. Manually inspect http.m LimitRequestBody.' $evidence 'Inspect http.m LimitRequestBody' }; return New-WebtoBResult 'VULNERABLE' 'WebtoB upload/download size limit evidence was not found.' $evidence 'Inspect http.m LimitRequestBody' }
        'WEB-09' { $accounts = @($state.Services | ForEach-Object { $_.StartName } | Where-Object { $_ }); if ($accounts -match '^(?i)(LocalSystem|NT AUTHORITY\\SYSTEM)$|Administrator') { return New-WebtoBResult 'VULNERABLE' 'WebtoB Windows service appears to run with administrator-equivalent OS privileges.' ($accounts -join ', ') 'Inspect WebtoB Windows service StartName' }; if ($accounts.Count -gt 0) { return New-WebtoBResult 'GOOD' 'WebtoB Windows service account is not administrator-equivalent.' ($accounts -join ', ') 'Inspect WebtoB Windows service StartName' }; return New-WebtoBResult 'MANUAL' 'WebtoB service account could not be determined.' $evidence 'Inspect WebtoB Windows service StartName' }
        'WEB-10' { $lines = @(Get-WebtoBConfigLines $state '(?i)REVERSE_PROXY|PathPrefix|ServerAddress|Proxy'); if ($lines.Count -gt 0) { return New-WebtoBResult 'MANUAL' 'WebtoB reverse proxy evidence was found; confirm only required proxy mappings remain.' ($lines -join "`n") 'Inspect http.m proxy settings' }; return New-WebtoBResult 'GOOD' 'No WebtoB reverse proxy evidence was found.' $evidence 'Inspect http.m proxy settings' }
        'WEB-11' { $lines = @(Get-WebtoBConfigLines $state '(?i)DOCROOT|WEBTOBDIR'); if ($lines.Count -gt 0) { return New-WebtoBResult 'MANUAL' 'WebtoB service path evidence was found; confirm DOCROOT is separated from install/system directories.' ($lines -join "`n") 'Inspect http.m DOCROOT/WEBTOBDIR' }; return New-WebtoBResult 'MANUAL' 'WebtoB service path evidence was not conclusive.' $evidence 'Inspect http.m DOCROOT/WEBTOBDIR' }
        'WEB-12' { $lines = @(Get-WebtoBActiveConfigLines $state '(?i)^\s*\*ALIAS'); if ($lines.Count -gt 0) { return New-WebtoBResult 'MANUAL' 'WebtoB active ALIAS/link mapping was found; necessity of the link cannot be derived from configuration alone. Confirm that only required aliases/links remain and remove any unnecessary ones.' ($lines -join "`n") 'Inspect http.m ALIAS settings' }; if (@($state.ConfigFiles).Count -eq 0) { return New-WebtoBResult 'MANUAL' 'WebtoB appears installed but no http.m config file could be read; ALIAS/link usage could not be determined. Manually inspect http.m ALIAS settings.' $evidence 'Inspect http.m ALIAS settings' }; return New-WebtoBResult 'GOOD' 'No WebtoB ALIAS/link mapping evidence was found.' $evidence 'Inspect http.m ALIAS settings' }
        'WEB-13' { return New-WebtoBResult 'N/A' 'Configuration file exposure/DB resource item is not targeted to WebtoB in the guideline metadata.' 'WEB-13 target excludes WebtoB.' 'Map WebtoB config exposure guideline applicability' }
        'WEB-14' { return Invoke-WebtoBAclCheck $state @($state.ConfigFiles + $state.WebtoBHomes) 'config/root' }
        'WEB-15' { return New-WebtoBResult 'N/A' 'Unnecessary script mapping item is not targeted to WebtoB in the guideline metadata.' 'WEB-15 target excludes WebtoB.' 'Map WebtoB script mapping guideline applicability' }
        'WEB-16' { $lines = @(Get-WebtoBActiveConfigLines $state '(?i)ServerTokens|ServerSignature'); if ($lines -match '(?i)ServerTokens\s+Prod|ServerTokens\s+ProductOnly') { return New-WebtoBResult 'GOOD' 'WebtoB server header minimization evidence was found (ServerTokens Prod/ProductOnly).' ($lines -join "`n") 'Inspect http.m ServerTokens/ServerSignature' }; return New-WebtoBResult 'MANUAL' 'WebtoB server header minimization evidence was not conclusive; ServerTokens Prod/ProductOnly was not confirmed (ServerSignature off alone does not minimize the Server header).' (($lines + $evidence) -join "`n") 'Inspect http.m ServerTokens/ServerSignature' }
        'WEB-17' { $lines = @(Get-WebtoBActiveConfigLines $state '(?i)^\s*\*ALIAS|RealPath\s*=|ALIAS\s*='); if ($lines.Count -gt 0) { return New-WebtoBResult 'MANUAL' 'WebtoB active virtual/alias directory mapping was found; necessity cannot be derived from configuration alone. Confirm that only required virtual/alias directories remain and remove any unnecessary ones.' ($lines -join "`n") 'Inspect http.m ALIAS settings' }; if (@($state.ConfigFiles).Count -eq 0) { return New-WebtoBResult 'MANUAL' 'WebtoB appears installed but no http.m config file could be read; virtual/alias directory presence could not be determined. Manually inspect http.m ALIAS settings.' $evidence 'Inspect http.m ALIAS settings' }; return New-WebtoBResult 'GOOD' 'No WebtoB virtual/alias directory evidence was found.' $evidence 'Inspect http.m ALIAS settings' }
        'WEB-18' { $lines = @(Get-WebtoBActiveConfigLines $state '(?i)Method\s*=.*(PROPFIND|PUT|DELETE|MKCOL|COPY|MOVE)|WebDAV\s*=\s*Y'); if ($lines.Count -gt 0) { return New-WebtoBResult 'VULNERABLE' 'WebtoB WebDAV-like methods/settings evidence was found.' ($lines -join "`n") 'Inspect http.m WebDAV methods' }; if (@($state.ConfigFiles).Count -eq 0) { return New-WebtoBResult 'MANUAL' 'WebtoB appears installed but no http.m config file could be read; WebDAV activation could not be determined. Manually inspect http.m WebDAV methods.' $evidence 'Inspect http.m WebDAV methods' }; return New-WebtoBResult 'GOOD' 'No WebtoB WebDAV-like method evidence was found.' $evidence 'Inspect http.m WebDAV methods' }
        'WEB-19' { $lines = @(Get-WebtoBActiveConfigLines $state '(?i)SvrType\s*=\s*SSI'); if ($lines.Count -gt 0) { return New-WebtoBResult 'VULNERABLE' 'WebtoB SSI server mapping evidence was found.' ($lines -join "`n") 'Inspect http.m SSI settings' }; if (@($state.ConfigFiles).Count -eq 0) { return New-WebtoBResult 'MANUAL' 'WebtoB appears installed but no http.m config file could be read; SSI activation could not be determined. Manually inspect http.m SSI settings.' $evidence 'Inspect http.m SSI settings' }; return New-WebtoBResult 'GOOD' 'No WebtoB SSI mapping evidence was found.' $evidence 'Inspect http.m SSI settings' }
        'WEB-20' { $lines = @(Get-WebtoBActiveConfigLines $state '(?i)SSLFLAG\s*=\s*[NY]|SSLNAME|CertificateFile|Protocols'); if ($lines -match '(?i)SSLFLAG\s*=\s*Y') { return New-WebtoBResult 'GOOD' 'WebtoB SSL/TLS is enabled (SSLFLAG=Y).' ($lines -join "`n") 'Inspect http.m SSL settings' }; if ($lines -match '(?i)SSLFLAG\s*=\s*N') { return New-WebtoBResult 'VULNERABLE' 'WebtoB SSL/TLS is disabled (SSLFLAG=N) despite SSL configuration being present.' ($lines -join "`n") 'Inspect http.m SSL settings' }; if ($lines.Count -gt 0) { return New-WebtoBResult 'MANUAL' 'WebtoB SSL configuration directives were found but the SSLFLAG activation state could not be determined.' (($lines + $evidence) -join "`n") 'Inspect http.m SSL settings' }; if (@($state.ConfigFiles).Count -eq 0) { return New-WebtoBResult 'MANUAL' 'WebtoB appears installed but no http.m config file could be read; SSL/TLS activation could not be determined. Manually inspect http.m SSL settings.' $evidence 'Inspect http.m SSL settings' }; return New-WebtoBResult 'VULNERABLE' 'WebtoB SSL/TLS activation evidence was not found.' $evidence 'Inspect http.m SSL settings' }
        'WEB-21' { $lines = @(Get-WebtoBActiveConfigLines $state '(?i)URLRewrite\s*=\s*[NY]|URLRewriteConfig|RewriteRule|https://'); if (($lines -match '(?i)URLRewrite\s*=\s*Y') -and ($lines -match '(?i)RewriteRule\s+\S+\s+https://')) { return New-WebtoBResult 'GOOD' 'WebtoB HTTP-to-HTTPS redirection is enabled (URLRewrite=Y with an explicit RewriteRule ... https:// redirect rule).' ($lines -join "`n") 'Inspect http.m rewrite settings' }; if ($lines -match '(?i)URLRewrite\s*=\s*N') { return New-WebtoBResult 'VULNERABLE' 'WebtoB URL rewrite is disabled (URLRewrite=N); HTTPS redirection is not active.' ($lines -join "`n") 'Inspect http.m rewrite settings' }; if ($lines -match '(?i)URLRewrite\s*=\s*Y') { return New-WebtoBResult 'MANUAL' 'WebtoB URLRewrite=Y is set but an explicit HTTPS redirect rule (RewriteRule ... https://) could not be confirmed; verify the rewrite config.' (($lines + $evidence) -join "`n") 'Inspect http.m rewrite settings' }; if (@($state.ConfigFiles).Count -eq 0) { return New-WebtoBResult 'MANUAL' 'WebtoB appears installed but no http.m config file could be read; HTTP-to-HTTPS redirection could not be determined. Manually verify redirection is enabled.' $evidence 'Inspect http.m rewrite settings' }; return New-WebtoBResult 'VULNERABLE' 'WebtoB HTTP-to-HTTPS redirection activation evidence was not found.' $evidence 'Inspect http.m rewrite settings' }
        'WEB-22' { $lines = @(Get-WebtoBActiveConfigLines $state '(?i)ERRORDOCUMENT|\surl\s*='); if ($lines -match '(?i)url\s*=\s*"?[^",\s]+') { return New-WebtoBResult 'GOOD' 'WebtoB custom error page is designated (ERRORDOCUMENT with a url= assignment).' ($lines -join "`n") 'Inspect http.m ERRORDOCUMENT' }; if ($lines -match '(?i)ERRORDOCUMENT') { return New-WebtoBResult 'VULNERABLE' 'WebtoB ERRORDOCUMENT section was found but no custom error page (url=) was designated.' (($lines + $evidence) -join "`n") 'Inspect http.m ERRORDOCUMENT' }; if (@($state.ConfigFiles).Count -eq 0) { return New-WebtoBResult 'MANUAL' 'WebtoB appears installed but no http.m config file could be read; custom error page designation could not be determined. Manually verify a custom error page is separately designated.' $evidence 'Inspect http.m ERRORDOCUMENT' }; return New-WebtoBResult 'VULNERABLE' 'WebtoB custom error page designation evidence was not found.' $evidence 'Inspect http.m ERRORDOCUMENT' }
        'WEB-23' { return New-WebtoBResult 'N/A' 'LDAP digest algorithm item (WEB-23) targets Tomcat only; WebtoB is out of scope.' 'WEB-23 target excludes WebtoB.' 'Map WebtoB guideline applicability' }
        'WEB-24' { $lines = @(Get-WebtoBConfigLines $state '(?i)upload|RealPath|ALIAS|LimitRequestBody'); if ($lines.Count -gt 0) { return New-WebtoBResult 'MANUAL' 'WebtoB upload/path evidence was found; confirm upload path is separated and ACL-restricted.' ($lines -join "`n") 'Inspect http.m upload path settings' }; return New-WebtoBResult 'MANUAL' 'WebtoB upload path evidence was not conclusive.' $evidence 'Inspect http.m upload path settings' }
        'WEB-25' { if ($state.WscflPath) { $output = & $state.WscflPath -version 2>&1 | Out-String; return New-WebtoBResult 'MANUAL' 'WebtoB was found. Compare detected version against current TmaxSoft security/patch guidance.' $output "$($state.WscflPath) -version" }; return New-WebtoBResult 'MANUAL' 'WebtoB was found, but wscfl was not found. Confirm version and patch level manually.' $evidence 'wscfl -version discovery' }
        'WEB-26' { $logTargets = @($state.LogDirs); foreach ($dir in @($state.LogDirs)) { $logTargets += @(Get-ChildItem -LiteralPath $dir -File -ErrorAction SilentlyContinue | Select-Object -First 200 -ExpandProperty FullName) }; return Invoke-WebtoBAclCheck $state $logTargets 'log' }
        default { return New-WebtoBResult 'MANUAL' "No WebtoB Windows diagnostic rule is defined for $ItemId." $evidence 'WebtoB Windows generic discovery' }
    }
}
