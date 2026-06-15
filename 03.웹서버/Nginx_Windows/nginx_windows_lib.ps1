#Requires -Version 5.1

function Add-NginxUniquePath {
    param(
        [System.Collections.Generic.List[string]]$Paths,
        [string]$Candidate
    )

    if ([string]::IsNullOrWhiteSpace($Candidate)) {
        return
    }

    try {
        $resolved = [System.IO.Path]::GetFullPath($Candidate.Trim('"'))
    }
    catch {
        return
    }

    if ((Test-Path -LiteralPath $resolved -PathType Leaf) -and -not $Paths.Contains($resolved)) {
        $Paths.Add($resolved) | Out-Null
    }
}

function Get-NginxWindowsProcesses {
    try {
        @(Get-CimInstance Win32_Process -ErrorAction Stop | Where-Object {
            $_.Name -match '(?i)^nginx\.exe$'
        })
    }
    catch {
        @()
    }
}

function Get-NginxWindowsServices {
    try {
        @(Get-CimInstance Win32_Service -ErrorAction Stop | Where-Object {
            $_.Name -match '(?i)nginx' -or $_.DisplayName -match '(?i)nginx'
        })
    }
    catch {
        @()
    }
}

function Get-NginxWindowsConfigCandidates {
    $paths = [System.Collections.Generic.List[string]]::new()

    $staticCandidates = @(
        "$env:ProgramFiles\nginx\conf\nginx.conf",
        "${env:ProgramFiles(x86)}\nginx\conf\nginx.conf",
        "C:\nginx\conf\nginx.conf",
        "C:\tools\nginx\conf\nginx.conf",
        "C:\ProgramData\nginx\conf\nginx.conf"
    )

    foreach ($candidate in $staticCandidates) {
        Add-NginxUniquePath -Paths $paths -Candidate $candidate
    }

    foreach ($process in Get-NginxWindowsProcesses) {
        $commandLine = [string]$process.CommandLine
        if ($commandLine -match '(?i)-c\s+"([^"]+)"') {
            Add-NginxUniquePath -Paths $paths -Candidate $Matches[1]
        }
        elseif ($commandLine -match '(?i)-c\s+([^\s]+)') {
            Add-NginxUniquePath -Paths $paths -Candidate $Matches[1]
        }

        if ($commandLine -match '(?i)-p\s+"([^"]+)"') {
            $prefix = $Matches[1]
        }
        elseif ($commandLine -match '(?i)-p\s+([^\s]+)') {
            $prefix = $Matches[1]
        }
        elseif ($commandLine -match '(?i)"([^"]*\\nginx\.exe)"') {
            $prefix = Split-Path -Parent $Matches[1]
        }
        elseif ($commandLine -match '(?i)(\S*\\nginx\.exe)') {
            $prefix = Split-Path -Parent $Matches[1]
        }
        else {
            $prefix = $null
        }

        if ($prefix) {
            Add-NginxUniquePath -Paths $paths -Candidate (Join-Path $prefix 'conf\nginx.conf')
        }
    }

    foreach ($service in Get-NginxWindowsServices) {
        $pathName = [string]$service.PathName
        if ($pathName -match '(?i)-c\s+"([^"]+)"') {
            Add-NginxUniquePath -Paths $paths -Candidate $Matches[1]
        }
        elseif ($pathName -match '(?i)-c\s+([^\s]+)') {
            Add-NginxUniquePath -Paths $paths -Candidate $Matches[1]
        }

        if ($pathName -match '(?i)"([^"]*\\nginx\.exe)"') {
            $prefix = Split-Path -Parent $Matches[1]
        }
        elseif ($pathName -match '(?i)(\S*\\nginx\.exe)') {
            $prefix = Split-Path -Parent $Matches[1]
        }
        else {
            $prefix = $null
        }

        if ($prefix) {
            Add-NginxUniquePath -Paths $paths -Candidate (Join-Path $prefix 'conf\nginx.conf')
        }
    }

    return @($paths)
}

function Resolve-NginxWindowsIncludePath {
    param(
        [string]$BaseConfig,
        [string]$IncludeValue
    )

    $clean = $IncludeValue.Trim().Trim(';').Trim('"').Replace('/', '\')
    if ([System.IO.Path]::IsPathRooted($clean)) {
        return $clean
    }

    $baseDir = Split-Path -Parent $BaseConfig
    return Join-Path $baseDir $clean
}

function Get-NginxWindowsConfigText {
    param([string[]]$ConfigFiles)

    $visited = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $queue = [System.Collections.Generic.Queue[string]]::new()
    foreach ($file in $ConfigFiles) {
        $queue.Enqueue($file)
    }

    $parts = [System.Collections.Generic.List[string]]::new()
    while ($queue.Count -gt 0) {
        $file = $queue.Dequeue()
        if (-not (Test-Path -LiteralPath $file -PathType Leaf)) {
            continue
        }
        if (-not $visited.Add($file)) {
            continue
        }

        $text = Get-Content -LiteralPath $file -Raw -ErrorAction Stop
        $parts.Add("`n# FILE: $file`n$text") | Out-Null

        foreach ($line in ($text -split "`r?`n")) {
            $trimmed = $line.Trim()
            if ($trimmed -match '^#') {
                continue
            }
            if ($trimmed -match '^(?i)include\s+(.+);$') {
                $includePath = Resolve-NginxWindowsIncludePath -BaseConfig $file -IncludeValue $Matches[1]
                foreach ($match in @(Get-ChildItem -Path $includePath -File -ErrorAction SilentlyContinue)) {
                    $queue.Enqueue($match.FullName)
                }
            }
        }
    }

    return [pscustomobject]@{
        Text = ($parts -join "`n")
        Files = @($visited)
    }
}

function Get-NginxActiveLines {
    param([string]$ConfigText)

    @($ConfigText -split "`r?`n" | ForEach-Object { $_.Trim() } | Where-Object {
        $_ -and $_ -notmatch '^#'
    })
}

function Get-NginxWindowsState {
    $processes = @(Get-NginxWindowsProcesses)
    $services = @(Get-NginxWindowsServices)
    $configFiles = @(Get-NginxWindowsConfigCandidates)
    $config = if ($configFiles.Count -gt 0) { Get-NginxWindowsConfigText -ConfigFiles $configFiles } else { $null }
    $activeLines = if ($config) { Get-NginxActiveLines -ConfigText $config.Text } else { @() }

    [pscustomobject]@{
        Processes = $processes
        Services = $services
        ConfigFiles = $configFiles
        Config = $config
        ActiveLines = @($activeLines)
        Installed = ($processes.Count -gt 0 -or $services.Count -gt 0 -or $configFiles.Count -gt 0)
    }
}

function Get-NginxWindowsProcessEvidence {
    param($State)

    @(
        $State.Processes | ForEach-Object { "Process $($_.ProcessId): $($_.CommandLine)" }
        $State.Services | ForEach-Object { "Service $($_.Name) [$($_.State)] $($_.StartName): $($_.PathName)" }
    ) -join "`n"
}

function Resolve-NginxConfiguredPath {
    param(
        [string]$Path,
        [string[]]$ConfigFiles
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return $null
    }

    $clean = $Path.Trim().Trim(';').Trim('"').Replace('/', '\')
    if ([System.IO.Path]::IsPathRooted($clean)) {
        return $clean
    }

    foreach ($conf in $ConfigFiles) {
        $prefix = Split-Path -Parent (Split-Path -Parent $conf)
        $candidate = Join-Path $prefix $clean
        if (Test-Path -LiteralPath $candidate) {
            return $candidate
        }
    }

    if ($ConfigFiles.Count -gt 0) {
        $prefix = Split-Path -Parent (Split-Path -Parent $ConfigFiles[0])
        return (Join-Path $prefix $clean)
    }

    return $clean
}

function Get-NginxRootPaths {
    param($State)

    $roots = [System.Collections.Generic.List[string]]::new()
    foreach ($line in $State.ActiveLines) {
        if ($line -match '^(?i)root\s+(.+);$') {
            $resolved = Resolve-NginxConfiguredPath -Path $Matches[1] -ConfigFiles $State.ConfigFiles
            if ($resolved -and -not $roots.Contains($resolved)) {
                $roots.Add($resolved) | Out-Null
            }
        }
    }
    return @($roots)
}

function Get-NginxAliasPaths {
    param($State)

    $aliases = [System.Collections.Generic.List[object]]::new()
    foreach ($line in $State.ActiveLines) {
        if ($line -match '^(?i)alias\s+(.+);$') {
            $raw = $Matches[1]
            $resolved = Resolve-NginxConfiguredPath -Path $raw -ConfigFiles $State.ConfigFiles
            $aliases.Add([pscustomobject]@{
                Directive = $line
                Path = $resolved
            }) | Out-Null
        }
    }
    return @($aliases)
}

function Get-NginxDefaultRootCandidates {
    $paths = [System.Collections.Generic.List[string]]::new()
    foreach ($candidate in @(
        'C:\nginx\html',
        "$env:ProgramFiles\nginx\html",
        "${env:ProgramFiles(x86)}\nginx\html",
        'C:\tools\nginx\html',
        'C:\inetpub\wwwroot'
    )) {
        if (-not [string]::IsNullOrWhiteSpace($candidate) -and (Test-Path -LiteralPath $candidate -PathType Container)) {
            try {
                $resolved = [System.IO.Path]::GetFullPath($candidate)
                if (-not $paths.Contains($resolved)) {
                    $paths.Add($resolved) | Out-Null
                }
            }
            catch {
                continue
            }
        }
    }
    return @($paths)
}

function Test-NginxBroadPrincipal {
    param([System.Security.Principal.IdentityReference]$Identity)

    try {
        $sid = $Identity.Translate([System.Security.Principal.SecurityIdentifier]).Value
    }
    catch {
        $sid = [string]$Identity
    }

    return ($sid -eq 'S-1-1-0') -or ($sid -eq 'S-1-5-11') -or ($sid -eq 'S-1-5-32-545') -or ($sid -eq 'S-1-5-32-546') -or ($sid -match '-513$') -or (([string]$Identity) -match '(?i)Everyone|Authenticated Users|BUILTIN\\Users|Guests|Domain Users')
}

function Test-NginxAnyRight {
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

function Get-NginxBroadAclEvidence {
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

    try {
        $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
    }
    catch {
        return [pscustomobject]@{ Path = $Path; Role = $Role; Access = 'Unknown'; Principal = 'N/A'; Rights = "ACL read failed: $($_.Exception.Message)" }
    }

    foreach ($rule in $acl.Access) {
        if ($rule.AccessControlType -ne 'Allow' -or -not (Test-NginxBroadPrincipal -Identity $rule.IdentityReference)) {
            continue
        }
        $hasWrite = Test-NginxAnyRight -Rights $rule.FileSystemRights -Expected $writeRights
        $hasRead = Test-NginxAnyRight -Rights $rule.FileSystemRights -Expected $readRights
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
