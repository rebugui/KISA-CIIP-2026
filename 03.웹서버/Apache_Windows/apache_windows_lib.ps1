#Requires -Version 5.1

function Add-ApacheUniquePath {
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

function Get-ApacheWindowsServices {
    try {
        @(Get-CimInstance Win32_Service -ErrorAction Stop | Where-Object {
            $_.Name -match '(?i)apache|httpd' -or $_.DisplayName -match '(?i)apache|httpd'
        })
    }
    catch {
        @()
    }
}

function Get-ApacheWindowsConfigCandidates {
    $paths = [System.Collections.Generic.List[string]]::new()

    $staticCandidates = @(
        "$env:ProgramFiles\Apache Software Foundation\Apache24\conf\httpd.conf",
        "$env:ProgramFiles\Apache24\conf\httpd.conf",
        "${env:ProgramFiles(x86)}\Apache Software Foundation\Apache24\conf\httpd.conf",
        "${env:ProgramFiles(x86)}\Apache24\conf\httpd.conf",
        "C:\Apache24\conf\httpd.conf",
        "C:\Apache\conf\httpd.conf",
        "C:\xampp\apache\conf\httpd.conf"
    )

    foreach ($candidate in $staticCandidates) {
        Add-ApacheUniquePath -Paths $paths -Candidate $candidate
    }

    foreach ($service in Get-ApacheWindowsServices) {
        $pathName = [string]$service.PathName
        if ($pathName -match '(?i)-f\s+"([^"]+)"') {
            Add-ApacheUniquePath -Paths $paths -Candidate $Matches[1]
        }
        elseif ($pathName -match '(?i)-f\s+([^\s]+)') {
            Add-ApacheUniquePath -Paths $paths -Candidate $Matches[1]
        }

        if ($pathName -match '(?i)"([^"]*\\(?:httpd|apache)\.exe)"') {
            $exePath = $Matches[1]
        }
        elseif ($pathName -match '(?i)(\S*\\(?:httpd|apache)\.exe)') {
            $exePath = $Matches[1]
        }
        else {
            $exePath = $null
        }

        if ($exePath) {
            $root = Split-Path -Parent (Split-Path -Parent $exePath)
            Add-ApacheUniquePath -Paths $paths -Candidate (Join-Path $root 'conf\httpd.conf')
        }
    }

    return @($paths)
}

function Resolve-ApacheWindowsIncludePath {
    param(
        [string]$BaseConfig,
        [string]$IncludeValue
    )

    $clean = $IncludeValue.Trim().Trim('"').Replace('/', '\')
    if ([System.IO.Path]::IsPathRooted($clean)) {
        return $clean
    }

    $baseDir = Split-Path -Parent $BaseConfig
    return Join-Path $baseDir $clean
}

function Get-ApacheWindowsConfigText {
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
            if ($trimmed -match '^(?i)Include(?:Optional)?\s+(.+)$') {
                $includePath = Resolve-ApacheWindowsIncludePath -BaseConfig $file -IncludeValue $Matches[1]
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

function Get-ApacheWindowsAclInspection {
    param(
        [Parameter(Mandatory = $true)][string[]]$Paths,
        [Parameter(Mandatory = $true)][scriptblock]$BroadPrincipalTest,
        [switch]$IncludeContainerChildren
    )

    $broad = [System.Collections.Generic.List[string]]::new()
    $errors = [System.Collections.Generic.List[string]]::new()

    foreach ($path in $Paths) {
        if ([string]::IsNullOrWhiteSpace($path)) { continue }
        $targets = @($path)
        if ($IncludeContainerChildren -and (Test-Path -LiteralPath $path -PathType Container)) {
            $targets += @(Get-ChildItem -LiteralPath $path -File -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName)
        }
        foreach ($target in $targets) {
            try {
                $acl = Get-Acl -LiteralPath $target -ErrorAction Stop
                foreach ($rule in $acl.Access) {
                    if ($rule.AccessControlType -eq 'Allow' -and (& $BroadPrincipalTest $rule.IdentityReference)) {
                        $broad.Add("$target => $($rule.IdentityReference) $($rule.FileSystemRights)") | Out-Null
                    }
                }
            }
            catch {
                $errors.Add("$target => ACL read failed: $($_.Exception.Message)") | Out-Null
            }
        }
    }

    return [pscustomobject]@{
        Broad  = @($broad)
        Errors = @($errors)
    }
}
