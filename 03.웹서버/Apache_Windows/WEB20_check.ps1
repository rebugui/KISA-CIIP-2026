# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Version: 1.0.1
# @Last Updated: 2026-05-24
# ============================================================================
# [Assessment Item]
# @ID          : WEB-20
# @Category    : 웹서비스>4.보안관리
# @Platform    : Apache_Windows
# @Severity    : 상
# @Title       : SSL/TLS 활성화
# @Description : Apache for Windows SSL/TLS configuration check.
# @Reference   : docs/guideline_metadata.json and docs/04_웹서비스.md
# ============================================================================

#Requires -Version 5.1

$ErrorActionPreference = 'Stop'
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\..\lib"
. "${LIB_DIR}\result_manager.ps1"

$ITEM_ID = "WEB-20"
$ITEM_NAME = "SSL/TLS 활성화"
$SEVERITY = "상"

$purpose = "서버와 클라이언트 간 통신 시 데이터의 평문 전송을 사용하지 않고 데이터가 암호화되는 SSL/TLS 인증 암호화 접속을 통해 스니 핑을 통한 정보 유출의 위험을 방지하기 위함"
$threat = "웹상의 데이터 통신 시 서버와 클라이언트 간에 데이터를 평문 전송하는 경우, 간단한 도청(스니핑)을 통해 정보가 탈취 및 도용될 위험이 존재함 SSL/TLS가 활성화되어 있지 않을 경우, 데이터는 암호화되지 않아 공격자가 중간에서 데이터를 가로채거나 도청할 수 있으며, 더 나아가 평문으로 전송되어 중간에서 변경될 우려가 있어 데이터의 정확성이 훼손될 위험이 존재함"
$criteria_good = "SSL/TLS 설정이 활성화되어 있는 경우"
$criteria_bad = "SSL/TLS 설정이 비활성화되어 있는 경우"
$remediation = "웹 서비스 내 SSL/TLS 활성화 설정"

function Add-UniquePath {
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

function Get-ApacheServices {
    try {
        @(Get-CimInstance Win32_Service -ErrorAction Stop | Where-Object {
            $_.Name -match '(?i)apache|httpd' -or $_.DisplayName -match '(?i)apache|httpd'
        })
    }
    catch {
        @()
    }
}

function Get-ApacheConfigCandidates {
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
        Add-UniquePath -Paths $paths -Candidate $candidate
    }

    foreach ($service in Get-ApacheServices) {
        $pathName = [string]$service.PathName
        if ($pathName -match '(?i)-f\s+"([^"]+)"') {
            Add-UniquePath -Paths $paths -Candidate $Matches[1]
        }
        elseif ($pathName -match '(?i)-f\s+([^\s]+)') {
            Add-UniquePath -Paths $paths -Candidate $Matches[1]
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
            Add-UniquePath -Paths $paths -Candidate (Join-Path $root 'conf\httpd.conf')
        }
    }

    return @($paths)
}

function Resolve-ApacheIncludePath {
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

function Get-ApacheConfigText {
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
                $includePath = Resolve-ApacheIncludePath -BaseConfig $file -IncludeValue $Matches[1]
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

try {
    $services = @(Get-ApacheServices)
    $configCandidates = @(Get-ApacheConfigCandidates)

    if ($services.Count -eq 0 -and $configCandidates.Count -eq 0) {
        $finalResult = "N/A"
        $status = "N/A"
        $summary = "Apache for Windows service/configuration was not found."
        $commandOutput = "No Apache service or known httpd.conf path found."
        $commandExecuted = "Get-CimInstance Win32_Service; known Apache httpd.conf paths"
    }
    elseif ($configCandidates.Count -eq 0) {
        $finalResult = "MANUAL"
        $status = "수동진단"
        $summary = "Apache service was found, but httpd.conf could not be located automatically."
        $commandOutput = ($services | Select-Object Name, DisplayName, State, PathName | Format-List | Out-String).Trim()
        $commandExecuted = "Get-CimInstance Win32_Service | Where-Object Name/DisplayName matches Apache/httpd"
    }
    else {
        $config = Get-ApacheConfigText -ConfigFiles $configCandidates
        $activeLines = @($config.Text -split "`r?`n" | Where-Object { $_.Trim() -notmatch '^#' })
        $activeText = $activeLines -join "`n"

        $hasSslModule = $activeText -match '(?im)^\s*LoadModule\s+ssl_module\b'
        $hasSslEngine = $activeText -match '(?im)^\s*SSLEngine\s+on\b'
        $hasHttpsListen = $activeText -match '(?im)^\s*Listen\s+(?:\S+:)?443\b'
        $hasHttpsVirtualHost = $activeText -match '(?im)<VirtualHost\s+[^>]*:443\s*>'
        $hasCertificate = $activeText -match '(?im)^\s*SSLCertificateFile\s+\S+'

        $evidence = @(
            "Config files: $($config.Files -join ', ')",
            "LoadModule ssl_module: $hasSslModule",
            "SSLEngine on: $hasSslEngine",
            "Listen 443: $hasHttpsListen",
            "VirtualHost :443: $hasHttpsVirtualHost",
            "SSLCertificateFile: $hasCertificate"
        )

        if ($hasSslModule -and $hasSslEngine -and ($hasHttpsListen -or $hasHttpsVirtualHost) -and $hasCertificate) {
            $finalResult = "GOOD"
            $status = "양호"
            $summary = "Apache SSL/TLS appears enabled with ssl_module, SSLEngine, HTTPS binding, and certificate configuration."
        }
        else {
            $finalResult = "VULNERABLE"
            $status = "취약"
            $summary = "Apache SSL/TLS configuration is incomplete or disabled."
        }

        $commandOutput = $evidence -join "`n"
        $commandExecuted = "Parse Apache httpd.conf and included *.conf files for ssl_module, SSLEngine, Listen 443, VirtualHost :443, SSLCertificateFile"
    }
}
catch {
    $finalResult = "MANUAL"
    $status = "수동진단"
    $summary = "Diagnostic execution failed; manual review required."
    $commandOutput = "Diagnostic execution failed: $($_.Exception.Message)"
    $commandExecuted = "Apache Windows SSL/TLS configuration discovery"
}

$resultParams = @{
    ItemId = $ITEM_ID
    ItemName = $ITEM_NAME
    Status = $status
    FinalResult = $finalResult
    InspectionSummary = $summary
    CommandResult = $commandOutput
    CommandExecuted = $commandExecuted
    GuidelinePurpose = $purpose
    GuidelineThreat = $threat
    GuidelineCriteriaGood = $criteria_good
    GuidelineCriteriaBad = $criteria_bad
    GuidelineRemediation = $remediation
    ScriptDir = $SCRIPT_DIR
}

Save-DualResult @resultParams

if (-not (Test-RunallMode)) {
    Write-Host ""
    Write-Host "Diagnostic complete: $ITEM_ID ($finalResult)"
}

exit 0