# KISA 취약점 진단 시스템 - 공통 라이브러리 (PowerShell)
# Encoding: UTF-8, CRLF
# Purpose: 진단 결과 생성, 파일 저장, 공통 함수 제공 (Unix common.sh 대응)
# Platform: Windows Server, PC, Windows 제품군
#
# 비고: 이 라이브러리는 Unix `lib/common.sh`의 PowerShell 대응본이다.
#       `result_manager.ps1`이 일부 동일 함수(Get-Hostname 등)를 재정의하므로,
#       두 라이브러리를 함께 dot-source해도 충돌 없이 마지막 정의가 적용된다.

#Requires -Version 5.1

# 진단 결과 기본 경로 (Unix common.sh와 동일 규약)
if (-not (Get-Variable -Name RESULT_DIR_BASE -Scope Script -ErrorAction SilentlyContinue)) {
    $Script:RESULT_DIR_BASE = "results"
}
$Script:DATE_SUFFIX = (Get-Date).ToString("yyyyMMdd")
$Script:TIMESTAMP = (Get-Date).ToString("yyyyMMdd_HHmmss")

# 호스트네임 가져오기 (Unix get_hostname 대응)
function Get-Hostname {
    try {
        $name = [System.Net.Dns]::GetHostName()
        if (-not [string]::IsNullOrWhiteSpace($name)) { return $name }
    } catch {}

    if (-not [string]::IsNullOrWhiteSpace($env:COMPUTERNAME)) {
        return $env:COMPUTERNAME
    }

    return "unknown"
}

# 결과 파일 경로 생성 (Unix create_result_path 대응)
function New-ResultPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ItemId,
        [string]$ScriptDir = $SCRIPT_DIR
    )

    $platformDir = Join-Path $ScriptDir (Join-Path $RESULT_DIR_BASE $DATE_SUFFIX)
    $hostname = Get-Hostname

    if (-not (Test-Path $platformDir)) {
        New-Item -ItemType Directory -Path $platformDir -Force | Out-Null
    }

    return (Join-Path $platformDir "${hostname}_${ItemId}_result_${TIMESTAMP}")
}

# 디스크 공간 확인 (Unix check_disk_space 대응, 최소 100MB)
function Test-DiskSpace {
    param(
        [string]$Path = ".",
        [int]$RequiredMB = 100
    )

    try {
        $driveName = (Get-Item $Path).PSDrive.Name
        $freeMB = [math]::Floor((Get-PSDrive -Name $driveName).Free / 1MB)
    } catch {
        Write-Warning "디스크 공간 확인 실패: $_"
        return $false
    }

    if ($freeMB -lt $RequiredMB) {
        Write-Warning "디스크 공간 부족: ${freeMB}MB 가용 (필요: ${RequiredMB}MB)"
        return $false
    }

    return $true
}

# 진단 결과 저장 성공 확인 (Unix verify_result_files 대응)
function Confirm-ResultFiles {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ItemId,
        [string]$ScriptDir = $SCRIPT_DIR
    )

    $resultPath = New-ResultPath -ItemId $ItemId -ScriptDir $ScriptDir

    if ((Test-Path "${resultPath}.json") -and (Test-Path "${resultPath}.txt")) {
        return $true
    }

    Write-Error "❌ 치명적 오류: 결과 파일 생성 실패 (예상 경로: ${resultPath})"
    return $false
}

# 필수 라이브러리 로드 확인 (Unix ensure_libraries_loaded 대응)
function Assert-LibrariesLoaded {
    $requiredFunctions = @(
        "Get-Hostname",
        "Test-RunallMode"
    )

    foreach ($fn in $requiredFunctions) {
        if (-not (Get-Command $fn -ErrorAction SilentlyContinue)) {
            Write-Error "❌ 치명적 오류: 필수 함수 미로드: $fn (result_manager.ps1 로드 여부 확인)"
            return $false
        }
    }

    return $true
}
