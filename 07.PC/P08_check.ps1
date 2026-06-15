

# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-05-20
# ============================================================================
# [점검 항목 상세]
# @ID          : PC-08
# @Category    : PC (Personal Computer)
# @Platform    : Windows 10, 11
# @Severity    : 중
# @Title       : 대상 시스템이 Windows 서버를 제외한 다른 OS로 멀티 부팅이 가능하지 않도록 설정
# @Description : 대상 시스템이 Windows 서버를 제외한 다른 OS로 멀티 부팅이 가능하지 않도록 설정
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\lib"
. "${LIB_DIR}\result_manager.ps1"

# Parameters
$ITEM_ID = "PC-08"
$ITEM_NAME = "대상 시스템이 Windows 서버를 제외한 다른 OS로 멀티 부팅이 가능하지 않도록 설정"
$SEVERITY = "중"
$CATEGORY = "2.서비스관리"

# run_all 모드가 아닐 때만 진단 정보 출력
if (-not (Test-RunallMode)) {
    Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"
    Write-Host "카테고리: $CATEGORY"
}

# 1. Run diagnostic using bcdedit
# bcdedit의 OS Loader 식별자(identifier) 개수로 멀티부팅 여부 판단
# 조회 권한 부족/실패 시 부트 항목 0개로 간주하지 않고 수동진단 처리
$commandExecuted = 'bcdedit /enum osloader; bcdedit /enum firmware'
$commandOutput = ""
try {
    $bcdOutput = bcdedit /enum osloader 2>&1 | Out-String
    $bcdExitCode = $LASTEXITCODE
    $commandOutput = "[bcdedit /enum osloader]`r`n" + $bcdOutput

    if ($bcdExitCode -ne 0 -or
        $bcdOutput -match 'Access is denied' -or
        $bcdOutput -match 'could not be opened' -or
        $bcdOutput -match '액세스가 거부') {
        $finalResult = "MANUAL"
        $summary = "bcdedit 조회 실패 또는 권한 부족: 관리자 권한으로 멀티부팅 여부 수동 확인 필요"
        $status = "수동진단"
    } else {
        $identifierLines = $bcdOutput -split "`r?`n" | Where-Object {
            $_ -match '^\s*(identifier|식별자)\s+(\{current\}|\{default\}|\{[0-9a-fA-F-]+\})'
        }
        $actualBootEntries = @($identifierLines).Count

        # bcdedit /enum osloader는 Windows BCD만 보므로, GRUB 우선 듀얼부팅 등
        # 비-Windows 부트로더는 보이지 않는 사각지대가 있음.
        # EFI 펌웨어 부트 항목을 추가 조회하여 비-Windows OS 로더 존재 여부를 보강 확인.
        $firmwareHasForeignLoader = $false
        $firmwareCheckable = $false
        $firmwareOutput = bcdedit /enum firmware 2>&1 | Out-String
        $fwExit = $LASTEXITCODE
        $commandOutput += "`r`n`r`n[bcdedit /enum firmware]`r`n" + $firmwareOutput
        if ($fwExit -eq 0 -and
            $firmwareOutput -notmatch 'Access is denied' -and
            $firmwareOutput -notmatch '액세스가 거부' -and
            $firmwareOutput -notmatch 'could not be opened' -and
            $firmwareOutput -notmatch 'only.*BIOS') {
            $firmwareCheckable = $true
            # 펌웨어 부트 항목 설명(description)에 비-Windows OS/부트로더 키워드가 있으면 외부 OS 로더로 간주
            $fwDescLines = $firmwareOutput -split "`r?`n" | Where-Object {
                $_ -match '(description|설명)\s+'
            }
            foreach ($descLine in $fwDescLines) {
                if ($descLine -match '(?i)(grub|ubuntu|linux|debian|fedora|centos|rhel|mint|manjaro|arch|opensuse|shim|rEFInd|bootmgfw\.efi/linux)') {
                    $firmwareHasForeignLoader = $true
                    break
                }
            }
        }

        if ($firmwareHasForeignLoader) {
            $finalResult = "VULNERABLE"
            $summary = "EFI 펌웨어 부트 항목에서 비-Windows OS 로더(GRUB/Linux 등) 감지: 멀티 부팅 구성 (OS Loader $actualBootEntries개)"
            $status = "취약"
        } elseif ($actualBootEntries -eq 0) {
            $finalResult = "MANUAL"
            $summary = "bcdedit 조회는 성공했으나 OS Loader 항목을 확인하지 못함: 수동 확인 필요"
            $status = "수동진단"
        } elseif ($actualBootEntries -ge 2) {
            $finalResult = "VULNERABLE"
            $summary = "멀티 부팅 구성 감지 (OS Loader $actualBootEntries개)"
            $status = "취약"
        } elseif (-not $firmwareCheckable) {
            # 단일 Windows BCD 항목이나, 펌웨어 부트 항목을 확인할 수 없어
            # GRUB 우선 듀얼부팅 사각지대를 배제할 수 없음 → 양호로 단정하지 않고 수동진단
            $finalResult = "MANUAL"
            $summary = "Windows BCD에는 단일 OS Loader($actualBootEntries개)만 존재하나, EFI 펌웨어 부트 항목 확인 불가로 비-Windows 멀티부팅 가능성 배제 불가: 수동 확인 필요"
            $status = "수동진단"
        } else {
            $finalResult = "GOOD"
            $summary = "단일 부팅 구성 (OS Loader $actualBootEntries개, EFI 펌웨어 부트 항목에 비-Windows 로더 없음)"
            $status = "양호"
        }
    }
} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: msconfig 또는 레지스트리 수동 확인 필요"
    $status = "수동진단"
    $commandOutput = "진단 실패"
}

# 2. lib를 통한 결과 저장
$purpose = '사용자 PC에서 멀티 부팅을 사용하는지를 점검하여 다른 OS를 이용한 주요 파일 시스템 접근을 차단하기 위함'
$threat = '멀티 부팅이 가능한 경우, 공격자는 해당 PC의 주요 OS 이외에 다른 OS로 부트하여 중요한 정보가 들어 있는 파일 시스템에 접근하여 주요 정보를 획득할 수 있는 위험이 존재함'
$criteria_good = 'PC 내에 하나의 OS만 설치된 경우'
$criteria_bad = 'PC 내에 2개 이상의 OS가 설치된 경우'
$remediation = '하나의 OS만 설치하여 운영함'

Save-DualResult -ItemId $ITEM_ID `
    -ItemName $ITEM_NAME `
    -Status $status `
    -FinalResult $finalResult `
    -InspectionSummary $summary `
    -CommandResult $commandOutput `
    -CommandExecuted $commandExecuted `
    -GuidelinePurpose $purpose `
    -GuidelineThreat $threat `
    -GuidelineCriteriaGood $criteria_good `
    -GuidelineCriteriaBad $criteria_bad `
    -GuidelineRemediation $remediation `
    -ScriptDir $SCRIPT_DIR

Write-Host ""
Write-Host "진단 완료: $ITEM_ID ($finalResult)"

exit 0
