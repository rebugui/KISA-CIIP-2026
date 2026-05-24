# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : W-62
# @Category    : Windows Server
# @Platform    : Windows Server
# @Severity    : 중
# @Title       : 시작 프로그램 목록 분석
# @Description : 시작 프로그램 목록 분석으로 악성 프로그램 실행 방지
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# Parameters
$ITEM_ID = "W-62"
$ITEM_NAME = "시작 프로그램 목록 분석"
$SEVERITY = "중"
$CATEGORY = "5.보안관리"

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\lib"
. "${LIB_DIR}\result_manager.ps1"

# run_all 모드가 아닐 때만 진단 정보 출력
if (-not (Test-RunallMode)) {
    Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"
    Write-Host "카테고리: $CATEGORY"
}

# 1. Check startup programs for unusual entries
try {
    $startupPaths = @(
        'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup',
        'C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
    )

    $hasUnusual = $false

    foreach ($path in $startupPaths) {
        if ($path -like 'HKLM:*' -or $path -like 'HKCU:*') {
            # Registry path
            try {
                $items = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
                if ($items) {
                    $props = Get-Item -Path $path -ErrorAction SilentlyContinue |
                             Select-Object -ExpandProperty Property -ErrorAction SilentlyContinue
                    if ($props) {
                        foreach ($prop in $props) {
                            if ($prop -notlike '*default*' -and
                                $prop -notlike '*Microsoft*' -and
                                $prop -notlike '*Windows*' -and
                                $prop -notlike '*Intel*' -and
                                $prop -notlike '*AMD*' -and
                                $prop -notlike '*NVIDIA*' -and
                                $prop -notlike '*VMware*') {
                                $hasUnusual = $true
                                break
                            }
                        }
                    }
                }
            } catch {
                # Ignore registry access errors
            }
        } else {
            # File system path
            if (Test-Path $path) {
                $items = Get-ChildItem $path -ErrorAction SilentlyContinue
                if ($items) {
                    foreach ($item in $items) {
                        if ($item.Name -notlike '*desktop.ini' -and $item.Name -notlike '*.lnk') {
                            $hasUnusual = $true
                            break
                        }
                    }
                }
            }
        }
    }

    if (-not $hasUnusual) {
        $finalResult = "GOOD"
        $summary = "시작 프로그램 목록에 불필요하거나 의심스러운 항목이 없음"
        $status = "양호"
    } else {
        $finalResult = "VULNERABLE"
        $summary = "시작 프로그램 목록에 불필요하거나 의심스러운 항목이 존재함"
        $status = "취약"
    }

    $commandExecuted = "Get-ItemProperty 및 Get-ChildItem (시작프로그램 경로 및 레지스트리 Run 키 확인)"
    $commandOutput = "불필요한 항목 존재: $hasUnusual"

} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandExecuted = "Get-ItemProperty 및 Get-ChildItem (시작프로그램 경로 및 레지스트리 Run 키 확인)"
    $commandOutput = "진단 실패: $_"
}

# 2. lib를 통한 결과 저장
$purpose = "불필요한 시작 프로그램을 삭제하거나 비활성화하여 악의적인 공격을 차단하기 위함"
$threat = "Windows 시작 시 너무 많은 시작 프로그램이 동시에 실행되면 속도가 저하되는 문제가 발생하며, 공격자가 심어 놓은 악성 프로그램이나 해킹 도구가 실행되어 시스템에 피해를 줄 위험이 존재함"
$criteria_good = "시작 프로그램 목록을 정기적으로 검사하고 불필요한 서비스를 비활성화한 경우"
$criteria_bad = "시작 프로그램 목록을 정기적으로 검사하지 않고, 부팅 시 불필요한 서비스도 실행되고 있는 경우"
$remediation = "시작 프로그램 목록의 정기적인 검사 실시 및 불필요한 서비스 비활성화 설정"

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
    -GuidelineRemediation $remediation

# run_all 모드가 아닐 때만 완료 메시지 출력
if (-not (Test-RunallMode)) {
    Write-Host ""
    Write-Host "진단 완료: $ITEM_ID ($finalResult)"
}

exit 0
