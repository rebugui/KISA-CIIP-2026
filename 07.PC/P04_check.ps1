

# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : PC-04
# @Category    : PC (Personal Computer)
# @Platform    : Windows 10, 11
# @Severity    : 상
# @Title       : 공유 폴더 제거
# @Description : 시스템의 공유폴더를 제거하여 외부 접근 경로 차단
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\lib"
. "${LIB_DIR}\result_manager.ps1"

# Parameters
$ITEM_ID = "PC-04"
$ITEM_NAME = "공유 폴더 제거"
$SEVERITY = "상"
$CATEGORY = "2.서비스관리"

# run_all 모드가 아닐 때만 진단 정보 출력
if (-not (Test-RunallMode)) {
    Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"
    Write-Host "카테고리: $CATEGORY"
}

# 1. Run diagnostic
$commandExecuted = 'net share; Get-SmbShareAccess'
$commandOutput = ""
try {
    $shareOutput = net share 2>&1 | Out-String
    $commandOutput = $shareOutput
    $lines = $shareOutput -split '`r`?`n'
    $basicShares = @('C$', 'ADMIN$', 'IPC$', 'print$')
    $unnecessaryShares = @()
    $everyoneAccessShares = @()

    foreach ($line in $lines) {
        if ([string]::IsNullOrWhiteSpace($line) -or $line -match '[가-힣]' -or $line -match '^-{10,}') {
            continue
        }
        if ($line -match '^([A-Za-z\$][A-Za-z0-9\$\-_]*)\s+') {
            $shareName = $matches[1]
            if ($shareName -notin $basicShares) {
                $unnecessaryShares += $shareName

                # Check Everyone access for this share
                try {
                    $accessCheck = Get-SmbShareAccess -Name $shareName -ErrorAction SilentlyContinue
                    foreach ($access in $accessCheck) {
                        if ($access.AccountName -eq 'Everyone' -or $access.AccountName -like '*S-1-1-0') {
                            if ($access.AccessControlType -eq 'Allow') {
                                $everyoneAccessShares += "$shareName ($($access.AccessRight))"
                            }
                        }
                    }
                } catch {
                    # PowerShell 5.1 compatibility: use net share with access check
                    $shareDetail = net share $shareName 2>&1 | Out-String
                    if ($shareDetail -match 'Everyone') {
                        $everyoneAccessShares += "$shareName (access suspected)"
                    }
                }
            }
        }
    }

    if ($unnecessaryShares.Count -eq 0) {
        $finalResult = "GOOD"
        $unnecessaryList = "(없음)"
        $summary = "불필요한 공유 폴더가 존재하지 않음 (기본 공유 C$, ADMIN$, IPC$, print$만 존재)"
        $status = "양호"
    } elseif ($everyoneAccessShares.Count -gt 0) {
        $finalResult = "VULNERABLE"
        $unnecessaryList = $unnecessaryShares -join ', '
        $everyoneList = $everyoneAccessShares -join ', '
        $summary = "불필요한 공유 폴더 존재 + Everyone 권한: $unnecessaryList`nEveryone 권한 있는 공유: $everyoneList"
        $status = "취약"
    } else {
        $finalResult = "VULNERABLE"
        $unnecessaryList = $unnecessaryShares -join ', '
        $summary = "불필요한 공유 폴더 존재: $unnecessaryList (Everyone 권한 없음)"
        $status = "취약"
    }
} catch {
    $finalResult = "MANUAL"
    $unnecessaryList = "진단 실패"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandOutput = "진단 실패: $_"
}

# 2. lib를 통한 결과 저장
$purpose = '사용하지 않는 불필요한 공유 폴더를 해제하거나 불가피하게 사용하고 있는 공유 폴더의 경우 비밀번호를 설정하는 등의 조치를 통해 인가된 사용자만 접근할 수 있게함으로써 무분별한 접근을 제한하기 위함'
$threat = '시스템 기본 공유 폴더의 경우 기본 드라이브를 개방해 놓고 사용하는 것과 같은 위험이 존재함(예시: 실행 창->\\192.168.16.xxx \C $로 C 드라이브 접근 가능) 접근 권한이 Everyone으로 설정된 공유 폴더는 정보 유출 및 악성 코드 유포의 접점이 될 수 있는 위험이 존재함'
$criteria_good = '불필요한 공유 폴더가 존재하지 않거나 공유 폴더에 접근 권한 및 비밀번호가 설정된 경우'
$criteria_bad = '불필요한 공유 폴더가 존재하거나 접근 권한 및 비밀번호 설정 없이 공유 폴더가 사용된 경우'
$remediation = '공유 폴더 불필요시 삭제 공유 폴더 필요하면 적절한 접근 권한 부여 및 비밀번호 설정 조치 후''AutoShareWks''값 변경으로 자동 공유 방지'

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
