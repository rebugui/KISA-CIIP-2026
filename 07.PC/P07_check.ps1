

# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : PC-07
# @Category    : PC (Personal Computer)
# @Platform    : Windows 10, 11
# @Severity    : 중
# @Title       : 파일 시스템이 NTFS 포맷으로 설정
# @Description : 파일 시스템이 NTFS 포맷으로 설정되어 있는지 확인하여 암호화 및 접근 제어 기능 보장
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\lib"
. "${LIB_DIR}\result_manager.ps1"

# Parameters
$ITEM_ID = "PC-07"
$ITEM_NAME = "파일 시스템이 NTFS 포맷으로 설정"
$SEVERITY = "중"
$CATEGORY = "2.서비스관리"

# run_all 모드가 아닐 때만 진단 정보 출력
if (-not (Test-RunallMode)) {
    Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"
    Write-Host "카테고리: $CATEGORY"
}

# 1. Run diagnostic
$commandExecuted = "Get-Volume"
$commandOutput = ""
try {
    $allVolumes = Get-Volume -ErrorAction SilentlyContinue
    $nonNtfsVolumes = @()
    $volumeDetails = @()

    foreach ($vol in $allVolumes) {
        if ($vol.DriveLetter) {
            $driveInfo = $vol.DriveLetter + ":\"
            $volObj = Get-Volume -DriveLetter $vol.DriveLetter -ErrorAction SilentlyContinue

            if ($volObj -and $volObj.FileSystem) {
                $fs = $volObj.FileSystem
                $volumeDetails += "$($vol.DriveLetter): $fs"

                if ($fs -ne "NTFS" -and $fs -ne "ReFS") {
                    $nonNtfsVolumes += "$($vol.DriveLetter): ($fs)"
                }
            }
        }
    }

    $commandOutput = $volumeDetails -join "`n"

    if ($nonNtfsVolumes.Count -eq 0) {
        $finalResult = "GOOD"
        $summary = "모든 볼륨이 NTFS(또는 ReFS) 포맷임 (총 $($volumeDetails.Count)개 볼륨 확인)"
        $status = "양호"
    } else {
        $finalResult = "VULNERABLE"
        $nonNtfsList = $nonNtfsVolumes -join ', '
        $summary = "NTFS가 아닌 볼륨 발견: $nonNtfsList"
        $status = "취약"
    }
} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandOutput = "진단 실패: $_"
}

# 2. lib를 통한 결과 저장
$purpose = '보안 성 기능이 없는 FAT32를 지양하고 사용 권한 및 암호화를 통해 특정 파일에 대한 특정 사용자의 액세스를 제한할 수 있는 NTFS를 사용하여 보안성을 강화하기 위함'
$threat = 'FAT32 파일 시스템을 사용하는 경우, 사용자의 컴퓨터에 액세스하는 사람은 누구나 컴퓨터 안에 있는 파일을 읽을 수 있으므로, 중요 파일에 접근할 수 없는 비인가자가 주요 정보를 유출할 수 있는 위험이 존재함'
$criteria_good = '모든 디스크 볼륨의 파일 시스템이 NTFS인 경우'
$criteria_bad = '모든 디스크 볼륨의 파일 시스템이 FAT32인 경우'
$remediation = '모든 디스크 볼륨에 대해 파일 시스템 NTFS로 변경'

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
