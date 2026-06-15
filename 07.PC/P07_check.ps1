

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
    # 드라이브 문자 유무와 관계없이 모든 볼륨을 열거 (OEM 복구 파티션 등 문자 없는 FAT32 누락 방지)
    $allVolumes = Get-Volume -ErrorAction SilentlyContinue
    $nonNtfsVolumes = @()
    $excludedVolumes = @()
    $volumeDetails = @()

    foreach ($vol in $allVolumes) {
        $fs = $vol.FileSystem
        if ([string]::IsNullOrWhiteSpace($fs)) {
            # 파일시스템 미인식(RAW/미포맷/광학 미디어 등)은 데이터 볼륨 판정 불가 → 건너뜀
            continue
        }

        $letter = if ($vol.DriveLetter) { "$($vol.DriveLetter):" } else { "(문자없음)" }
        $dtype = $vol.DriveType
        $sizeMB = if ($vol.Size) { [math]::Round($vol.Size / 1MB, 0) } else { 0 }
        $volumeDetails += "$letter $fs [$dtype, ${sizeMB}MB]"

        if ($fs -eq "NTFS" -or $fs -eq "ReFS") {
            continue
        }

        # EFI System Partition은 사양상 FAT32여야 하며 사용자 데이터 볼륨이 아님 → 정당한 예외(제외)
        #  - 드라이브 문자가 없고, FAT/FAT32이며, 용량이 작은(<=600MB) 시스템 파티션을 EFI로 간주
        $isLetterless = -not $vol.DriveLetter
        $isFatFamily = ($fs -eq "FAT32" -or $fs -eq "FAT" -or $fs -eq "FAT16")
        $isEfiCandidate = $isLetterless -and $isFatFamily -and ($vol.Size -le 600MB)

        if ($isEfiCandidate) {
            $excludedVolumes += "$letter $fs (EFI 시스템 파티션 추정, 정당한 예외)"
            continue
        }

        # 그 외 NTFS/ReFS가 아닌 실제 데이터 볼륨(문자 유무 무관) → 취약
        $nonNtfsVolumes += "$letter ($fs)"
    }

    $commandOutput = ($volumeDetails -join "`n")
    if ($excludedVolumes.Count -gt 0) {
        $commandOutput += "`n[예외 처리됨]`n" + ($excludedVolumes -join "`n")
    }

    if ($nonNtfsVolumes.Count -eq 0) {
        $finalResult = "GOOD"
        $summary = "모든 데이터 볼륨이 NTFS(또는 ReFS) 포맷임 (확인 $($volumeDetails.Count)개"
        if ($excludedVolumes.Count -gt 0) {
            $summary += ", EFI 시스템 파티션 $($excludedVolumes.Count)개 예외"
        }
        $summary += ")"
        $status = "양호"
    } else {
        $finalResult = "VULNERABLE"
        $nonNtfsList = $nonNtfsVolumes -join ', '
        $summary = "NTFS가 아닌 데이터 볼륨 발견: $nonNtfsList"
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
