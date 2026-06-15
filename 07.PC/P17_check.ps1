

# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : PC-17
# @Category    : PC (Personal Computer)
# @Platform    : Windows 10, 11
# @Severity    : 중
# @Title       : 이동식미디어자동실행방지
# @Description : 이동식 미디어 자동 실행 기능을 비활성화하여 악성코드 실행 방지
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\lib"
. "${LIB_DIR}\result_manager.ps1"

# Parameters
$ITEM_ID = "PC-17"
$ITEM_NAME = "이동식미디어자동실행방지"
$SEVERITY = ""
$CATEGORY = "4.보안관리"

# run_all 모드가 아닐 때만 진단 정보 출력
if (-not (Test-RunallMode)) {
    Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"
    Write-Host "카테고리: $CATEGORY"
}

# 1. Check autorun settings for removable media
try {
    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    $regName = "NoDriveTypeAutoRun"

    $value = Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue

    if ($value -ne $null) {
        $hexValue = [int]$value.NoDriveTypeAutoRun
        $hexString = "0x$($hexValue.ToString('X2')) ($hexValue)"
        $commandOutput = "$regName : $hexString"

        # NoDriveTypeAutoRun is a bitmask: a SET bit disables autorun for that drive type.
        # bit 0x04 = DRIVE_REMOVABLE (USB), bit 0x20 = DRIVE_CDROM.
        # This item targets removable-media autorun, so GOOD = removable bit (0x04) set
        # (e.g. 0xFF, 0xDD, 0xB5 — all disable removable autorun). Bit 0x04 clear = VULNERABLE.
        if (($hexValue -band 0x04) -ne 0) {
            $finalResult = "GOOD"
            $summary = "이동식 미디어 자동실행 금지됨 ($hexString)"
            $status = "양호"
        } else {
            $finalResult = "VULNERABLE"
            $summary = "이동식 미디어 자동실행 허용됨 ($hexString, 권장: 이동식 미디어 비트(0x04) 설정)"
            $status = "취약"
        }
    } else {
        $finalResult = "VULNERABLE"
        $summary = "NoDriveTypeAutoRun 레지스트리 값 없음 (자동실행 허용 상태)"
        $status = "취약"
        $commandOutput = "$regName : Not set (default: autorun enabled)"
    }

    $commandExecuted = "reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer /v NoDriveTypeAutoRun"

} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandOutput = "진단 실패: $_"
    $commandExecuted = "reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
}

# 2. Define guideline variables
$purpose = 'CD/DVD,USB 메모리 등과 같은 이동식 미디어를 USBport에 연결 시 자동 실행을 차단하기 위함'
$threat = 'CD/DVD, USB 메모리 등과 같은 이동식 미디어가 자동 실행되는 경우 미디어에 탑재된''Autorun.i nf''파일을 통해 다른 응용 프로그램이 자동 실행될 수 있는 위험이 존재함 이동식 미디어가 사용될 때 읽기 기능을 통해 바이러스 감염이 생길 수 있고, 쓰기 기능을 통하여 주요 정보 유출이 발생할 수 있음'
$criteria_good = '미디어 사용 시 자동 실행되지 않고 내부적으로 관리 절차를 수립하여 이행된 경우'
$criteria_bad = '미디어 사용 시 자동 실행되거나 내부적으로 관리 절차가 수립되지 않은 경우'
$remediation = '미디어 자동 실행 방지 설정'

# 3. Save results using Save-DualResult
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

Write-Host "진단 완료: $ITEM_ID ($finalResult)"

exit 0
