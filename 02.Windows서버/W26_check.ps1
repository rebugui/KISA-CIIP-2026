# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : W-26
# @Category    : Windows Server
# @Platform    : Windows Server
# @Severity    : 상
# @Title       : RDS(Remote Data Services)제거
# @Description : RDS(Remote Data Services) 서비스/기능 제거로 레거시 데이터 접속 취약점 방지
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\lib"
. "${LIB_DIR}\result_manager.ps1"

# Parameters
$ITEM_ID = "W-26"
$ITEM_NAME = "RDS(Remote Data Services)제거"
$SEVERITY = "상"
$CATEGORY = "2.서비스관리"

# run_all 모드가 아닐 때만 진단 정보 출력
if (-not (Test-RunallMode)) {
    Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"
    Write-Host "카테고리: $CATEGORY"
}

# 1. Run diagnostic
try {
    # Check OS version - Windows 2008+ automatically GOOD per criteria
    $osVersion = [System.Environment]::OSVersion.Version
    if ($osVersion.Major -ge 6) {
        $finalResult = "GOOD"
        $summary = "Windows 2008 이상 버전 사용 중 (RDS 취약점 해당 없음)"
        $status = "양호"
        $commandOutput = "OS Version: $($osVersion.ToString()) - Windows 2008+ 이상"
        $commandExecuted = "[System.Environment]::OSVersion.Version"
    }
    else {
        $rdsService = Get-Service -Name 'MSADC*' -ErrorAction SilentlyContinue
        $commandOutput = ""

        if ($rdsService) {
            $commandOutput = ($rdsService | Format-List -Property Name, Status, StartType | Out-String).Trim()
            $finalResult = "VULNERABLE"
            $summary = "RDS(Remote Data Services) 서비스가 설치되어 있어 보안 위험"
            $status = "취약"
        } else {
            $rdsFeature = Get-WindowsFeature -Name 'RDS-*' -ErrorAction SilentlyContinue | Where-Object { $_.Installed -eq $true }
            if ($rdsFeature) {
                $commandOutput = ($rdsFeature | Format-List -Property Name, DisplayName, Installed | Out-String).Trim()
                $finalResult = "VULNERABLE"
                $summary = "RDS(Remote Data Services) 기능이 설치되어 있어 보안 위험"
                $status = "취약"
            } else {
                $commandOutput = "RDS 서비스 및 기능이 설치되지 않음"
                $finalResult = "GOOD"
                $summary = "RDS(Remote Data Services) 서비스/기능이 설치되지 않음"
                $status = "양호"
            }
        }
    }
} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandOutput = $_.Exception.Message
}

$commandExecuted = "Get-Service -Name 'MSADC*'; Get-WindowsFeature -Name 'RDS-*'"

# 2. lib를 통한 결과 저장
$purpose = "취약한 RDS 서비스를 제거하여 불법적인 원격 공격을 차단하기 위함"
$threat = "취약한 플랫폼의 RDS가 사용되는 경우 서비스 거부 공격이나 원격에서 관리자 권한으로 임의의 명령을 실행할 수 있는 위험이 존재함"
$criteria_good = "다음 중 한 가지라도 해당하는 경우 1. IIS를 사용하지 않는 경우 2. Windows2008 이상 버전을 사용하는 경우 3. Windows 2000 서비스 팩 4, Windows2003 서비스 팩 2 이상 설치된 경우 4. 기본 웹 사이트에 MSADC 가상 디렉터리가 존재하지 않는 경우 5. 해당 레지스트리값이 존재하지 않는 경우"
$criteria_bad = "양호 기준에 한 가지도 해당하지 않는 경우"
$remediation = "사용하지 않는 경우 IIS 서비스 중지/ 사용 안 함, 사용할 경우 레지스트리 키 값 제거 또는 관련 패치 적용"

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
