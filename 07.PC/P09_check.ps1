

# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : PC-09
# @Category    : PC (Personal Computer)
# @Platform    : Windows 10, 11
# @Severity    : 하
# @Title       : 브라우저 종료 시 임시 인터넷 파일 폴더의 내용을 삭제하도록 설정
# @Description : 브라우저 종료 시 임시 인터넷 파일 폴더의 내용을 삭제하여 캐시 정보 누출 방지
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\lib"
. "${LIB_DIR}\result_manager.ps1"

# Parameters
$ITEM_ID = "PC-09"
$ITEM_NAME = "브라우저 종료 시 임시 인터넷 파일 폴더의 내용을 삭제하도록 설정"
$SEVERITY = "하"
$CATEGORY = "2.서비스관리"

# run_all 모드가 아닐 때만 진단 정보 출력
if (-not (Test-RunallMode)) {
    Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"
    Write-Host "카테고리: $CATEGORY"
}

# 1. Check Internet Explorer temporary file deletion setting
# GP: 컴퓨터 구성 > 관리 템플릿 > Windows 구성 요소 > Internet Explorer > 인터넷 제어판 > 고급 페이지
# Reg: HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\5.0\Cache
# Policy: HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Cache

$commandExecuted = 'reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Cache; reg query HKLM\SOFTWARE\Policies\Microsoft\Edge'
$gpPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Cache'
$iePath = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\5.0\Cache'
$edgeGpPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'

$regOutput = ""
$isConfigured = $false
$isEnabled = $false

# Check Group Policy registry for IE
if (Test-Path $gpPath) {
    try {
        $gpQuery = reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Cache" 2>&1
        $regOutput += $gpQuery + "`r`n"
    } catch {
        $regOutput += "IE Group Policy query failed: $_`r`n"
    }
    $gpValue = Get-ItemProperty -Path $gpPath -ErrorAction SilentlyContinue
    if ($gpValue.PSObject.Properties.Name -contains 'Persistent') {
        $isConfigured = $true
        if ($gpValue.Persistent -eq 0) {
            $isEnabled = $true
        }
    }
} else {
    $regOutput += "IE Group Policy 경로 없음 (정상: GP 미사용 시 IE 설정 확인)`r`n"
}

# Check IE registry if not configured by GP
if (-not $isConfigured) {
    if (Test-Path $iePath) {
        try {
            $ieQuery = reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\5.0\Cache" /v Persistent 2>&1
            $regOutput += $ieQuery + "`r`n"
        } catch {
            $regOutput += "IE registry query failed: $_`r`n"
        }
        $ieValue = Get-ItemProperty -Path $iePath -ErrorAction SilentlyContinue
        if ($ieValue.PSObject.Properties.Name -contains 'Persistent') {
            if ($ieValue.Persistent -eq 0) {
                $isEnabled = $true
            }
        }
    } else {
        $regOutput += "IE 레지스트리 경로 없음 (정상: 기본값 사용으로 취약)`r`n"
    }
}

# Check Microsoft Edge Group Policy (ClearBrowsingDataOnExit)
$edgeEnabled = $false
$regOutput += "`r`n=== Edge Browser Check ===`r`n"
if (Test-Path $edgeGpPath) {
    try {
        $edgeGpQuery = reg query "HKLM\SOFTWARE\Policies\Microsoft\Edge" 2>&1
        $regOutput += $edgeGpQuery + "`r`n"
    } catch {
        $regOutput += "Edge Group Policy query failed: $_`r`n"
    }
    $edgeGpValue = Get-ItemProperty -Path $edgeGpPath -ErrorAction SilentlyContinue
    if ($edgeGpValue.PSObject.Properties.Name -contains 'ClearBrowsingDataOnExit') {
        if ($edgeGpValue.ClearBrowsingDataOnExit -eq 1) {
            $edgeEnabled = $true
            $regOutput += "Edge ClearBrowsingDataOnExit 활성화됨`r`n"
        }
    } else {
        $regOutput += "Edge ClearBrowsingDataOnExit 정책 미설정`r`n"
    }
} else {
    $regOutput += "Edge Group Policy 경로 없음 (Edge 미설치 또는 GP 미사용)`r`n"
}

# Final judgment (IE or Edge)
if ($isEnabled -or $edgeEnabled) {
    $finalResult = "GOOD"
    $browserList = @()
    if ($isEnabled) { $browserList += "IE" }
    if ($edgeEnabled) { $browserList += "Edge" }
    $summary = "브라우저 종료 시 임시 인터넷 파일 폴더 삭제 설정이 활성화됨 ($($browserList -join ', '))"
    $status = "양호"
} else {
    $finalResult = "VULNERABLE"
    $summary = "브라우저 종료 시 임시 인터넷 파일 폴더 삭제 설정이 비활성화됨 (기본값: 미삭제)"
    $status = "취약"
}

# 2. lib를 통한 결과 저장
$purpose = '브라우저 사용 시 생성되는 임시 인터넷 파일 삭제를 통하여 웹 양식에 입력한 정보(예: 이름 및 주소), 자동 로그인을 위한 웹 사이트 비밀번호 정보 등을 삭제하여 개인 정보의 보안을 향상하기 위함'
$threat = '임시 인터넷 파일 폴더 내용을 삭제하지 않을 경우, 다른 계정에 저장된 임시 인터넷 파일 폴더를 통해 이메일 주소, 웹 사이트 접근 기록 등의 개인 정보를 획득할 수 있는 위험이 존재함'
$criteria_good = '"브라우저를 닫을 때 임시 인터넷 파일 폴더 비우기''설정이''사용''으로 설정된 경우'
$criteria_bad = '"브라우저를 닫을 때 임시 인터넷 파일 폴더 비우기''설정이''미사용''으로 설정된 경우'
$remediation = '하나의 OS만 설치하여 운영함'

Save-DualResult -ItemId $ITEM_ID `
    -ItemName $ITEM_NAME `
    -Status $status `
    -FinalResult $finalResult `
    -InspectionSummary $summary `
    -CommandResult $regOutput `
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
