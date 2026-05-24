# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : WEB-02
# @Category    : Web Server
# @Platform    : IIS_Windows
# @Severity    : 상
# @Title       : 취약한 비밀번호 사용 제한
# @Description : 관리자 계정의 취약한 비밀번호 설정 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================



$ErrorActionPreference = 'Stop'

# ============================================================================
# 라이브러리 로드
# ============================================================================
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\..\lib"
. "${LIB_DIR}\result_manager.ps1"

# ============================================================================
# 메타데이터
# ============================================================================
$ITEM_ID = "WEB-02"
$ITEM_NAME = "취약한 비밀번호 사용 제한"
$SEVERITY = "상"

# 가이드라인 정보
$GUIDELINE_PURPOSE = "관리자 계정의 비밀번호가 복잡 도 기준에 맞게 적용되어 있는지 점검하여, 비인가자에 의한 비밀번호 유추 공격 및 관리자 권한 탈취 등을 방지하기 위함"
$GUIDELINE_THREAT = "관리자 계정의 비밀번호를 취약하게 설정하여 사용하는 경우, 비인가자의 비밀번호 유추 공격으로 관리자 권한 탈취 및 시스템 침입 등의 위험이 존재함"
$GUIDELINE_CRITERIA_GOOD = "관리자 비밀번호가 암호화되어 있거나, 유추하기 어려운 비밀번호로 설정된 경우"
$GUIDELINE_CRITERIA_BAD = "관리자 비밀번호가 암호화되어 있지 않거나, 유추하기 쉬운 비밀번호로 설정된 경우"
$GUIDELINE_REMEDIATION = "복잡 도 기준에 맞는 추측하기 어려운 비밀번호 설정"

Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"

try {
    # IIS 웹서버 관리자 계정 확인
    # 1. IIS Manager 사용자 (IIS Manager Users)
    # 2. FTP 관리자 계정 (FTP Administrators)
    # 3. Application Pool Identity 계정

    $commandOutput = ""
    $commandExecuted = ""
    $hasVulnerablePassword = $false

    # 1. Windows 계정 정책 확인 (IIS는 Windows 계정 사용)
    try {
        $passwordPolicy = net accounts | Select-String -Pattern "Password"
        if ($passwordPolicy) {
            $commandOutput += "=== Windows Password Policy ===`r`n"
            $commandOutput += $passwordPolicy | Out-String
            $commandOutput += "`r`n"

            # 비밀번호 복잡도 정책 확인
            $complexityEnabled = $passwordPolicy | Select-String -Pattern "Complexity"
            if ($complexityEnabled -and $complexityEnabled.ToString() -match "Yes") {
                $commandOutput += "[양호] 비밀번호 복잡도 요구사항이 활성화되어 있습니다.`r`n"
            } else {
                $commandOutput += "[취약] 비밀번호 복잡도 요구사항이 비활성화되어 있습니다.`r`n"
                $hasVulnerablePassword = $true
            }

            # 비밀번호 최소 길이 확인
            $minLength = $passwordPolicy | Select-String -Pattern "Minimum password length"
            if ($minLength -and $minLength.ToString() -match "(\d+)") {
                $length = [int]$matches[1]
                if ($length -ge 8) {
                    $commandOutput += "[양호] 최소 비밀번호 길이: ${length}자`r`n"
                } else {
                    $commandOutput += "[취약] 최소 비밀번호 길이가 8자 미만입니다: ${length}자`r`n"
                    $hasVulnerablePassword = $true
                }
            }
        }
        $commandExecuted += "net accounts; "
    } catch {
        $commandOutput += "[WARN] Windows 계정 정책 확인 실패: $_`r`n"
    }

    # 2. IIS Application Pool Identity 계정 확인
    try {
        import-module WebAdministration -ErrorAction SilentlyContinue
        $appPools = Get-ChildItem IIS:\AppPools -ErrorAction SilentlyContinue
        if ($appPools) {
            $commandOutput += "`r`n=== IIS Application Pool Identities ===`r`n"
            foreach ($pool in $appPools) {
                $identity = $pool.processModel.identityType
                $username = $pool.processModel.userName
                $commandOutput += "Pool: $($pool.Name), Identity: $identity"
                if ($username -and $username -ne "") {
                    $commandOutput += ", User: $username"
                }
                $commandOutput += "`r`n"

                # ApplicationPoolIdentity 또는 LocalSystem, NetworkService 등 사용 확인
                if ($identity -eq "ApplicationPoolIdentity" -or $identity -eq "LocalSystem" -or $identity -eq "NetworkService") {
                    # 기본 identity 사용은 양호 (별도 비밀번호 없음)
                } elseif ($username -and $username -ne "") {
                    # 사용자 지정 계정 사용 시 Windows 계정 정책 따름
                    $commandOutput += "  [INFO] 사용자 지정 계정 사용: Windows 계정 정책 적용`r`n"
                }
            }
        }
        $commandExecuted += "Get-ChildItem IIS:\AppPools; "
    } catch {
        $commandOutput += "`r`n[WARN] IIS Application Pool 확인 실패: $_`r`n"
    }

    # 3. IIS Manager 사용자 확인 (IIS 7.0+)
    try {
        $iisManagerUsers = Get-WebConfiguration -Filter "/system.ftpServer/security/authorization" -PSPath "MACHINE/WEBROOT/APPHOST" -ErrorAction SilentlyContinue
        # IIS Manager Users는 레지스트리 또는 Administration.config 파일에 저장
        $adminConfig = "$env:WINDIR\System32\inetsrv\config\administration.config"
        if (Test-Path $adminConfig) {
            $commandOutput += "`r`n=== IIS Manager Users Configuration ===`r`n"
            $adminConfigContent = Get-Content $adminConfig | Select-String -Pattern "credentials" -Context 0,10
            if ($adminConfigContent) {
                $commandOutput += $adminConfigContent | Out-String
                $commandOutput += "  [INFO] IIS Manager 사용자는 administration.config 파일에 암호화되어 저장됩니다.`r`n"
            } else {
                $commandOutput += "  [양호] IIS Manager 사용자가 구성되지 않았습니다.`r`n"
            }
        }
        $commandExecuted += "Get-Content $env:WINDIR\System32\inetsrv\config\administration.config; "
    } catch {
        $commandOutput += "`r`n[WARN] IIS Manager 사용자 확인 실패: $_`r`n"
    }

    # 최종 판정
    if ($hasVulnerablePassword) {
        $finalResult = "VULNERABLE"
        $summary = "Windows 비밀번호 정책이 취약합니다. 비밀번호 복잡도 요구사항을 활성화하고 최소 길이를 8자 이상으로 설정하세요."
        $status = "취약"
    } else {
        $finalResult = "GOOD"
        $summary = "Windows 비밀번호 정책이 적절하게 설정되어 있습니다. IIS는 Windows 계정 정책을 따릅니다."
        $status = "양호"
    }

    $commandExecuted = $commandExecuted.TrimEnd('; ')

} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: IIS 비밀번호 정책 확인 중 오류 발생. 수동으로 확인하세요: 1) Windows 계정 정책 (net accounts) 2) IIS Manager 사용자 3) Application Pool Identity"
    $status = "수동진단"
    $commandExecuted = "N/A"
    $commandOutput = "진단 실패: $_"
}

# ============================================================================
# 결과 저장
# ============================================================================
Save-DualResult -ItemId $ITEM_ID `
    -ItemName $ITEM_NAME `
    -Status $status `
    -FinalResult $finalResult `
    -InspectionSummary $summary `
    -CommandResult $commandOutput `
    -CommandExecuted $commandExecuted `
    -GuidelinePurpose $GUIDELINE_PURPOSE `
    -GuidelineThreat $GUIDELINE_THREAT `
    -GuidelineCriteriaGood $GUIDELINE_CRITERIA_GOOD `
    -GuidelineCriteriaBad $GUIDELINE_CRITERIA_BAD `
    -GuidelineRemediation $GUIDELINE_REMEDIATION `
    -Severity $SEVERITY

Write-Host ""
Write-Host "진단 완료: $status"
Write-Host "판정: $finalResult"
Write-Host "설명: $summary"
Write-Host ""
