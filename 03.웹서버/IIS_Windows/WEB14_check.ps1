# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : WEB-14
# @Category    : Web Server
# @Platform    : IIS (Windows Server)
# @Severity    : 하
# @Title       : 웹서비스경로내파일의접근통제
# @Description : 웹서비스 경로 내 백업 파일(.bak), 설정 파일(.config), 소스 코드 등 민감한 파일에 대한 웹 접근을 차단하여 정보 노출을 방지합니다. IIS Request Filtering을 사용하여 파일 확장자별 접근 제어가 필요합니다.
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\..\lib"
. "${LIB_DIR}\result_manager.ps1"

$ITEM_ID = "WEB-14"
$ITEM_NAME = "웹 서비스 경로 내 파일의 접근 통제"
$SEVERITY = "상"

Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"

try {
    # IIS 웹서비스 경로 내 불필요한 파일 확인
    $sites = Get-Website
    $sensitiveFiles = @()
    $fileFound = $false

    $sensitivePatterns = @(
        "*.bak",
        "*.old",
        "*.tmp",
        "*.log",
        "*.sql",
        "*.mdb",
        "*.db",
        "*.ini",
        "*.conf",
        "*.config",
        ".git",
        ".svn",
        "*.ps1",
        "*.bat",
        "*.cmd"
    )

    foreach ($site in $sites) {
        $path = $site.PhysicalPath
        if (Test-Path $path) {
            foreach ($pattern in $sensitivePatterns) {
                $files = Get-ChildItem -Path $path -Filter $pattern -Recurse -ErrorAction SilentlyContinue
                foreach ($file in $files) {
                    if ($file.FullName -notlike "*\logs\*") {
                        $fileFound = $true
                        $relativePath = $file.FullName.Substring($path.Length)
                        $sensitiveFiles += "Site: $($site.Name), File: $relativePath"
                    }
                }
            }
        }
    }

    $commandExecuted = "Get-Website; Get-ChildItem -Path [SitePath] -Filter *.bak,*.old,*.tmp,*.log,*.sql,*.mdb,*.db,*.ini,*.conf,*.config,.git,.svn,*.ps1,*.bat,*.cmd -Recurse"

    if ($fileFound) {
        $finalResult = "VULNERABLE"
        $summary = "웹서비스 경로 내에 접근이 제한되어야 할 민감한 파일이 발견되었습니다: " + ($sensitiveFiles[0] + " 외 " + ($sensitiveFiles.Count - 1) + "개")
        $status = "취약"
        $commandOutput = $sensitiveFiles -join "`n"
    } else {
        $finalResult = "GOOD"
        $summary = "웹서비스 경로 내에 노출되면 안되는 민감한 파일이 없습니다. (보안 권고사항 준수)"
        $status = "양호"
        $commandOutput = "Sensitive files: Not found in web paths"
    }

} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandExecuted = "Get-Website; Get-ChildItem -Path [SitePath] -Recurse"
    $commandOutput = "진단 실패: $_"
}

# 가이드라인 변수
$purpose = '웹 서비스 경로의 파일들에 관리자를 제외한 일반 사용자의 파일 접근 권한을 제거함으로써 인가되지 않은 사용자가 허용되지 않는 파일에 접근하는 것을 차단하기 위함'
$threat = '웹 서비스 경로 파일에 비인가자가 접근 가능한 경우, 해당 파일의 수정 및 삭제로 인해 웹 서비스 운영 장애 및 계정 비밀번호 정보 등의 중요한 정보가 노출될 위험이 존재함'
$criteria_good = '주요 설정 파일 및 디렉터리에 불필요한 접근 권한이 부여되지 않은 경우'
$criteria_bad = '주요 설정 파일 및 디렉터리에 불필요한 접근 권한이 부여된 경우'
$remediation = '주요 설정 파일 및 디렉터리에 불필요한 접근 권한 제거 설정'

# 결과 저장
Save-DualResult -ItemId "${ITEM_ID}" `
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

exit 0
