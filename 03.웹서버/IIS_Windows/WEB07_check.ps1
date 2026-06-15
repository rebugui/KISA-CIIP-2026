# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : WEB-07
# @Category    : Web Server
# @Platform    : IIS_Windows
# @Severity    : 중
# @Title       : 웹 서비스 경로 내 불필요한 파일 제거
# @Description : 웹 디렉터리에서 백업 파일(.bak), 샘플 파일, 테스트 파일 등 불필요한 파일을 제거하여 정보 노출 및 공격 면적을 감소시킵니다. 이러한 파일들은 소스 코드 유출, 시스템 정보 노출, 공격자의 공격 경로 제공 등의 보안 위협이 될 수 있습니다.
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

$ErrorActionPreference = 'Stop'

# lib 로드
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\..\lib"
. "${LIB_DIR}\result_manager.ps1"

$ITEM_ID = "WEB-07"
$ITEM_NAME = "웹 서비스 경로 내 불필요한 파일 제거"
$SEVERITY = "중"

Write-Host "진단 항목: $ITEM_ID - $ITEM_NAME"

try {
    # IIS 불필요한 파일 확인 (sample, backup, test 파일 등)
    # Tier A: 확장자로 명확히 식별되는 백업/임시 파일 (기본 생성 불필요 파일과 1:1 대응) -> 취약
    $definiteFiles = @()
    # Tier B: 정상 업무/애플리케이션 콘텐츠와 충돌할 수 있는 모호한 패턴
    #         (예: robots.txt, license.txt, test.aspx, example.js) -> 수동진단
    #         기본 설치 산출물(샘플/매뉴얼/테스트)인지 분석가 확인 필요
    $ambiguousFiles = @()
    $sites = Get-Website

    foreach ($site in $sites) {
        $path = $site.PhysicalPath
        if (Test-Path $path) {
            # Tier A 패턴: 확장자로 명확한 백업/임시 파일
            $definitePatterns = @(
                "*.bak",
                "*.backup",
                "*.old",
                "*.orig",
                "*.save",
                "*.swp",
                "*.tmp",
                "*.temp",
                "*.dump"
            )
            # Tier B 패턴: 이름/확장자만으로 출처(설치 기본 vs 애플리케이션)를 정적으로 판별할 수 없는 파일
            $ambiguousPatterns = @(
                "*~",
                "test.*",
                "sample.*",
                "example.*",
                "*sample*",
                "*example*",
                "*readme*",
                "*.txt"
            )

            foreach ($pattern in $definitePatterns) {
                $files = Get-ChildItem -Path $path -Filter $pattern -Recurse -ErrorAction SilentlyContinue
                foreach ($file in $files) {
                    if ($file.Name -ne "web.config") {
                        $definiteFiles += "$($file.Name) in $path"
                    }
                }
            }

            foreach ($pattern in $ambiguousPatterns) {
                $files = Get-ChildItem -Path $path -Filter $pattern -Recurse -ErrorAction SilentlyContinue
                foreach ($file in $files) {
                    # IIS 구성 파일 제외
                    if ($file.Name -ne "web.config") {
                        $ambiguousFiles += "$($file.Name) in $path"
                    }
                }
            }
        }
    }

    $commandExecuted = "Get-ChildItem -Path {webroot} -Filter {[definite] *.bak,*.backup,*.old,*.orig,*.tmp; [ambiguous] *.txt,test.*,sample.*} -Recurse"

    if ($definiteFiles.Count -gt 0) {
        # Tier A — 확장자로 명확한 백업/임시 파일 존재 -> 취약
        $finalResult = "VULNERABLE"
        $summary = "불필요한 백업/임시 파일이 $($definiteFiles.Count)개 발견되었습니다: " + ($definiteFiles[0] + " 등")
        $status = "취약"
        $commandOutput = $definiteFiles -join "`n"
        if ($ambiguousFiles.Count -gt 0) {
            $commandOutput += "`n[수동 확인 필요 - 출처 확인]`n" + ($ambiguousFiles -join "`n")
        }
    } elseif ($ambiguousFiles.Count -gt 0) {
        # Tier B — 정상 업무/애플리케이션 콘텐츠와 충돌 가능한 모호한 매칭 -> 수동진단
        $finalResult = "MANUAL"
        $summary = "이름/확장자가 sample/example/test/readme 또는 .txt 인 파일이 $($ambiguousFiles.Count)개 발견되었습니다(예: robots.txt). 정상 애플리케이션 파일과 겹칠 수 있으므로, 해당 파일이 웹 서버 기본 설치 시 생성된 불필요한 샘플/매뉴얼/테스트 파일인지 직접 확인하여 양호/취약을 판정하세요."
        $status = "수동진단"
        $commandOutput = $ambiguousFiles -join "`n"
    } else {
        $finalResult = "GOOD"
        $summary = "웹 디렉터리에서 불필요한 파일(백업, 샘플, 테스트 파일 등)이 발견되지 않았습니다. (보안 권고사항 준수)"
        $status = "양호"
        $commandOutput = "No unnecessary files found"
    }

} catch {
    $finalResult = "MANUAL"
    $summary = "진단 실패: 수동 확인 필요"
    $status = "수동진단"
    $commandExecuted = "Get-ChildItem -Path {webroot} -Filter {*.bak,*.backup,*.old,*.tmp, test.*} -Recurse"
    $commandOutput = "진단 실패: $_"
}

# 2. lib를 통한 결과 저장
$purpose = '웹 서비스 설치 시 기본으로 생성되는 샘플, 매뉴얼 파일 등 서비스에 불필요한 파일을 제거하여 불필요한 공격 대상으로 이용되는 것을 방지하기 위함'
$threat = '웹 서비스 설치 시 기본으로 생성되는 파일 및 디렉터리나 백 업, 테스트 파일 등을 제거하지 않은 경우, 비인가자에게 시스템 관련 정보 및 웹 서버 정보가 노출되거나 해킹에 악용될 수 있음'
$criteria_good = '기본으로 생성되는 불필요한 파일 및 디렉터리가 존재하지 않을 경우'
$criteria_bad = '기본으로 생성되는 불필요한 파일 및 디렉터리가 존재하는 경우'
$remediation = '불필요한 파일 및 디렉터리를 제거하도록 설정'

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
