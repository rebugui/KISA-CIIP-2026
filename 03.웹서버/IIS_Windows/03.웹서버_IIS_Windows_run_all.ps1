# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-01-17
# ============================================================================
# [점검 항목 상세]
# @ID          : All
# @Category    : Web Server (웹 서버)
# @Platform    : Microsoft IIS
# @Severity    : 중
# @Title       : 모든 웹서버 점검 스크립트 실행
# @Description : 웹서버 모든 점검 항목을 실행하는 스크립트 (PowerShell 형식)
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

Write-Host ""
Write-Host "==============================================================================" -ForegroundColor Cyan
Write-Host "KISA-CIIP-2026 Vulnerability Assessment Scripts" -ForegroundColor Cyan
Write-Host "Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved." -ForegroundColor Cyan
Write-Host "Version: 1.0.0" -ForegroundColor Cyan
Write-Host "Last Updated: 2026-01-17" -ForegroundColor Cyan
Write-Host "==============================================================================" -ForegroundColor Cyan
Write-Host ""

$ErrorActionPreference = 'Continue'

# 스크립트 디렉토리 설정
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\..\lib"

# 필수 라이브러리 로드
. "$LIB_DIR\result_manager.ps1"

# ============================================================================
# 전체 진단 설정
# ============================================================================
$CATEGORY = "웹서버"
$PLATFORM = "IIS_Windows"
$TOTAL_ITEMS = 26  # WEB-01~WEB-26

# 결과 저장 배열
$RESULTS_JSON = @()
$FAILED_ITEMS = @()
$PASSED_ITEMS = @()

# 진단 항목 목록 (WEB-01~WEB-26)
$DIAGNOSIS_ITEMS = 1..26 | ForEach-Object { "WEB-{0:D2}" -f $_ }

# ============================================================================
# 진단 실행 함수 (PowerShell run_all 패턴)
# ============================================================================

# 단일 항목 진단 실행
function Run-SingleCheck {
    param(
        [string]$ItemId
    )

    $current = $DIAGNOSIS_ITEMS.IndexOf($ItemId) + 1
    $scriptName = $ItemId -replace '-', ''
    $scriptFile = Join-Path $SCRIPT_DIR "$scriptName`_check.ps1"
    $tmpOutput = [System.IO.Path]::GetTempFileName()

    # 스크립트 파일 존재 확인
    if (-not (Test-Path $scriptFile)) {
        Write-Host "[WARN] 스크립트 파일 없음: $scriptFile" -ForegroundColor Yellow
        $FAILED_ITEMS += $ItemId
        Remove-Item $tmpOutput -Force -ErrorAction SilentlyContinue
        return $false
    }

    # 진단 스크립트 실행 (출력 캡처)
    $startTime = Get-Date
    $exitCode = 0

    try {
        # run_all 모드 설정 후 스크립트 실행
        # stdout만 캡처 (stderr는 별도로 처리하여 JSON 추출 방해 방지)
        $env:WS_RUNALL_MODE = "1"
        $output = & $scriptFile 2>&1 | Out-String
        $output | Out-File -FilePath $tmpOutput -Encoding UTF8
        $exitCode = $LASTEXITCODE
        Remove-Item env:WS_RUNALL_MODE -ErrorAction SilentlyContinue
    }
    catch {
        $exitCode = 1
    }

    $endTime = Get-Date
    $duration = ($endTime - $startTime).TotalSeconds

    # 결과 JSON 파싱 (stdout 캡처에서 추출)
    $jsonOutput = ""
    $finalResult = ""
    $summary = ""
    $itemName = ""

    # tmp_output에서 JSON 추출 (개선된 로직)
    $outputLines = Get-Content $tmpOutput -Encoding UTF8

    # JSON 시작 찾기 ('{'로 시작하는 라인)
    $jsonStartIndex = -1
    $braceCount = 0

    for ($i = 0; $i -lt $outputLines.Count; $i++) {
        $line = $outputLines[$i].Trim()

        # JSON 객체 시작 감지
        if ($line -match '^\{') {
            $jsonStartIndex = $i
            $braceCount = 1

            # JSON 끝 찾기 (중괄호 균형)
            for ($j = $i + 1; $j -lt $outputLines.Count; $j++) {
                $openBraces = ([regex]::Matches($outputLines[$j], '\{').Count)
                $closeBraces = ([regex]::Matches($outputLines[$j], '\}').Count)
                $braceCount += $openBraces - $closeBraces

                if ($braceCount -eq 0) {
                    # JSON 객체 완성 - 추출 및 파싱 시도
                    $candidateJson = $outputLines[$i..$j] -join "`n"

                    try {
                        $jsonObj = $candidateJson | ConvertFrom-Json

                        # 필수 필드 확인
                        if ($jsonObj.item_id -and $jsonObj.final_result) {
                            $jsonOutput = $candidateJson
                            $itemName = $jsonObj.item_name
                            $finalResult = $jsonObj.final_result

                            # inspection.summary 추출
                            if ($jsonObj.inspection) {
                                $summary = $jsonObj.inspection.summary
                            }
                            if (-not $summary) {
                                $summary = "진단 실패"
                            }

                            $script:RESULTS_JSON += $jsonOutput
                            break
                        }
                    }
                    catch {
                        # 파싱 실패시 다음 후보 계속 검색
                    }

                    # 다음 후보 찾기 위해 재시작
                    $i = $j
                    $jsonStartIndex = -1
                    break
                }
            }

            # 유효한 JSON을 찾으면 종료
            if ($jsonOutput) {
                break
            }
        }
    }

    if (-not $jsonOutput) {
        Write-Warning "JSON 추출 실패: ${ItemId}"
    }

    # 결과 확인
    if ($exitCode -eq 0) {
        $PASSED_ITEMS += $ItemId
    }
    else {
        $FAILED_ITEMS += $ItemId
    }

    # PC 형식으로 CLI 출력 (간단한 요약만)
    Write-Host "===================================================================" -ForegroundColor Cyan
    Write-Host "진단 항목: ${ItemId} (${current}/${TOTAL_ITEMS})" -ForegroundColor Cyan
    Write-Host "===================================================================" -ForegroundColor Cyan
    Write-Host "진단 항목: ${ItemId} - ${itemName}"
    Write-Host "${summary}"
    Write-Host "  > 진단 완료: ${finalResult}"
    Write-Host ""

    # 텍스트 파일에 결과 append
    if ($jsonOutput -and $Script:TXT_FILE) {
        Append-RunallTextResult -JsonObj $jsonOutput -TxtFile $Script:TXT_FILE
    }

    # 임시 파일 삭제
    Remove-Item $tmpOutput -Force -ErrorAction SilentlyContinue

    return $exitCode -eq 0
}

# ============================================================================
# 메인 실행
# ============================================================================

Write-Host "===================================================================" -ForegroundColor Cyan
Write-Host "KISA 취약점 진단 시스템 - 전체 항목 일괄 진단" -ForegroundColor Cyan
Write-Host "===================================================================" -ForegroundColor Cyan
Write-Host "카테고리: ${CATEGORY}"
Write-Host "플랫폼: ${PLATFORM}"
Write-Host "진단 항목: $($DIAGNOSIS_ITEMS -join ' ')"
Write-Host "===================================================================" -ForegroundColor Cyan
Write-Host ""

# 디스크 공간 확인 (함수가 있다면 호출)
if (Get-Command Check-DiskSpace -ErrorAction SilentlyContinue) {
    Check-DiskSpace
}

# 텍스트 파일 초기화 (result_manager.ps1 함수 사용)
$Script:TXT_FILE = Initialize-RunallTextFile -Category $CATEGORY -Platform $PLATFORM -ScriptDir $SCRIPT_DIR

# 진단 시작 시간
$startTime = Get-Date

# 각 항목 진단 실행
$current = 0
foreach ($itemId in $DIAGNOSIS_ITEMS) {
    $current++

    if (-not (Run-SingleCheck -ItemId $itemId)) {
        Write-Host "[WARN] ${itemId} 진단 실패" -ForegroundColor Yellow
    }
}

# 진단 종료 시간
$endTime = Get-Date
$totalDuration = ($endTime - $startTime).TotalSeconds

Write-Host ""
Write-Host "===================================================================" -ForegroundColor Magenta
Write-Host "전체 진단 완료" -ForegroundColor Magenta
Write-Host "===================================================================" -ForegroundColor Magenta
Write-Host "총 소요 시간: $([int]$totalDuration)초 ($([int]($totalDuration / 60))분)"
Write-Host "진단 항목: ${TOTAL_ITEMS}개"
Write-Host "===================================================================" -ForegroundColor Magenta
Write-Host ""

# 통합 결과 파일 생성 (result_manager.ps1 함수 사용)
New-RunallAggregatedResults `
    -Category $CATEGORY `
    -Platform $PLATFORM `
    -ScriptDir $SCRIPT_DIR `
    -TotalItems $TOTAL_ITEMS `
    -ResultsJson $RESULTS_JSON

Write-Host ""
Write-Host "[완료] 전체 진단 완료" -ForegroundColor Green
Write-Host ""
