#Requires -Version 5.1

$ErrorActionPreference = 'Stop'
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\..\lib"
. "${LIB_DIR}\result_manager.ps1"
. "${SCRIPT_DIR}\oracle_windows_lib.ps1"

$ITEM_ID = "D-13"
$ITEM_NAME = "불필요한 ODBC/OLE-DB 데이터 소스와 드라이브를 제거하여 사용"
$SEVERITY = "중"

$purpose = "불필요한 데이터 소스 및 드라이버를 제거함으로써 비인가자에 의한 데이터베이스 접속 및 자료 유출을 차단하기 위함"
$threat = "불필요한 ODBC/OLE-DB 데이터 소스를 통한 비인가자의 데이터베이스 접속 및 주요 정보 유출에 대한 위험이 발생할 수 있음"
$criteria_good = "불필요한 ODBC/OLE-DB가 설치되지 않은 경우"
$criteria_bad = "불필요한 ODBC/OLE-DB가 설치된 경우"
$remediation = "불필요한 ODBC/OLE-DB 제거"

try {
    $diagnostic = Invoke-OracleWindowsCheck -ItemId $ITEM_ID -ItemName $ITEM_NAME
    $finalResult = $diagnostic.FinalResult
    $status = $diagnostic.Status
    $summary = $diagnostic.Summary
    $commandOutput = $diagnostic.CommandOutput
    $commandExecuted = $diagnostic.CommandExecuted
}
catch {
    $finalResult = "MANUAL"
    $status = "수동진단"
    $summary = "Diagnostic execution failed; manual review required."
    $commandOutput = "Diagnostic execution failed: $($_.Exception.Message)"
    $commandExecuted = "Invoke-OracleWindowsCheck"
}

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

exit 0
