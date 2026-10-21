<#
.SYNOPSIS
    Merges multiple Tenable Nessus (.nessus) scan files into a single consolidated report.

.DESCRIPTION
    NessusMerge.ps1 is a simple, single-file PowerShell utility that discovers all .nessus
    files in a specified folder, loads the first report as the base, and appends the
    ReportHost elements from all remaining reports into one unified .nessus report.
    It uses safe .NET XML parsing (disabling DTD processing and external entity resolution).

.PARAMETER FilePath
    The directory containing .nessus scan files. Defaults to the current working directory.

.PARAMETER OutputFileName
    The file name or path for the merged output file. Defaults to 'merged_nessus_report.nessus'.

.PARAMETER ReportName
    The name assigned to the consolidated <Report> node. Defaults to 'Merged Report'.

.EXAMPLE
    .\NessusMerge.ps1

.EXAMPLE
    .\NessusMerge.ps1 -FilePath "D:\NessusScans"

.EXAMPLE
    .\NessusMerge.ps1 `
      -FilePath "D:\NessusScans" `
      -OutputFileName "FinalReport.nessus" `
      -ReportName "Consolidated Security Report"
#>

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [Alias("InputPath", "Path")]
    [string]$FilePath = (Get-Location).Path,

    [Parameter(Position = 1)]
    [Alias("OutputFile")]
    [string]$OutputFileName = "merged_nessus_report.nessus",

    [Parameter(Position = 2)]
    [string]$ReportName = "Merged Report"
)

# Function to safely load XML files with DTD and external entity resolution disabled
function Load-SafeXmlDocument {
    param([string]$Path)

    $settings = New-Object System.Xml.XmlReaderSettings
    $settings.DtdProcessing = [System.Xml.DtdProcessing]::Prohibit
    $settings.XmlResolver = $null

    $reader = [System.Xml.XmlReader]::Create($Path, $settings)
    try {
        $xmlDoc = New-Object System.Xml.XmlDocument
        $xmlDoc.XmlResolver = $null
        $xmlDoc.Load($reader)
        return $xmlDoc
    }
    finally {
        $reader.Close()
        $reader.Dispose()
    }
}

# 1. Validate the input folder
if (-not (Test-Path -Path $FilePath -PathType Container)) {
    Write-Host "[ERROR] Input folder does not exist: $FilePath" -ForegroundColor Red
    return
}

$targetFolder = (Resolve-Path -Path $FilePath).Path

# Determine full output file path
$outputFilePath = if ([System.IO.Path]::IsPathRooted($OutputFileName)) {
    $OutputFileName
} else {
    Join-Path -Path $targetFolder -ChildPath $OutputFileName
}

$outputFileFullPath = [System.IO.Path]::GetFullPath($outputFilePath)

# 2. Discover .nessus files in the folder (excluding the output file)
$files = @(Get-ChildItem -Path $targetFolder -Filter "*.nessus" -File |
    Where-Object { [System.IO.Path]::GetFullPath($_.FullName) -ne $outputFileFullPath })

if ($files.Count -eq 0) {
    Write-Host "[WARN] No .nessus files found in '$targetFolder'." -ForegroundColor Yellow
    return
}

Write-Host "Found $($files.Count) .nessus file(s) in '$targetFolder':" -ForegroundColor Cyan
foreach ($f in $files) {
    Write-Host "  - $($f.Name)" -ForegroundColor DarkGray
}

# 3. Load the first file as the base report
$baseFile = $files[0]
Write-Host "`nLoading base report: $($baseFile.Name)" -ForegroundColor Cyan

$baseDoc = $null
try {
    $baseDoc = Load-SafeXmlDocument -Path $baseFile.FullName
}
catch {
    Write-Host "[ERROR] Failed to load base report '$($baseFile.Name)': $($_.Exception.Message)" -ForegroundColor Red
    return
}

$baseReportNode = $baseDoc.SelectSingleNode("//Report")
if (-not $baseReportNode) {
    Write-Host "[ERROR] Invalid Nessus file: No <Report> element found in '$($baseFile.Name)'." -ForegroundColor Red
    return
}

$baseHostNodes = $baseDoc.SelectNodes("//Report/ReportHost")
$baseHostCount = if ($baseHostNodes) { $baseHostNodes.Count } else { 0 }
Write-Host "  Base report loaded with $baseHostCount host(s)." -ForegroundColor Green

# 4. Append ReportHost nodes from the remaining files
$totalHostsAdded = 0
$hasErrors = $false

if ($files.Count -gt 1) {
    for ($i = 1; $i -lt $files.Count; $i++) {
        $file = $files[$i]
        Write-Host "Processing: $($file.Name)" -ForegroundColor Cyan
        try {
            $doc = Load-SafeXmlDocument -Path $file.FullName
            $reportNode = $doc.SelectSingleNode("//Report")
            if (-not $reportNode) {
                Write-Host "  [WARN] Skipping '$($file.Name)': No <Report> element found." -ForegroundColor Yellow
                $hasErrors = $true
                continue
            }

            $hostNodes = $doc.SelectNodes("//Report/ReportHost")
            $fileHostCount = 0

            if ($hostNodes) {
                foreach ($hostNode in $hostNodes) {
                    $importedHost = $baseDoc.ImportNode($hostNode, $true)
                    [void]$baseReportNode.AppendChild($importedHost)
                    $fileHostCount++
                }
            }

            $totalHostsAdded += $fileHostCount
            Write-Host "  Added $fileHostCount host(s) from $($file.Name)." -ForegroundColor Green
        }
        catch {
            Write-Host "  [ERROR] Failed to process '$($file.Name)': $($_.Exception.Message)" -ForegroundColor Red
            $hasErrors = $true
        }
    }
}

# 5. Set the merged report name and save the output file
Write-Host "`nSetting report name to: '$ReportName'" -ForegroundColor Cyan
$baseReportNode.SetAttribute("name", $ReportName)

Write-Host "Saving merged report to: '$outputFilePath'" -ForegroundColor Cyan
try {
    $baseDoc.Save($outputFilePath)
    $totalHosts = $baseHostCount + $totalHostsAdded
    Write-Host "`n[SUCCESS] Successfully merged $totalHosts host(s) into '$outputFilePath'." -ForegroundColor Green
    if ($hasErrors) {
        Write-Host "[WARN] Note: One or more files encountered errors during processing (see messages above)." -ForegroundColor Yellow
    }
}
catch {
    Write-Host "`n[ERROR] Failed to save merged report to '$outputFilePath': $($_.Exception.Message)" -ForegroundColor Red
    return
}
