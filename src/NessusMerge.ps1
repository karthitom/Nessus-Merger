<#
.SYNOPSIS
    Nessus Merge Tool - Consolidates multiple Tenable Nessus v2 XML scan files.
.DESCRIPTION
    A lightweight, reliable, command-line-only utility to merge and deduplicate
    multiple Tenable Nessus (.nessus) scan files into a unified report.
    Built with hardened .NET XML processing to prevent XXE and data corruption.
.PARAMETER InputPath
    Directory containing .nessus files or paths to individual scan files.
.PARAMETER Files
    Explicit array of .nessus file paths.
.PARAMETER OutputPath
    Destination file path for the consolidated .nessus report.
.PARAMETER DeduplicationMode
    Deduplication strategy: 'Safe' (default), 'None', or 'KeepSeparate'.
.PARAMETER KeepSeparate
    Switch to force ambiguous hosts and distinct scans to remain separate.
.PARAMETER ValidateOnly
    Validates input scan files without generating a merged output file.
.PARAMETER LogPath
    Optional path to write a persistent execution log.
.PARAMETER Force
    Overwrite destination output file if it already exists.
.PARAMETER Quiet
    Suppresses non-error terminal output.
.PARAMETER Help
    Displays help and usage instructions.
.EXAMPLE
    pwsh -File .\src\NessusMerge.ps1 -InputPath ".\scans" -OutputPath ".\reports\merged.nessus"
.EXAMPLE
    pwsh -File .\src\NessusMerge.ps1 -Files ".\scan1.nessus", ".\scan2.nessus" -OutputPath ".\merged.nessus"
.EXAMPLE
    pwsh -File .\src\NessusMerge.ps1 -InputPath ".\scans" -OutputPath ".\reports\merged.nessus" -DeduplicationMode Safe
.EXAMPLE
    pwsh -File .\src\NessusMerge.ps1 -InputPath ".\scans" -ValidateOnly
#>

[CmdletBinding(DefaultParameterSetName = 'PathSet')]
param(
    [Parameter(ParameterSetName = 'PathSet', Position = 0, Mandatory = $false)]
    [string[]]$InputPath,

    [Parameter(ParameterSetName = 'FilesSet', Mandatory = $false)]
    [string[]]$Files,

    [Parameter(Mandatory = $false)]
    [string]$OutputPath,

    [Parameter(Mandatory = $false)]
    [ValidateSet('Safe', 'None', 'KeepSeparate')]
    [string]$DeduplicationMode = 'Safe',

    [Parameter(Mandatory = $false)]
    [switch]$KeepSeparate,

    [Parameter(Mandatory = $false)]
    [switch]$ValidateOnly,

    [Parameter(Mandatory = $false)]
    [string]$LogPath,

    [Parameter(Mandatory = $false)]
    [switch]$Force,

    [Parameter(Mandatory = $false)]
    [switch]$Quiet,

    [Parameter(Mandatory = $false)]
    [switch]$Help
)

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# Import modules
. (Join-Path $scriptDir "Logger.ps1")
. (Join-Path $scriptDir "XmlValidator.ps1")
. (Join-Path $scriptDir "HostDeduplicator.ps1")
. (Join-Path $scriptDir "FindingDeduplicator.ps1")

# Handle -Help switch
if ($Help.IsPresent) {
    $helpText = @"
================================================================================
                           NESSUS MERGE TOOL
================================================================================

DESCRIPTION:
  Merges and deduplicates multiple Tenable Nessus (.nessus) XML scan files
  into a single consolidated report using secure, hardened XML processing.

USAGE:
  pwsh -File .\src\NessusMerge.ps1 -InputPath <Dir/Files> -OutputPath <MergedFile> [Options]
  pwsh -File .\src\NessusMerge.ps1 -Files <File1,File2,...> -OutputPath <MergedFile> [Options]
  pwsh -File .\src\NessusMerge.ps1 -InputPath <Dir> -ValidateOnly

PARAMETERS:
  -InputPath <String[]>
      Path to a directory containing .nessus files or individual scan files.

  -Files <String[]>
      Array of explicit .nessus file paths.

  -OutputPath <String>
      Destination path for the consolidated .nessus report. Required unless
      -ValidateOnly is specified.

  -DeduplicationMode <Safe | None | KeepSeparate>
      Safe         : Intelligent deduplication based on canonical host identity
                     and finding composite keys (pluginID, port, protocol, svc).
                     Combines differing plugin output to ensure zero data loss.
                     (Default)
      None         : Performs no deduplication; merges all hosts and findings as-is.
      KeepSeparate : Preserves all host records separately without consolidating.

  -KeepSeparate
      Alias switch to force separate host records.

  -ValidateOnly
      Performs XML and Nessus schema validation on all inputs without merging.

  -LogPath <String>
      Optional path to append execution and error logs.

  -Force
      Overwrite existing output file if it already exists.

  -Quiet
      Suppress non-error console output.

  -Help
      Display this help menu and exit.

EXIT CODES:
  0 = Processing succeeded.
  1 = Processing failed or validation errors encountered.
================================================================================
"@
    Write-Host $helpText -ForegroundColor Cyan
    exit 0
}

# Initialize Logger
Initialize-NessusLogger -LogPath $LogPath -Quiet:$Quiet
Show-NessusBanner

if ($KeepSeparate.IsPresent) {
    $DeduplicationMode = 'KeepSeparate'
}

# Validate OutputPath presence when not ValidateOnly
if (-not $ValidateOnly.IsPresent) {
    if ([string]::IsNullOrWhiteSpace($OutputPath)) {
        Write-NessusLog "Missing required parameter '-OutputPath'. Specify a destination file or use '-ValidateOnly'." -Level 'ERROR'
        exit 1
    }
}

# Resolve OutputPath
$resolvedOutputPath = $null
if (-not [string]::IsNullOrWhiteSpace($OutputPath)) {
    try {
        $resolvedOutputPath = [System.IO.Path]::GetFullPath($OutputPath)
    }
    catch {
        Write-NessusLog "Invalid output path: '$OutputPath' ($($_.Exception.Message))" -Level 'ERROR'
        exit 1
    }
}

# Discover Input Files
$candidateFiles = [System.Collections.Generic.List[string]]::new()

if ($PSCmdlet.ParameterSetName -eq 'FilesSet' -and $null -ne $Files) {
    foreach ($f in $Files) {
        if ([string]::IsNullOrWhiteSpace($f)) { continue }
        try {
            $fullPath = [System.IO.Path]::GetFullPath($f)
            $candidateFiles.Add($fullPath)
        }
        catch {
            Write-NessusLog "Failed to resolve file path: '$f'" -Level 'WARN'
        }
    }
}
elseif ($null -ne $InputPath) {
    foreach ($p in $InputPath) {
        if ([string]::IsNullOrWhiteSpace($p)) { continue }
        if (-not (Test-Path -LiteralPath $p)) {
            Write-NessusLog "Input path does not exist: '$p'" -Level 'WARN'
            continue
        }

        if (Test-Path -LiteralPath $p -PathType Container) {
            $found = Get-ChildItem -LiteralPath $p -Filter "*.nessus" -File -Recurse | ForEach-Object { $_.FullName }
            foreach ($item in $found) {
                $candidateFiles.Add($item)
            }
        }
        else {
            try {
                $fullPath = [System.IO.Path]::GetFullPath($p)
                $candidateFiles.Add($fullPath)
            }
            catch {
                Write-NessusLog "Failed to resolve file path: '$p'" -Level 'WARN'
            }
        }
    }
}
else {
    Write-NessusLog "No input specified. Please provide -InputPath or -Files." -Level 'ERROR'
    exit 1
}

# Filter out OutputPath from candidate files to prevent self-merge
$inputFiles = [System.Collections.Generic.List[string]]::new()
$excludedOutputCount = 0

foreach ($file in $candidateFiles) {
    if (-not [string]::IsNullOrWhiteSpace($resolvedOutputPath) -and [string]::Equals($file, $resolvedOutputPath, [System.StringComparison]::OrdinalIgnoreCase)) {
        $excludedOutputCount++
        Write-NessusLog "Excluded output file from inputs: '$file'" -Level 'DEBUG'
    }
    else {
        if (-not $inputFiles.Contains($file)) {
            $inputFiles.Add($file)
        }
    }
}

if ($inputFiles.Count -eq 0) {
    Write-NessusLog "No eligible .nessus input files found to process." -Level 'ERROR'
    exit 1
}

Write-NessusLog "Discovered $($inputFiles.Count) eligible input file(s)." -Level 'INFO'

# Check existing output file protection
if (-not $ValidateOnly.IsPresent -and -not [string]::IsNullOrWhiteSpace($resolvedOutputPath)) {
    if (Test-Path -LiteralPath $resolvedOutputPath) {
        if (-not $Force.IsPresent) {
            Write-NessusLog "Destination file already exists: '$resolvedOutputPath'. Use -Force to overwrite." -Level 'ERROR'
            exit 1
        }
        else {
            Write-NessusLog "Destination file exists and -Force was specified. Will overwrite upon completion." -Level 'WARN'
        }
    }
}

# Validation Phase
$validFiles = [System.Collections.Generic.List[string]]::new()
$failedFiles = [System.Collections.Generic.List[PSCustomObject]]::new()
$sourceHostTotal = 0
$sourceFindingsTotal = 0

Write-NessusLog "Validating input files..." -Level 'INFO'
$fileIndex = 0

foreach ($filePath in $inputFiles) {
    $fileIndex++
    $fileName = [System.IO.Path]::GetFileName($filePath)
    $validation = Test-NessusXmlFile -FilePath $filePath

    if ($validation.IsValid) {
        $validFiles.Add($filePath)
        $sourceHostTotal += $validation.HostCount
        $sourceFindingsTotal += $validation.FindingCount
        Write-NessusLog "[$fileIndex/$($inputFiles.Count)] [VALID] $fileName (Hosts: $($validation.HostCount), Findings: $($validation.FindingCount))" -Level 'DEBUG'
    }
    else {
        $failedFiles.Add([PSCustomObject]@{
            FilePath = $filePath
            FileName = $fileName
            Error    = $validation.ErrorMessage
        })
        Write-NessusLog "[$fileIndex/$($inputFiles.Count)] [INVALID] $fileName - $($validation.ErrorMessage)" -Level 'ERROR'
    }
}

# Handle ValidateOnly mode
if ($ValidateOnly.IsPresent) {
    $overallStatus = if ($failedFiles.Count -eq 0) { 'VALIDATION-ONLY' } else { 'FAILED' }
    $summary = @{
        InputFiles           = $inputFiles.Count
        ProcessedFiles       = $validFiles.Count
        FailedFiles          = $failedFiles.Count
        SourceHosts          = $sourceHostTotal
        ConsolidatedHosts    = '-'
        FindingsProcessed    = $sourceFindingsTotal
        FindingsDeduplicated = '-'
        UniqueFindings       = '-'
        Output               = 'N/A (ValidateOnly mode)'
        Status               = $overallStatus
    }

    Show-NessusSummary -Summary $summary
    if ($failedFiles.Count -gt 0) {
        exit 1
    }
    exit 0
}

# If no valid files remain
if ($validFiles.Count -eq 0) {
    Write-NessusLog "All input files failed validation. Aborting merge." -Level 'ERROR'
    $summary = @{
        InputFiles           = $inputFiles.Count
        ProcessedFiles       = 0
        FailedFiles          = $failedFiles.Count
        SourceHosts          = 0
        ConsolidatedHosts    = 0
        FindingsProcessed    = 0
        FindingsDeduplicated = 0
        UniqueFindings       = 0
        Output               = $resolvedOutputPath
        Status               = 'FAILED'
    }
    Show-NessusSummary -Summary $summary
    exit 1
}

# Merge Execution Phase
Write-NessusLog "Beginning consolidation with DeduplicationMode '$DeduplicationMode'..." -Level 'INFO'

$masterDoc = [System.Xml.XmlDocument]::new()
$masterDoc.XmlResolver = $null

# Create root XML declaration and NessusClientData_v2
$xmlDeclaration = $masterDoc.CreateXmlDeclaration("1.0", "UTF-8", $null)
$null = $masterDoc.AppendChild($xmlDeclaration)

$rootElement = $masterDoc.CreateElement("NessusClientData_v2")
$null = $masterDoc.AppendChild($rootElement)

$policyImported = $false
$masterReport = $masterDoc.CreateElement("Report")
$masterReport.SetAttribute("name", "Consolidated Nessus Report")
$masterReport.SetAttribute("xmlns:cm", "http://www.nessus.org/cm")

# Dictionaries to track hosts and findings
# Key: canonical host key -> Target ReportHost XmlElement
$consolidatedHosts = [System.Collections.Generic.Dictionary[string, System.Xml.XmlElement]]::new([System.StringComparer]::OrdinalIgnoreCase)

# Key: canonical host key -> Dictionary of finding composite key -> Target ReportItem XmlElement
$hostFindings = [System.Collections.Generic.Dictionary[string, System.Collections.Generic.Dictionary[string, System.Xml.XmlElement]]]::new([System.StringComparer]::OrdinalIgnoreCase)

# Key: canonical host key -> Dictionary of finding composite key -> Source File Name
$hostFindingSource = [System.Collections.Generic.Dictionary[string, System.Collections.Generic.Dictionary[string, string]]]::new([System.StringComparer]::OrdinalIgnoreCase)

$findingsProcessedCount = 0
$findingsDeduplicatedCount = 0

$currentFileNum = 0
foreach ($filePath in $validFiles) {
    $currentFileNum++
    $fileName = [System.IO.Path]::GetFileName($filePath)
    Write-NessusLog "Processing file [$currentFileNum/$($validFiles.Count)]: $fileName" -Level 'INFO'

    $sourceDoc = Load-SafeNessusDocument -FilePath $filePath

    # Import Policy from first file if not yet imported
    if (-not $policyImported) {
        $policyNode = $sourceDoc.SelectSingleNode('/NessusClientData_v2/Policy')
        if ($null -ne $policyNode) {
            $importedPolicy = $masterDoc.ImportNode($policyNode, $true)
            $null = $rootElement.AppendChild($importedPolicy)
            $policyImported = $true
            Write-NessusLog "Imported scan policy from '$fileName'" -Level 'DEBUG'
        }
    }

    # Process ReportHosts
    $sourceHosts = $sourceDoc.SelectNodes('/NessusClientData_v2/Report/ReportHost')
    foreach ($sourceHost in $sourceHosts) {
        $hostKey = Get-CanonicalHostKey -ReportHostElement $sourceHost -DeduplicationMode $DeduplicationMode -SourceIdentifier $fileName

        $targetHost = $null
        if ($consolidatedHosts.ContainsKey($hostKey)) {
            # Duplicate/matching host found - merge properties
            $targetHost = $consolidatedHosts[$hostKey]
            Merge-HostProperties -TargetHost $targetHost -SourceHost $sourceHost -SourceFileName $fileName
        }
        else {
            # New host record
            $targetHost = $masterDoc.CreateElement("ReportHost")
            $targetHost.SetAttribute("name", $sourceHost.GetAttribute("name"))

            # Clone HostProperties
            $hostProps = $sourceHost.SelectSingleNode("HostProperties")
            if ($null -ne $hostProps) {
                $importedProps = $masterDoc.ImportNode($hostProps, $true)
                $null = $targetHost.AppendChild($importedProps)
            }

            $null = $masterReport.AppendChild($targetHost)
            $consolidatedHosts[$hostKey] = $targetHost
            $hostFindings[$hostKey] = [System.Collections.Generic.Dictionary[string, System.Xml.XmlElement]]::new([System.StringComparer]::OrdinalIgnoreCase)
            $hostFindingSource[$hostKey] = [System.Collections.Generic.Dictionary[string, string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        }

        $findingsMap = $hostFindings[$hostKey]
        $sourceMap   = $hostFindingSource[$hostKey]

        # Process ReportItems (Findings)
        $sourceItems = $sourceHost.SelectNodes('ReportItem')
        foreach ($sourceItem in $sourceItems) {
            $findingsProcessedCount++
            $findingKey = Get-FindingCompositeKey -ReportItemElement $sourceItem

            if ($DeduplicationMode -eq 'Safe' -and $findingsMap.ContainsKey($findingKey)) {
                # Duplicate finding on same host - merge safely
                $targetItem = $findingsMap[$findingKey]
                $targetSrc  = $sourceMap[$findingKey]
                Merge-ReportItems -TargetItem $targetItem -SourceItem $sourceItem -TargetSourceName $targetSrc -SourceFileName $fileName
                $findingsDeduplicatedCount++
            }
            else {
                # Distinct finding or deduplication disabled
                $importedItem = $masterDoc.ImportNode($sourceItem, $true)
                $null = $targetHost.AppendChild($importedItem)

                if ($DeduplicationMode -ne 'None') {
                    $uniqueFindingKey = if ($DeduplicationMode -eq 'Safe') { $findingKey } else { "$findingKey|$([System.Guid]::NewGuid().ToString('N'))" }
                    $findingsMap[$uniqueFindingKey] = $importedItem
                    $sourceMap[$uniqueFindingKey] = $fileName
                }
            }
        }
    }
}

# Attach master report to root
$null = $rootElement.AppendChild($masterReport)

# Atomic Output Generation
$uniqueFindingsTotal = $findingsProcessedCount - $findingsDeduplicatedCount
$outputDir = [System.IO.Path]::GetDirectoryName($resolvedOutputPath)
if (-not [string]::IsNullOrWhiteSpace($outputDir) -and -not (Test-Path -LiteralPath $outputDir)) {
    $null = New-Item -ItemType Directory -Path $outputDir -Force
}

$tempOutputFile = "$resolvedOutputPath.tmp.$([System.Guid]::NewGuid().ToString('N')).nessus"

try {
    Write-NessusLog "Writing merged XML to temporary destination: '$tempOutputFile'" -Level 'DEBUG'
    
    $xmlWriterSettings = [System.Xml.XmlWriterSettings]::new()
    $xmlWriterSettings.Indent = $true
    $xmlWriterSettings.IndentChars = "  "
    $xmlWriterSettings.Encoding = [System.Text.UTF8Encoding]::new($false)
    $xmlWriterSettings.CloseOutput = $true

    $writer = [System.Xml.XmlWriter]::Create($tempOutputFile, $xmlWriterSettings)
    try {
        $masterDoc.Save($writer)
    }
    finally {
        $writer.Dispose()
    }

    # Validate generated output before finalizing
    Write-NessusLog "Validating consolidated output document..." -Level 'INFO'
    $outputValidation = Test-MergedNessusOutput -FilePath $tempOutputFile -ExpectedHosts $consolidatedHosts.Count -ExpectedFindings $uniqueFindingsTotal

    if (-not $outputValidation.IsValid) {
        throw [System.InvalidOperationException]::new("Output validation failed: $($outputValidation.ErrorMessage)")
    }

    # Finalize destination file atomically
    if (Test-Path -LiteralPath $resolvedOutputPath) {
        Remove-Item -LiteralPath $resolvedOutputPath -Force
    }
    Move-Item -LiteralPath $tempOutputFile -Destination $resolvedOutputPath -Force
    Write-NessusLog "Successfully finalized output at '$resolvedOutputPath'" -Level 'SUCCESS'

    $finalStatus = if ($failedFiles.Count -eq 0) { 'SUCCESS' } else { 'FAILED' }

    $summary = @{
        InputFiles           = $inputFiles.Count
        ProcessedFiles       = $validFiles.Count
        FailedFiles          = $failedFiles.Count
        SourceHosts          = $sourceHostTotal
        ConsolidatedHosts    = $consolidatedHosts.Count
        FindingsProcessed    = $findingsProcessedCount
        FindingsDeduplicated = $findingsDeduplicatedCount
        UniqueFindings       = $uniqueFindingsTotal
        Output               = $resolvedOutputPath
        Status               = $finalStatus
    }

    Show-NessusSummary -Summary $summary

    if ($failedFiles.Count -gt 0) {
        Write-NessusLog "Merge completed with partial input failures. Review failed files list." -Level 'WARN'
        exit 1
    }
    exit 0
}
catch {
    Write-NessusLog "Fatal error writing output file: $($_.Exception.Message)" -Level 'ERROR'
    if (Test-Path -LiteralPath $tempOutputFile) {
        Remove-Item -LiteralPath $tempOutputFile -Force -ErrorAction SilentlyContinue
    }
    $summary = @{
        InputFiles           = $inputFiles.Count
        ProcessedFiles       = $validFiles.Count
        FailedFiles          = $failedFiles.Count
        SourceHosts          = $sourceHostTotal
        ConsolidatedHosts    = $consolidatedHosts.Count
        FindingsProcessed    = $findingsProcessedCount
        FindingsDeduplicated = $findingsDeduplicatedCount
        UniqueFindings       = $uniqueFindingsTotal
        Output               = $resolvedOutputPath
        Status               = 'FAILED'
    }
    Show-NessusSummary -Summary $summary
    exit 1
}
