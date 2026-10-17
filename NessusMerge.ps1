<#
.SYNOPSIS
    Nessus Merge Tool - A simple, single-file CLI utility to merge and deduplicate
    multiple Tenable Nessus (.nessus) scan files into a unified report.

.DESCRIPTION
    Consolidates multiple Nessus v2 XML scan reports into a single file with safe host
    and finding deduplication, XXE protection, and atomic output generation.

.PARAMETER InputPath
    Folder path containing .nessus scan files or path to an individual scan file.

.PARAMETER Files
    Array of explicit paths to .nessus files.

.PARAMETER OutputPath
    Destination file path for the merged .nessus report. Required unless -ValidateOnly is used.

.PARAMETER DeduplicationMode
    Deduplication strategy: 'Safe' (default), 'None', or 'KeepSeparate'.
    - Safe: Deduplicates hosts by canonical IP/FQDN and merges duplicate findings
            without discarding differing evidence.
    - None: Keeps all host records and findings as-is without deduplication.
    - KeepSeparate: Forces all hosts from different scans to stay separate.

.PARAMETER KeepSeparate
    Switch to force all host records to remain separate (equivalent to -DeduplicationMode KeepSeparate).

.PARAMETER ValidateOnly
    Checks all input files for XML and Nessus schema validity without generating an output file.

.PARAMETER LogPath
    Optional file path to append execution logs.

.PARAMETER Force
    Overwrite destination output file if it already exists.

.PARAMETER Quiet
    Suppress non-error terminal output.

.PARAMETER Help
    Show parameter help and CLI usage examples.

.EXAMPLE
    pwsh -File .\NessusMerge.ps1 -InputPath ".\scans" -OutputPath ".\merged.nessus"

.EXAMPLE
    pwsh -File .\NessusMerge.ps1 -Files ".\scan1.nessus", ".\scan2.nessus" -OutputPath ".\merged.nessus"

.EXAMPLE
    pwsh -File .\NessusMerge.ps1 -InputPath ".\scans" -ValidateOnly
#>

[CmdletBinding()]
param(
    [Parameter(Position = 0, Mandatory = $false)]
    [string[]]$InputPath,

    [Parameter(Mandatory = $false)]
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

# -----------------------------------------------------------------------------
# CLI Banner & Help
# -----------------------------------------------------------------------------

function Show-Banner {
    if ($Quiet.IsPresent) { return }
    Write-Host @"
==========================================
           NESSUS MERGE TOOL
==========================================
"@ -ForegroundColor DarkCyan
}

function Show-Help {
    Write-Host @"
================================================================================
                           NESSUS MERGE TOOL
================================================================================

DESCRIPTION:
  Merges and deduplicates multiple Tenable Nessus (.nessus) XML scan files
  into a single consolidated report using secure, hardened .NET XML processing.

USAGE:
  pwsh -File .\NessusMerge.ps1 -InputPath <Folder> -OutputPath <MergedFile> [Options]
  pwsh -File .\NessusMerge.ps1 -Files <File1,File2,...> -OutputPath <MergedFile> [Options]
  pwsh -File .\NessusMerge.ps1 -InputPath <Folder> -ValidateOnly

PARAMETERS:
  -InputPath <String[]>
      Path to a folder containing .nessus files or individual scan files.

  -Files <String[]>
      Array of explicit .nessus file paths.

  -OutputPath <String>
      Destination path for the consolidated .nessus report.
      (Required unless -ValidateOnly is used).

  -DeduplicationMode <Safe | None | KeepSeparate>
      Safe         : Intelligent deduplication based on IP/FQDN. Combines differing
                     plugin outputs into a unified finding so no evidence is lost. (Default)
      None         : Performs no deduplication; imports all records as-is.
      KeepSeparate : Preserves all host records separately without consolidating.

  -KeepSeparate
      Shortcut switch to force separate host records.

  -ValidateOnly
      Validates XML and Nessus structure without generating an output file.

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
"@ -ForegroundColor Cyan
}

if ($Help.IsPresent) {
    Show-Help
    exit 0
}

# -----------------------------------------------------------------------------
# Logging Functionality
# -----------------------------------------------------------------------------

$script:ResolvedLogPath = $null

if (-not [string]::IsNullOrWhiteSpace($LogPath)) {
    try {
        $script:ResolvedLogPath = [System.IO.Path]::GetFullPath($LogPath)
        $logDir = [System.IO.Path]::GetDirectoryName($script:ResolvedLogPath)
        if (-not [string]::IsNullOrWhiteSpace($logDir) -and -not (Test-Path -LiteralPath $logDir)) {
            $null = New-Item -ItemType Directory -Path $logDir -Force
        }
        $header = "[{0:yyyy-MM-dd HH:mm:ss}] [INFO] Nessus Merge Tool Logger Initialized." -f (Get-Date)
        [System.IO.File]::AppendAllText($script:ResolvedLogPath, "$header`r`n", [System.Text.Encoding]::UTF8)
    }
    catch {
        Write-Warning "Could not initialize log file at '$LogPath': $($_.Exception.Message)"
        $script:ResolvedLogPath = $null
    }
}

function Write-Log {
    param(
        [Parameter(Mandatory = $true, Position = 0)][string]$Message,
        [Parameter(Mandatory = $false)][ValidateSet('INFO', 'SUCCESS', 'WARN', 'ERROR', 'DEBUG')][string]$Level = 'INFO'
    )

    $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $logEntry = "[$timestamp] [$Level] $Message"

    if (-not [string]::IsNullOrWhiteSpace($script:ResolvedLogPath)) {
        try {
            [System.IO.File]::AppendAllText($script:ResolvedLogPath, "$logEntry`r`n", [System.Text.Encoding]::UTF8)
        }
        catch {}
    }

    if ($Quiet.IsPresent -and $Level -ne 'ERROR') { return }

    switch ($Level) {
        'SUCCESS' { Write-Host $logEntry -ForegroundColor Green }
        'WARN'    { Write-Host $logEntry -ForegroundColor Yellow }
        'ERROR'   { Write-Host $logEntry -ForegroundColor Red }
        'DEBUG'   { Write-Verbose $logEntry }
        default   { Write-Host $logEntry -ForegroundColor Cyan }
    }
}

# -----------------------------------------------------------------------------
# XML Security & Validation
# -----------------------------------------------------------------------------

function Get-SafeXmlReaderSettings {
    # Hardened settings: Prohibit DTD processing and external entity resolution (XXE prevention)
    $settings = [System.Xml.XmlReaderSettings]::new()
    $settings.DtdProcessing = [System.Xml.DtdProcessing]::Prohibit
    $settings.XmlResolver = $null
    $settings.MaxCharactersFromEntities = 0
    $settings.IgnoreComments = $false
    $settings.IgnoreWhitespace = $false
    return $settings
}

function Test-NessusXml {
    param([Parameter(Mandatory = $true)][string]$FilePath)

    $result = [PSCustomObject]@{
        FilePath     = $FilePath
        IsValid      = $false
        ErrorMessage = $null
        HostCount    = 0
        FindingCount = 0
    }

    if (-not (Test-Path -LiteralPath $FilePath -PathType Leaf)) {
        $result.ErrorMessage = "File does not exist or is a directory: '$FilePath'"
        return $result
    }

    $fileInfo = Get-Item -LiteralPath $FilePath
    if ($fileInfo.Length -eq 0) {
        $result.ErrorMessage = "File is empty (0 bytes): '$FilePath'"
        return $result
    }

    $settings = Get-SafeXmlReaderSettings
    $reader = $null

    try {
        $reader = [System.Xml.XmlReader]::Create($FilePath, $settings)
        $hasRoot = $false

        while ($reader.Read()) {
            if ($reader.NodeType -eq [System.Xml.XmlNodeType]::Element) {
                if ($reader.LocalName -ne 'NessusClientData_v2') {
                    $result.ErrorMessage = "Invalid root element '<$($reader.LocalName)>'. Expected '<NessusClientData_v2>'."
                    return $result
                }
                $hasRoot = $true
                break
            }
        }

        if (-not $hasRoot) {
            $result.ErrorMessage = "XML file contains no root element."
            return $result
        }

        $hasReport = $false
        $hosts = 0
        $findings = 0

        while ($reader.Read()) {
            if ($reader.NodeType -eq [System.Xml.XmlNodeType]::Element) {
                if ($reader.LocalName -eq 'Report') { $hasReport = $true }
                elseif ($reader.LocalName -eq 'ReportHost') { $hosts++ }
                elseif ($reader.LocalName -eq 'ReportItem') { $findings++ }
            }
        }

        if (-not $hasReport) {
            $result.ErrorMessage = "Missing required '<Report>' element in Nessus scan."
            return $result
        }

        $result.IsValid = $true
        $result.HostCount = $hosts
        $result.FindingCount = $findings
        return $result
    }
    catch [System.Xml.XmlException] {
        $result.ErrorMessage = "Malformed XML at Line $($_.Exception.LineNumber), Pos $($_.Exception.LinePosition): $($_.Exception.Message)"
        return $result
    }
    catch {
        $result.ErrorMessage = "XML validation error: $($_.Exception.Message)"
        return $result
    }
    finally {
        if ($null -ne $reader) { $reader.Dispose() }
    }
}

function Load-NessusXml {
    param([Parameter(Mandatory = $true)][string]$FilePath)

    $settings = Get-SafeXmlReaderSettings
    $reader = [System.Xml.XmlReader]::Create($FilePath, $settings)
    try {
        $doc = [System.Xml.XmlDocument]::new()
        $doc.XmlResolver = $null
        $doc.Load($reader)
        return $doc
    }
    finally {
        if ($null -ne $reader) { $reader.Dispose() }
    }
}

# -----------------------------------------------------------------------------
# Deduplication Logic
# -----------------------------------------------------------------------------

function Test-IsIp {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    $ip = $null
    return [System.Net.IPAddress]::TryParse($Value.Trim(), [ref]$ip)
}

function Get-HostKey {
    param(
        [Parameter(Mandatory = $true)][System.Xml.XmlElement]$ReportHostElement,
        [Parameter(Mandatory = $true)][string]$Mode,
        [Parameter(Mandatory = $true)][string]$SourceId
    )

    $hostName = $ReportHostElement.GetAttribute('name')
    if ($null -eq $hostName) { $hostName = '' }
    $hostName = $hostName.Trim()

    if ($Mode -eq 'None' -or $Mode -eq 'KeepSeparate') {
        return "$SourceId::HOST::$hostName::$([System.Guid]::NewGuid().ToString('N'))"
    }

    # Extract tags
    $props = @{}
    $hostPropsNode = $ReportHostElement.SelectSingleNode('HostProperties')
    if ($null -ne $hostPropsNode) {
        foreach ($tag in $hostPropsNode.SelectNodes('tag')) {
            $name = $tag.GetAttribute('name')
            if (-not [string]::IsNullOrEmpty($name)) {
                $props[$name] = $tag.InnerText
            }
        }
    }

    $hostIp   = if ($props.ContainsKey('host-ip')) { $props['host-ip'].Trim() } else { '' }
    $hostFqdn = if ($props.ContainsKey('host-fqdn')) { $props['host-fqdn'].Trim().ToLowerInvariant() } else { '' }
    $netbios  = if ($props.ContainsKey('netbios-name')) { $props['netbios-name'].Trim().ToUpperInvariant() } else { '' }
    $mac      = if ($props.ContainsKey('mac-address')) { $props['mac-address'].Trim().ToLowerInvariant() } else { '' }

    # Guard: If name is IP and host-ip tag is differing IP, keep separate
    if ((Test-IsIp $hostName) -and -not [string]::IsNullOrWhiteSpace($hostIp) -and (Test-IsIp $hostIp)) {
        if ($hostName -ne $hostIp) {
            return "AMBIGUOUS::$SourceId::$hostName::$hostIp::$([System.Guid]::NewGuid().ToString('N'))"
        }
    }

    if (Test-IsIp $hostIp)   { return "IP::$hostIp" }
    if (Test-IsIp $hostName) { return "IP::$hostName" }
    if (-not [string]::IsNullOrWhiteSpace($mac))      { return "MAC::$mac" }
    if (-not [string]::IsNullOrWhiteSpace($hostFqdn)) { return "FQDN::$hostFqdn" }
    if (-not [string]::IsNullOrWhiteSpace($netbios))  { return "NETBIOS::$netbios" }
    if (-not [string]::IsNullOrWhiteSpace($hostName)) { return "NAME::$($hostName.ToLowerInvariant())" }

    return "ANON::$SourceId::$([System.Guid]::NewGuid().ToString('N'))"
}

function Merge-HostProperties {
    param(
        [Parameter(Mandatory = $true)][System.Xml.XmlElement]$TargetHost,
        [Parameter(Mandatory = $true)][System.Xml.XmlElement]$SourceHost,
        [Parameter(Mandatory = $true)][string]$SourceFileName
    )

    $doc = $TargetHost.OwnerDocument
    $targetProps = $TargetHost.SelectSingleNode('HostProperties')
    if ($null -eq $targetProps) {
        $targetProps = $doc.CreateElement('HostProperties')
        $null = $TargetHost.PrependChild($targetProps)
    }

    $sourceProps = $SourceHost.SelectSingleNode('HostProperties')
    if ($null -eq $sourceProps) { return }

    $targetTags = @{}
    foreach ($tag in $targetProps.SelectNodes('tag')) {
        $n = $tag.GetAttribute('name')
        if (-not [string]::IsNullOrEmpty($n)) { $targetTags[$n] = $tag }
    }

    foreach ($sTag in $sourceProps.SelectNodes('tag')) {
        $tagName = $sTag.GetAttribute('name')
        if ([string]::IsNullOrEmpty($tagName)) { continue }
        $sVal = $sTag.InnerText

        if (-not $targetTags.ContainsKey($tagName)) {
            $imported = $doc.ImportNode($sTag, $true)
            $null = $targetProps.AppendChild($imported)
            $targetTags[$tagName] = $imported
        }
        else {
            $tTag = $targetTags[$tagName]
            $tVal = $tTag.InnerText
            if ($tVal -eq $sVal) { continue }

            if ($tagName -eq 'HOST_START') {
                try {
                    $dt1 = [DateTime]::Parse($tVal)
                    $dt2 = [DateTime]::Parse($sVal)
                    if ($dt2 -lt $dt1) { $tTag.InnerText = $sVal }
                } catch {}
            }
            elseif ($tagName -eq 'HOST_END') {
                try {
                    $dt1 = [DateTime]::Parse($tVal)
                    $dt2 = [DateTime]::Parse($sVal)
                    if ($dt2 -gt $dt1) { $tTag.InnerText = $sVal }
                } catch {}
            }
            else {
                # Preserve conflicting metadata with provenance note
                $sanitized = ($SourceFileName -replace '[^a-zA-Z0-9_\-]', '_')
                $conflictName = "$tagName`_conflict_$sanitized"
                if (-not $targetTags.ContainsKey($conflictName)) {
                    $conflictTag = $doc.CreateElement('tag')
                    $conflictTag.SetAttribute('name', $conflictName)
                    $conflictTag.InnerText = $sVal
                    $null = $targetProps.AppendChild($conflictTag)
                    $targetTags[$conflictName] = $conflictTag
                }
            }
        }
    }
}

function Get-FindingKey {
    param([Parameter(Mandatory = $true)][System.Xml.XmlElement]$ReportItem)

    $id   = $ReportItem.GetAttribute('pluginID')
    $port = $ReportItem.GetAttribute('port')
    $prot = $ReportItem.GetAttribute('protocol')
    $svc  = $ReportItem.GetAttribute('svc_name')

    if ($null -eq $id)   { $id = '' }
    if ($null -eq $port) { $port = '0' }
    if ($null -eq $prot) { $prot = 'tcp' }
    if ($null -eq $svc)  { $svc = '' }

    return "$($id.Trim())|$($port.Trim())|$($prot.Trim().ToLowerInvariant())|$($svc.Trim().ToLowerInvariant())"
}

function Merge-Findings {
    param(
        [Parameter(Mandatory = $true)][System.Xml.XmlElement]$TargetItem,
        [Parameter(Mandatory = $true)][System.Xml.XmlElement]$SourceItem,
        [Parameter(Mandatory = $true)][string]$TargetSrc,
        [Parameter(Mandatory = $true)][string]$SourceSrc
    )

    $doc = $TargetItem.OwnerDocument

    # Update to higher severity if different
    $tSev = 0; $sSev = 0
    [int]::TryParse($TargetItem.GetAttribute('severity'), [ref]$tSev) | Out-Null
    [int]::TryParse($SourceItem.GetAttribute('severity'), [ref]$sSev) | Out-Null
    if ($sSev -gt $tSev) { $TargetItem.SetAttribute('severity', $sSev.ToString()) }

    # Combine differing plugin_output without data loss
    $tOut = $TargetItem.SelectSingleNode('plugin_output')
    $sOut = $SourceItem.SelectSingleNode('plugin_output')

    if ($null -ne $sOut) {
        $sText = $sOut.InnerText
        if ($null -eq $tOut) {
            $importedOut = $doc.ImportNode($sOut, $true)
            $null = $TargetItem.AppendChild($importedOut)
        }
        else {
            $tText = $tOut.InnerText
            if ($tText.Trim() -ne $sText.Trim() -and -not [string]::IsNullOrWhiteSpace($sText)) {
                $combined = @"
[Source: $TargetSrc]
$($tText.Trim())

----------------------------------------
[Source: $SourceSrc]
$($sText.Trim())
"@
                $tOut.InnerText = $combined
            }
        }
    }

    # Merge unique CVEs
    $existingCves = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($cve in $TargetItem.SelectNodes('cve')) {
        if (-not [string]::IsNullOrWhiteSpace($cve.InnerText)) {
            $null = $existingCves.Add($cve.InnerText.Trim())
        }
    }
    foreach ($sCve in $SourceItem.SelectNodes('cve')) {
        $val = $sCve.InnerText.Trim()
        if (-not [string]::IsNullOrWhiteSpace($val) -and -not $existingCves.Contains($val)) {
            $importedCve = $doc.ImportNode($sCve, $true)
            $null = $TargetItem.AppendChild($importedCve)
            $null = $existingCves.Add($val)
        }
    }

    # Merge references & see_also
    $existingRefs = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($xref in $TargetItem.SelectNodes('xref')) {
        if (-not [string]::IsNullOrWhiteSpace($xref.InnerText)) {
            $null = $existingRefs.Add($xref.InnerText.Trim())
        }
    }
    foreach ($sRef in $SourceItem.SelectNodes('xref')) {
        $val = $sRef.InnerText.Trim()
        if (-not [string]::IsNullOrWhiteSpace($val) -and -not $existingRefs.Contains($val)) {
            $importedRef = $doc.ImportNode($sRef, $true)
            $null = $TargetItem.AppendChild($importedRef)
            $null = $existingRefs.Add($val)
        }
    }
}

# -----------------------------------------------------------------------------
# Summary Output
# -----------------------------------------------------------------------------

function Show-Summary {
    param([Parameter(Mandatory = $true)][hashtable]$Summary)

    if ($Quiet.IsPresent) { return }

    $color = if ($Summary.Status -eq 'SUCCESS') { 'Green' }
             elseif ($Summary.Status -eq 'VALIDATION-ONLY') { 'Cyan' }
             else { 'Red' }

    $outLine = if (-not [string]::IsNullOrWhiteSpace($Summary.Output)) {
        "Output: $($Summary.Output)`r`n"
    } else { "" }

    Write-Host @"

==========================================
       NESSUS MERGE TOOL SUMMARY
==========================================

Input files         : $($Summary.InputFiles)
Processed files     : $($Summary.ProcessedFiles)
Failed files        : $($Summary.FailedFiles)
Source host records : $($Summary.SourceHosts)
Consolidated hosts  : $($Summary.ConsolidatedHosts)
Findings processed  : $($Summary.FindingsProcessed)
Findings deduplicated: $($Summary.FindingsDeduplicated)
Unique findings     : $($Summary.UniqueFindings)

$($outLine)Status: $($Summary.Status)
==========================================
"@ -ForegroundColor $color
}

# -----------------------------------------------------------------------------
# Main Workflow Execution
# -----------------------------------------------------------------------------

Show-Banner

if ($KeepSeparate.IsPresent) {
    $DeduplicationMode = 'KeepSeparate'
}

# Validate OutputPath when not in ValidateOnly mode
if (-not $ValidateOnly.IsPresent) {
    if ([string]::IsNullOrWhiteSpace($OutputPath)) {
        Write-Log "Missing required parameter '-OutputPath'. Specify a destination file or use '-ValidateOnly'." -Level 'ERROR'
        exit 1
    }
}

$resolvedOutputPath = $null
if (-not [string]::IsNullOrWhiteSpace($OutputPath)) {
    try {
        $resolvedOutputPath = [System.IO.Path]::GetFullPath($OutputPath)
    }
    catch {
        Write-Log "Invalid output path: '$OutputPath' ($($_.Exception.Message))" -Level 'ERROR'
        exit 1
    }
}

# 1. Discover Input Files
$discovered = [System.Collections.Generic.List[string]]::new()
$inputCandidates = [System.Collections.Generic.List[string]]::new()

if ($null -ne $Files) {
    foreach ($entry in $Files) {
        if ([string]::IsNullOrWhiteSpace($entry)) { continue }
        foreach ($sub in $entry.Split(',')) {
            $cleaned = $sub.Trim().Trim('"').Trim("'")
            if (-not [string]::IsNullOrWhiteSpace($cleaned)) {
                $inputCandidates.Add($cleaned)
            }
        }
    }
}

if ($null -ne $InputPath) {
    foreach ($entry in $InputPath) {
        if ([string]::IsNullOrWhiteSpace($entry)) { continue }
        foreach ($sub in $entry.Split(',')) {
            $cleaned = $sub.Trim().Trim('"').Trim("'")
            if (-not [string]::IsNullOrWhiteSpace($cleaned)) {
                $inputCandidates.Add($cleaned)
            }
        }
    }
}

if ($inputCandidates.Count -eq 0) {
    Write-Log "No input specified. Please provide -InputPath or -Files." -Level 'ERROR'
    exit 1
}

foreach ($target in $inputCandidates) {
    if (-not (Test-Path -LiteralPath $target)) {
        Write-Log "Input path does not exist: '$target'" -Level 'WARN'
        continue
    }

    if (Test-Path -LiteralPath $target -PathType Container) {
        $filesFound = Get-ChildItem -LiteralPath $target -Filter "*.nessus" -File -Recurse | ForEach-Object { $_.FullName }
        foreach ($item in $filesFound) {
            $discovered.Add($item)
        }
    }
    else {
        try {
            $discovered.Add([System.IO.Path]::GetFullPath($target))
        }
        catch {
            Write-Log "Failed to resolve file path: '$target'" -Level 'WARN'
        }
    }
}

# Exclude OutputPath from input files to prevent self-merging
$inputFiles = [System.Collections.Generic.List[string]]::new()
foreach ($file in $discovered) {
    if (-not [string]::IsNullOrWhiteSpace($resolvedOutputPath) -and [string]::Equals($file, $resolvedOutputPath, [System.StringComparison]::OrdinalIgnoreCase)) {
        Write-Log "Excluded output file from input list: '$file'" -Level 'DEBUG'
    }
    else {
        if (-not $inputFiles.Contains($file)) { $inputFiles.Add($file) }
    }
}

if ($inputFiles.Count -eq 0) {
    Write-Log "No eligible .nessus input files found to process." -Level 'ERROR'
    exit 1
}

Write-Log "Discovered $($inputFiles.Count) eligible input file(s)." -Level 'INFO'

# Prevent accidental overwrites
if (-not $ValidateOnly.IsPresent -and -not [string]::IsNullOrWhiteSpace($resolvedOutputPath)) {
    if (Test-Path -LiteralPath $resolvedOutputPath) {
        if (-not $Force.IsPresent) {
            Write-Log "Destination file already exists: '$resolvedOutputPath'. Use -Force to overwrite." -Level 'ERROR'
            exit 1
        }
        else {
            Write-Log "Destination file exists and -Force was specified. Overwrite enabled." -Level 'WARN'
        }
    }
}

# 2. Validation Phase
$validFiles = [System.Collections.Generic.List[string]]::new()
$failedFiles = [System.Collections.Generic.List[PSCustomObject]]::new()
$sourceHostTotal = 0
$sourceFindingsTotal = 0

Write-Log "Validating input scan files..." -Level 'INFO'
$i = 0
foreach ($filePath in $inputFiles) {
    $i++
    $fName = [System.IO.Path]::GetFileName($filePath)
    $val = Test-NessusXml -FilePath $filePath

    if ($val.IsValid) {
        $validFiles.Add($filePath)
        $sourceHostTotal += $val.HostCount
        $sourceFindingsTotal += $val.FindingCount
        Write-Log "[$i/$($inputFiles.Count)] [VALID] $fName (Hosts: $($val.HostCount), Findings: $($val.FindingCount))" -Level 'DEBUG'
    }
    else {
        $failedFiles.Add([PSCustomObject]@{ FilePath = $filePath; Error = $val.ErrorMessage })
        Write-Log "[$i/$($inputFiles.Count)] [INVALID] $fName - $($val.ErrorMessage)" -Level 'ERROR'
    }
}

if ($ValidateOnly.IsPresent) {
    $vStatus = if ($failedFiles.Count -eq 0) { 'VALIDATION-ONLY' } else { 'FAILED' }
    $vSummary = @{
        InputFiles           = $inputFiles.Count
        ProcessedFiles       = $validFiles.Count
        FailedFiles          = $failedFiles.Count
        SourceHosts          = $sourceHostTotal
        ConsolidatedHosts    = '-'
        FindingsProcessed    = $sourceFindingsTotal
        FindingsDeduplicated = '-'
        UniqueFindings       = '-'
        Output               = 'N/A (ValidateOnly mode)'
        Status               = $vStatus
    }
    Show-Summary -Summary $vSummary
    if ($failedFiles.Count -gt 0) { exit 1 }
    exit 0
}

if ($validFiles.Count -eq 0) {
    Write-Log "All input files failed validation. Aborting merge." -Level 'ERROR'
    $fSummary = @{
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
    Show-Summary -Summary $fSummary
    exit 1
}

# 3. Merging Phase
Write-Log "Beginning consolidation with DeduplicationMode '$DeduplicationMode'..." -Level 'INFO'

$masterDoc = [System.Xml.XmlDocument]::new()
$masterDoc.XmlResolver = $null
$null = $masterDoc.AppendChild($masterDoc.CreateXmlDeclaration("1.0", "UTF-8", $null))

$rootElement = $masterDoc.CreateElement("NessusClientData_v2")
$null = $masterDoc.AppendChild($rootElement)

$masterReport = $masterDoc.CreateElement("Report")
$masterReport.SetAttribute("name", "Consolidated Nessus Report")
$masterReport.SetAttribute("xmlns:cm", "http://www.nessus.org/cm")

$policyImported = $false
$consolidatedHosts = [System.Collections.Generic.Dictionary[string, System.Xml.XmlElement]]::new([System.StringComparer]::OrdinalIgnoreCase)
$hostFindings = [System.Collections.Generic.Dictionary[string, System.Collections.Generic.Dictionary[string, System.Xml.XmlElement]]]::new([System.StringComparer]::OrdinalIgnoreCase)
$hostFindingSource = [System.Collections.Generic.Dictionary[string, System.Collections.Generic.Dictionary[string, string]]]::new([System.StringComparer]::OrdinalIgnoreCase)

$findingsProcessed = 0
$findingsDeduplicated = 0

$cur = 0
foreach ($filePath in $validFiles) {
    $cur++
    $fName = [System.IO.Path]::GetFileName($filePath)
    Write-Log "Processing scan [$cur/$($validFiles.Count)]: $fName" -Level 'INFO'

    $sDoc = Load-NessusXml -FilePath $filePath

    if (-not $policyImported) {
        $pNode = $sDoc.SelectSingleNode('/NessusClientData_v2/Policy')
        if ($null -ne $pNode) {
            $null = $rootElement.AppendChild($masterDoc.ImportNode($pNode, $true))
            $policyImported = $true
        }
    }

    $sHosts = $sDoc.SelectNodes('/NessusClientData_v2/Report/ReportHost')
    foreach ($sHost in $sHosts) {
        $hKey = Get-HostKey -ReportHostElement $sHost -Mode $DeduplicationMode -SourceId $fName

        $tHost = $null
        if ($consolidatedHosts.ContainsKey($hKey)) {
            $tHost = $consolidatedHosts[$hKey]
            Merge-HostProperties -TargetHost $tHost -SourceHost $sHost -SourceFileName $fName
        }
        else {
            $tHost = $masterDoc.CreateElement("ReportHost")
            $tHost.SetAttribute("name", $sHost.GetAttribute("name"))

            $hProps = $sHost.SelectSingleNode("HostProperties")
            if ($null -ne $hProps) {
                $null = $tHost.AppendChild($masterDoc.ImportNode($hProps, $true))
            }

            $null = $masterReport.AppendChild($tHost)
            $consolidatedHosts[$hKey] = $tHost
            $hostFindings[$hKey] = [System.Collections.Generic.Dictionary[string, System.Xml.XmlElement]]::new([System.StringComparer]::OrdinalIgnoreCase)
            $hostFindingSource[$hKey] = [System.Collections.Generic.Dictionary[string, string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        }

        $fMap = $hostFindings[$hKey]
        $sMap = $hostFindingSource[$hKey]

        $sItems = $sHost.SelectNodes('ReportItem')
        foreach ($sItem in $sItems) {
            $findingsProcessed++
            $fKey = Get-FindingKey -ReportItem $sItem

            if ($DeduplicationMode -eq 'Safe' -and $fMap.ContainsKey($fKey)) {
                $tItem = $fMap[$fKey]
                $tSrc  = $sMap[$fKey]
                Merge-Findings -TargetItem $tItem -SourceItem $sItem -TargetSrc $tSrc -SourceSrc $fName
                $findingsDeduplicated++
            }
            else {
                $importedItem = $masterDoc.ImportNode($sItem, $true)
                $null = $tHost.AppendChild($importedItem)

                if ($DeduplicationMode -ne 'None') {
                    $storeKey = if ($DeduplicationMode -eq 'Safe') { $fKey } else { "$fKey|$([System.Guid]::NewGuid().ToString('N'))" }
                    $fMap[$storeKey] = $importedItem
                    $sMap[$storeKey] = $fName
                }
            }
        }
    }
}

$null = $rootElement.AppendChild($masterReport)

# 4. Atomic Output Writing & Validation
$uniqueFindings = $findingsProcessed - $findingsDeduplicated
$outDir = [System.IO.Path]::GetDirectoryName($resolvedOutputPath)
if (-not [string]::IsNullOrWhiteSpace($outDir) -and -not (Test-Path -LiteralPath $outDir)) {
    $null = New-Item -ItemType Directory -Path $outDir -Force
}

$tempFile = "$resolvedOutputPath.tmp.$([System.Guid]::NewGuid().ToString('N')).nessus"

try {
    Write-Log "Writing merged XML to temporary file..." -Level 'DEBUG'
    $writerSettings = [System.Xml.XmlWriterSettings]::new()
    $writerSettings.Indent = $true
    $writerSettings.IndentChars = "  "
    $writerSettings.Encoding = [System.Text.UTF8Encoding]::new($false)
    $writerSettings.CloseOutput = $true

    $writer = [System.Xml.XmlWriter]::Create($tempFile, $writerSettings)
    try {
        $masterDoc.Save($writer)
    }
    finally {
        $writer.Dispose()
    }

    # Validate generated output
    Write-Log "Validating generated output document..." -Level 'INFO'
    $outVal = Test-NessusXml -FilePath $tempFile
    if (-not $outVal.IsValid) {
        throw [System.InvalidOperationException]::new("Output XML failed validation: $($outVal.ErrorMessage)")
    }

    if ($outVal.HostCount -ne $consolidatedHosts.Count -or $outVal.FindingCount -ne $uniqueFindings) {
        throw [System.InvalidOperationException]::new("Output count mismatch (Expected Hosts: $($consolidatedHosts.Count), Found: $($outVal.HostCount); Expected Findings: $uniqueFindings, Found: $($outVal.FindingCount))")
    }

    # Finalize atomically
    if (Test-Path -LiteralPath $resolvedOutputPath) {
        Remove-Item -LiteralPath $resolvedOutputPath -Force
    }
    Move-Item -LiteralPath $tempFile -Destination $resolvedOutputPath -Force
    Write-Log "Successfully finalized output at '$resolvedOutputPath'" -Level 'SUCCESS'

    $finalStatus = if ($failedFiles.Count -eq 0) { 'SUCCESS' } else { 'FAILED' }
    $summary = @{
        InputFiles           = $inputFiles.Count
        ProcessedFiles       = $validFiles.Count
        FailedFiles          = $failedFiles.Count
        SourceHosts          = $sourceHostTotal
        ConsolidatedHosts    = $consolidatedHosts.Count
        FindingsProcessed    = $findingsProcessed
        FindingsDeduplicated = $findingsDeduplicated
        UniqueFindings       = $uniqueFindings
        Output               = $resolvedOutputPath
        Status               = $finalStatus
    }
    Show-Summary -Summary $summary

    if ($failedFiles.Count -gt 0) { exit 1 }
    exit 0
}
catch {
    Write-Log "Fatal error during output generation: $($_.Exception.Message)" -Level 'ERROR'
    if (Test-Path -LiteralPath $tempFile) {
        Remove-Item -LiteralPath $tempFile -Force -ErrorAction SilentlyContinue
    }
    $summary = @{
        InputFiles           = $inputFiles.Count
        ProcessedFiles       = $validFiles.Count
        FailedFiles          = $failedFiles.Count
        SourceHosts          = $sourceHostTotal
        ConsolidatedHosts    = $consolidatedHosts.Count
        FindingsProcessed    = $findingsProcessed
        FindingsDeduplicated = $findingsDeduplicated
        UniqueFindings       = $uniqueFindings
        Output               = $resolvedOutputPath
        Status               = 'FAILED'
    }
    Show-Summary -Summary $summary
    exit 1
}
