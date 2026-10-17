<#
.SYNOPSIS
    Logger module for Nessus Merge Tool.
.DESCRIPTION
    Provides formatted console output, ASCII banners, processing summaries,
    and optional persistent file logging.
#>

$script:NessusLogFilePath = $null
$script:NessusQuietMode = $false

function Initialize-NessusLogger {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$LogPath,

        [Parameter(Mandatory = $false)]
        [switch]$Quiet
    )

    $script:NessusQuietMode = $Quiet.IsPresent

    if (-not [string]::IsNullOrWhiteSpace($LogPath)) {
        try {
            $resolvedPath = [System.IO.Path]::GetFullPath($LogPath)
            $logDir = [System.IO.Path]::GetDirectoryName($resolvedPath)
            if (-not [string]::IsNullOrWhiteSpace($logDir) -and -not (Test-Path -LiteralPath $logDir)) {
                $null = New-Item -ItemType Directory -Path $logDir -Force
            }
            $script:NessusLogFilePath = $resolvedPath
            
            $header = "[{0:yyyy-MM-dd HH:mm:ss}] [INFO] Nessus Merge Tool Logger Initialized. Target: {1}" -f (Get-Date), $resolvedPath
            [System.IO.File]::AppendAllText($script:NessusLogFilePath, "$header`r`n", [System.Text.Encoding]::UTF8)
        }
        catch {
            Write-Warning "Failed to initialize log file at '$LogPath': $($_.Exception.Message)"
            $script:NessusLogFilePath = $null
        }
    }
}

function Write-NessusLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Message,

        [Parameter(Mandatory = $false)]
        [ValidateSet('INFO', 'SUCCESS', 'WARN', 'ERROR', 'DEBUG')]
        [string]$Level = 'INFO'
    )

    $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $logEntry = "[$timestamp] [$Level] $Message"

    # Write to file if configured
    if (-not [string]::IsNullOrWhiteSpace($script:NessusLogFilePath)) {
        try {
            [System.IO.File]::AppendAllText($script:NessusLogFilePath, "$logEntry`r`n", [System.Text.Encoding]::UTF8)
        }
        catch {
            # Ignore file logging failures to not disrupt processing
        }
    }

    # Write to console unless quiet (ERROR always displays)
    if ($script:NessusQuietMode -and $Level -ne 'ERROR') {
        return
    }

    switch ($Level) {
        'SUCCESS' { Write-Host $logEntry -ForegroundColor Green }
        'WARN'    { Write-Host $logEntry -ForegroundColor Yellow }
        'ERROR'   { Write-Host $logEntry -ForegroundColor Red }
        'DEBUG'   { Write-Verbose $logEntry }
        default   { Write-Host $logEntry -ForegroundColor Cyan }
    }
}

function Show-NessusBanner {
    if ($script:NessusQuietMode) { return }

    $banner = @"
==========================================
       NESSUS MERGE TOOL
==========================================
"@
    Write-Host $banner -ForegroundColor DarkCyan
}

function Show-NessusSummary {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Summary
    )

    if ($script:NessusQuietMode) { return }

    $statusColor = if ($Summary.Status -eq 'SUCCESS') { 'Green' } elseif ($Summary.Status -eq 'VALIDATION-ONLY') { 'Cyan' } else { 'Red' }

    $outputStr = if ($Summary.ContainsKey('Output') -and -not [string]::IsNullOrWhiteSpace($Summary.Output)) {
        "Output: $($Summary.Output)`r`n"
    } else {
        ""
    }

    $summaryBox = @"

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

$($outputStr)Status: $($Summary.Status)
==========================================
"@
    Write-Host $summaryBox -ForegroundColor $statusColor
}
