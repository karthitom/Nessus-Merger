<#
.SYNOPSIS
    XML Validator module for Nessus Merge Tool.
.DESCRIPTION
    Provides hardened XML parsing, validation of Nessus XML v2 schema/elements,
    mitigation against XXE (XML External Entity) and entity expansion attacks,
    and verification of generated output files.
#>

function Get-SafeXmlReaderSettings {
    [CmdletBinding()]
    param()

    $settings = [System.Xml.XmlReaderSettings]::new()
    $settings.DtdProcessing = [System.Xml.DtdProcessing]::Prohibit
    $settings.XmlResolver = $null
    $settings.MaxCharactersFromEntities = 0
    $settings.IgnoreComments = $false
    $settings.IgnoreWhitespace = $false
    return $settings
}

function Test-NessusXmlFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$FilePath
    )

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

        # Move to root element
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

        # Scan through the document to count ReportHosts, ReportItems, and ensure Report element exists
        $hasReport = $false
        $hostCount = 0
        $findingCount = 0

        while ($reader.Read()) {
            if ($reader.NodeType -eq [System.Xml.XmlNodeType]::Element) {
                if ($reader.LocalName -eq 'Report') {
                    $hasReport = $true
                }
                elseif ($reader.LocalName -eq 'ReportHost') {
                    $hostCount++
                }
                elseif ($reader.LocalName -eq 'ReportItem') {
                    $findingCount++
                }
            }
        }

        if (-not $hasReport) {
            $result.ErrorMessage = "Missing required '<Report>' element in Nessus scan."
            return $result
        }

        $result.IsValid = $true
        $result.HostCount = $hostCount
        $result.FindingCount = $findingCount
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
        if ($null -ne $reader) {
            $reader.Dispose()
        }
    }
}

function Load-SafeNessusDocument {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$FilePath
    )

    if (-not (Test-Path -LiteralPath $FilePath -PathType Leaf)) {
        throw [System.IO.FileNotFoundException]::new("File not found: '$FilePath'")
    }

    $settings = Get-SafeXmlReaderSettings
    $reader = [System.Xml.XmlReader]::Create($FilePath, $settings)

    try {
        $doc = [System.Xml.XmlDocument]::new()
        $doc.XmlResolver = $null
        $doc.Load($reader)
        return $doc
    }
    finally {
        if ($null -ne $reader) {
            $reader.Dispose()
        }
    }
}

function Test-MergedNessusOutput {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$FilePath,

        [Parameter(Mandatory = $false)]
        [int]$ExpectedHosts = -1,

        [Parameter(Mandatory = $false)]
        [int]$ExpectedFindings = -1
    )

    $validation = Test-NessusXmlFile -FilePath $FilePath
    if (-not $validation.IsValid) {
        return [PSCustomObject]@{
            IsValid      = $false
            ErrorMessage = "Output validation failed: $($validation.ErrorMessage)"
            HostCount    = $validation.HostCount
            FindingCount = $validation.FindingCount
        }
    }

    if ($ExpectedHosts -ge 0 -and $validation.HostCount -ne $ExpectedHosts) {
        return [PSCustomObject]@{
            IsValid      = $false
            ErrorMessage = "Output host count mismatch: expected $ExpectedHosts, found $($validation.HostCount)"
            HostCount    = $validation.HostCount
            FindingCount = $validation.FindingCount
        }
    }

    if ($ExpectedFindings -ge 0 -and $validation.FindingCount -ne $ExpectedFindings) {
        return [PSCustomObject]@{
            IsValid      = $false
            ErrorMessage = "Output finding count mismatch: expected $ExpectedFindings, found $($validation.FindingCount)"
            HostCount    = $validation.HostCount
            FindingCount = $validation.FindingCount
        }
    }

    return [PSCustomObject]@{
        IsValid      = $true
        ErrorMessage = $null
        HostCount    = $validation.HostCount
        FindingCount = $validation.FindingCount
    }
}
