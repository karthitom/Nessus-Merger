<#
.SYNOPSIS
    Finding Deduplicator module for Nessus Merge Tool.
.DESCRIPTION
    Provides composite key generation, port/protocol preservation,
    and safe consolidation of duplicate ReportItem findings without data loss.
#>

function Get-FindingCompositeKey {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Xml.XmlElement]$ReportItemElement
    )

    $pluginId = $ReportItemElement.GetAttribute('pluginID')
    $port     = $ReportItemElement.GetAttribute('port')
    $protocol = $ReportItemElement.GetAttribute('protocol')
    $svcName  = $ReportItemElement.GetAttribute('svc_name')

    if ($null -eq $pluginId) { $pluginId = '' }
    if ($null -eq $port) { $port = '0' }
    if ($null -eq $protocol) { $protocol = 'tcp' }
    if ($null -eq $svcName) { $svcName = '' }

    return "$($pluginId.Trim())|$($port.Trim())|$($protocol.Trim().ToLowerInvariant())|$($svcName.Trim().ToLowerInvariant())"
}

function Merge-ReportItems {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Xml.XmlElement]$TargetItem,

        [Parameter(Mandatory = $true)]
        [System.Xml.XmlElement]$SourceItem,

        [Parameter(Mandatory = $false)]
        [string]$TargetSourceName = 'Existing',

        [Parameter(Mandatory = $false)]
        [string]$SourceFileName = 'Incoming'
    )

    $doc = $TargetItem.OwnerDocument

    # 1. Compare and update severity to highest if different
    $targetSev = 0
    $sourceSev = 0
    [int]::TryParse($TargetItem.GetAttribute('severity'), [ref]$targetSev) | Out-Null
    [int]::TryParse($SourceItem.GetAttribute('severity'), [ref]$sourceSev) | Out-Null

    if ($sourceSev -gt $targetSev) {
        $TargetItem.SetAttribute('severity', $sourceSev.ToString())
    }

    # 2. Merge plugin_output safely
    $targetOutputNode = $TargetItem.SelectSingleNode('plugin_output')
    $sourceOutputNode = $SourceItem.SelectSingleNode('plugin_output')

    if ($null -ne $sourceOutputNode) {
        $sourceText = $sourceOutputNode.InnerText
        if ($null -eq $targetOutputNode) {
            $importedOutput = $doc.ImportNode($sourceOutputNode, $true)
            $null = $TargetItem.AppendChild($importedOutput)
        }
        else {
            $targetText = $targetOutputNode.InnerText
            if ($targetText.Trim() -ne $sourceText.Trim() -and -not [string]::IsNullOrWhiteSpace($sourceText)) {
                # Distinct outputs - combine with clear provenance separation
                $combinedText = @"
[Source: $TargetSourceName]
$($targetText.Trim())

----------------------------------------
[Source: $SourceFileName]
$($sourceText.Trim())
"@
                $targetOutputNode.InnerText = $combinedText
            }
        }
    }

    # 3. Merge CVEs (preserve all unique CVEs)
    $targetCves = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($cveNode in $TargetItem.SelectNodes('cve')) {
        if (-not [string]::IsNullOrWhiteSpace($cveNode.InnerText)) {
            $null = $targetCves.Add($cveNode.InnerText.Trim())
        }
    }

    foreach ($sourceCveNode in $SourceItem.SelectNodes('cve')) {
        $cveVal = $sourceCveNode.InnerText.Trim()
        if (-not [string]::IsNullOrWhiteSpace($cveVal) -and -not $targetCves.Contains($cveVal)) {
            $importedCve = $doc.ImportNode($sourceCveNode, $true)
            $null = $TargetItem.AppendChild($importedCve)
            $null = $targetCves.Add($cveVal)
        }
    }

    # 4. Merge xrefs (preserve all unique references)
    $targetXrefs = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($xrefNode in $TargetItem.SelectNodes('xref')) {
        if (-not [string]::IsNullOrWhiteSpace($xrefNode.InnerText)) {
            $null = $targetXrefs.Add($xrefNode.InnerText.Trim())
        }
    }

    foreach ($sourceXrefNode in $SourceItem.SelectNodes('xref')) {
        $xrefVal = $sourceXrefNode.InnerText.Trim()
        if (-not [string]::IsNullOrWhiteSpace($xrefVal) -and -not $targetXrefs.Contains($xrefVal)) {
            $importedXref = $doc.ImportNode($sourceXrefNode, $true)
            $null = $TargetItem.AppendChild($importedXref)
            $null = $targetXrefs.Add($xrefVal)
        }
    }

    # 5. Merge see_also links
    $targetSeeAlso = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($saNode in $TargetItem.SelectNodes('see_also')) {
        if (-not [string]::IsNullOrWhiteSpace($saNode.InnerText)) {
            $null = $targetSeeAlso.Add($saNode.InnerText.Trim())
        }
    }

    foreach ($sourceSaNode in $SourceItem.SelectNodes('see_also')) {
        $saVal = $sourceSaNode.InnerText.Trim()
        if (-not [string]::IsNullOrWhiteSpace($saVal) -and -not $targetSeeAlso.Contains($saVal)) {
            $importedSa = $doc.ImportNode($sourceSaNode, $true)
            $null = $TargetItem.AppendChild($importedSa)
            $null = $targetSeeAlso.Add($saVal)
        }
    }

    # 6. Fill in missing CVSS scores if target lacks them
    foreach ($cvssField in @('cvss_base_score', 'cvss3_base_score', 'cvss_vector', 'cvss3_vector', 'cvss_temporal_score')) {
        $targetField = $TargetItem.SelectSingleNode($cvssField)
        $sourceField = $SourceItem.SelectSingleNode($cvssField)
        if ($null -eq $targetField -and $null -ne $sourceField) {
            $importedField = $doc.ImportNode($sourceField, $true)
            $null = $TargetItem.AppendChild($importedField)
        }
    }
}
