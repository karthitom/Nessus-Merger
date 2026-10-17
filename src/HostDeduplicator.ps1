<#
.SYNOPSIS
    Host Deduplicator module for Nessus Merge Tool.
.DESCRIPTION
    Provides host identity resolution, canonical key generation, ambiguity detection,
    and safe merging of HostProperties metadata across consolidated hosts.
#>

function Get-HostPropertiesTable {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Xml.XmlElement]$ReportHostElement
    )

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
    return $props
}

function Test-IsIpAddress {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$Value
    )

    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    $ip = $null
    return [System.Net.IPAddress]::TryParse($Value.Trim(), [ref]$ip)
}

function Get-CanonicalHostKey {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Xml.XmlElement]$ReportHostElement,

        [Parameter(Mandatory = $false)]
        [string]$DeduplicationMode = 'Safe',

        [Parameter(Mandatory = $false)]
        [string]$SourceIdentifier = 'source'
    )

    $hostName = $ReportHostElement.GetAttribute('name')
    if ($null -eq $hostName) { $hostName = '' }
    $hostName = $hostName.Trim()

    # In 'None' or 'KeepSeparate' mode, generate a unique key per source occurrence
    if ($DeduplicationMode -eq 'None' -or $DeduplicationMode -eq 'KeepSeparate') {
        return "$SourceIdentifier::HOST::$hostName::$([System.Guid]::NewGuid().ToString('N'))"
    }

    $props = Get-HostPropertiesTable -ReportHostElement $ReportHostElement
    $hostIp = if ($props.ContainsKey('host-ip')) { $props['host-ip'].Trim() } else { '' }
    $hostFqdn = if ($props.ContainsKey('host-fqdn')) { $props['host-fqdn'].Trim().ToLowerInvariant() } else { '' }
    $netbios = if ($props.ContainsKey('netbios-name')) { $props['netbios-name'].Trim().ToUpperInvariant() } else { '' }
    $mac = if ($props.ContainsKey('mac-address')) { $props['mac-address'].Trim().ToLowerInvariant() } else { '' }

    # Check for ambiguity: if hostname is an IP, but host-ip tag is different IP
    if ((Test-IsIpAddress -Value $hostName) -and -not [string]::IsNullOrWhiteSpace($hostIp) -and (Test-IsIpAddress -Value $hostIp)) {
        if ($hostName -ne $hostIp) {
            # Ambiguous identity! Keep separate to prevent incorrect consolidation
            return "AMBIGUOUS::$SourceIdentifier::$hostName::$hostIp::$([System.Guid]::NewGuid().ToString('N'))"
        }
    }

    # Primary key: IP address
    if (Test-IsIpAddress -Value $hostIp) {
        return "IP::$hostIp"
    }
    if (Test-IsIpAddress -Value $hostName) {
        return "IP::$hostName"
    }

    # Secondary: MAC address if present
    if (-not [string]::IsNullOrWhiteSpace($mac)) {
        return "MAC::$mac"
    }

    # Tertiary: FQDN
    if (-not [string]::IsNullOrWhiteSpace($hostFqdn)) {
        return "FQDN::$hostFqdn"
    }

    # Quaternary: NetBIOS
    if (-not [string]::IsNullOrWhiteSpace($netbios)) {
        return "NETBIOS::$netbios"
    }

    # Fallback: Hostname attribute
    if (-not [string]::IsNullOrWhiteSpace($hostName)) {
        return "NAME::$($hostName.ToLowerInvariant())"
    }

    # Anonymous host
    return "ANONYMOUS::$SourceIdentifier::$([System.Guid]::NewGuid().ToString('N'))"
}

function Merge-HostProperties {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Xml.XmlElement]$TargetHost,

        [Parameter(Mandatory = $true)]
        [System.Xml.XmlElement]$SourceHost,

        [Parameter(Mandatory = $false)]
        [string]$SourceFileName = 'source'
    )

    $doc = $TargetHost.OwnerDocument

    $targetPropsNode = $TargetHost.SelectSingleNode('HostProperties')
    if ($null -eq $targetPropsNode) {
        $targetPropsNode = $doc.CreateElement('HostProperties')
        $null = $TargetHost.PrependChild($targetPropsNode)
    }

    $sourcePropsNode = $SourceHost.SelectSingleNode('HostProperties')
    if ($null -eq $sourcePropsNode) { return }

    # Map existing target tags
    $targetTags = @{}
    foreach ($tag in $targetPropsNode.SelectNodes('tag')) {
        $name = $tag.GetAttribute('name')
        if (-not [string]::IsNullOrEmpty($name)) {
            $targetTags[$name] = $tag
        }
    }

    foreach ($sourceTag in $sourcePropsNode.SelectNodes('tag')) {
        $tagName = $sourceTag.GetAttribute('name')
        if ([string]::IsNullOrEmpty($tagName)) { continue }
        $sourceVal = $sourceTag.InnerText

        if (-not $targetTags.ContainsKey($tagName)) {
            # Tag doesn't exist in target - import it
            $importedTag = $doc.ImportNode($sourceTag, $true)
            $null = $targetPropsNode.AppendChild($importedTag)
            $targetTags[$tagName] = $importedTag
        }
        else {
            $existingTag = $targetTags[$tagName]
            $existingVal = $existingTag.InnerText

            if ($existingVal -eq $sourceVal) {
                # Identical value, keep as is
                continue
            }

            # Handle timestamps: HOST_START (earliest) and HOST_END (latest)
            if ($tagName -eq 'HOST_START') {
                $dtTarget = $null
                $dtSource = $null
                if ([DateTime]::TryParse($existingVal, [ref]$dtTarget) -and [DateTime]::TryParse($sourceVal, [ref]$dtSource)) {
                    if ($dtSource -lt $dtTarget) {
                        $existingTag.InnerText = $sourceVal
                    }
                }
            }
            elseif ($tagName -eq 'HOST_END') {
                $dtTarget = $null
                $dtSource = $null
                if ([DateTime]::TryParse($existingVal, [ref]$dtTarget) -and [DateTime]::TryParse($sourceVal, [ref]$dtSource)) {
                    if ($dtSource -gt $dtTarget) {
                        $existingTag.InnerText = $sourceVal
                    }
                }
            }
            else {
                # Conflicting property: Preserve conflicting value with source annotation
                $sanitizedSource = ($SourceFileName -replace '[^a-zA-Z0-9_\-]', '_')
                $conflictTagName = "$tagName`_conflict_$sanitizedSource"
                
                # Check if conflict tag already exists
                if (-not $targetTags.ContainsKey($conflictTagName)) {
                    $conflictTag = $doc.CreateElement('tag')
                    $conflictTag.SetAttribute('name', $conflictTagName)
                    $conflictTag.InnerText = $sourceVal
                    $null = $targetPropsNode.AppendChild($conflictTag)
                    $targetTags[$conflictTagName] = $conflictTag
                }
            }
        }
    }
}
