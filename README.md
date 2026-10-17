# Nessus Merge Tool

[![CI Tests](https://github.com/example/nessus-merge-tool/actions/workflows/tests.yml/badge.svg)](https://github.com/example/nessus-merge-tool/actions)
[![PowerShell](https://img.shields.io/badge/PowerShell-7%2B%20%7C%205.1-blue.svg)](https://microsoft.com/powershell)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A high-performance, command-line-only utility designed for cybersecurity engineers and penetration testers to consolidate multiple Tenable Nessus (`.nessus` v2) XML scan files into a unified report.

Built exclusively using PowerShell and hardened .NET XML processing APIs (`System.Xml`), **Nessus Merge Tool** guarantees strict data integrity, zero external dependencies, robust host and vulnerability deduplication, and complete protection against XXE vulnerabilities.

---

## Key Features

- **Pure CLI Architecture**: Zero web dependencies, no Node/Python requirements, no GUI or cloud services. Runs locally in pure PowerShell.
- **Strict Data Integrity**: Guaranteed zero silent loss of vulnerability evidence, CVE references, CVSS ratings, or plugin output.
- **Safe Host Deduplication**: Intelligent host identity resolution using canonical IP address, FQDN, MAC, and NetBIOS heuristics.
- **Service & Port-Aware Finding Deduplication**: Vulnerabilities matching across scans on identical ports/protocols are consolidated; differing findings across distinct ports (e.g., port 80 vs 443) or protocols (TCP vs UDP) are strictly preserved.
- **Evidence Merging**: When multiple scans report the same vulnerability on a host with differing scan output, both outputs are cleanly preserved with source provenance demarcation.
- **Ambiguity Guard (`KeepSeparate`)**: Prevents improper consolidation of hosts with conflicting network identities or overlapping subnets.
- **Hardened XML Parser**: Enforces `DtdProcessing = Prohibit` and disables external entity resolvers (`XmlResolver = $null`) to neutralize XML External Entity (XXE) and billion-laughs expansion attacks.
- **Atomic File Writing**: Writes consolidated XML to a temporary file, verifies the output document against Nessus schema and count metrics, and atomically moves to the final destination.
- **Non-Destructive by Default**: Never modifies source files; protects existing destination files from accidental overwrite unless `-Force` is explicitly passed.
- **Pre-Flight Validation Mode**: Rapidly tests batches of `.nessus` files for XML well-formedness and schema integrity without generating output.
- **Informative Terminal Dashboard**: Displays a real-time progress stream and a structured summary box with calculated counts.

---

## Directory Structure

```
nessus-merge-tool/
├── src/
│   ├── NessusMerge.ps1        # Main CLI entry point & workflow orchestrator
│   ├── XmlValidator.ps1       # Hardened XML validation & XXE mitigation
│   ├── HostDeduplicator.ps1   # Canonical host key resolution & property merging
│   ├── FindingDeduplicator.ps1# Finding composite key matching & evidence consolidation
│   └── Logger.ps1             # CLI ASCII banner, formatted summary, & logging
├── tests/
│   ├── Merge.Tests.ps1        # Integration test suite for all CLI workflows
│   ├── Validation.Tests.ps1   # Unit test suite for XML parser and security checks
│   └── Fixtures/              # Synthetic Nessus scan fixtures
├── examples/
│   └── README.md              # Real-world usage scenarios and automation recipes
├── .github/
│   └── workflows/
│       └── tests.yml          # GitHub Actions CI matrix (Windows & Linux)
├── .gitignore                 # Excludes real customer scan files, reports, logs
├── LICENSE                    # MIT License
└── README.md                  # Complete documentation and specifications
```

---

## Prerequisites

- **PowerShell**: PowerShell 7+ (`pwsh`) or Windows PowerShell 5.1.
- **Runtime**: Built-in .NET Framework / .NET Core runtime (preinstalled on Windows, included with PowerShell on Linux/macOS).
- **Testing (Optional)**: Pester 5.0+ (`Install-Module -Name Pester -Scope CurrentUser`).

---

## Quick Start & CLI Usage

### 1. Merge All Scan Files in a Directory

Automatically discovers all `.nessus` files inside the target directory (recursively) and consolidates them:

```powershell
pwsh -File .\src\NessusMerge.ps1 `
  -InputPath ".\scans" `
  -OutputPath ".\reports\merged_network_audit.nessus"
```

### 2. Merge Explicitly Selected Files

Consolidate a specific list of scan files:

```powershell
pwsh -File .\src\NessusMerge.ps1 `
  -Files ".\scans\internal_dmz.nessus", ".\scans\internal_lan.nessus" `
  -OutputPath ".\reports\merged_corp.nessus"
```

### 3. Enable Safe Deduplication (Default)

Consolidate identical host records and combine differing plugin outputs into unified findings:

```powershell
pwsh -File .\src\NessusMerge.ps1 `
  -InputPath ".\scans" `
  -OutputPath ".\reports\merged_safe.nessus" `
  -DeduplicationMode Safe
```

### 4. Keep All Host Records Separate

Preserve every host record as an independent `<ReportHost>` entry without merging (recommended for multi-tenant or multi-VLAN overlapping IP scans):

```powershell
pwsh -File .\src\NessusMerge.ps1 `
  -InputPath ".\scans" `
  -OutputPath ".\reports\multi_tenant.nessus" `
  -KeepSeparate
```

### 5. Validate Input Files Without Merging

Scan and check all input files for syntax errors, missing `<Report>` tags, or schema issues without generating an output file:

```powershell
pwsh -File .\src\NessusMerge.ps1 `
  -InputPath ".\scans" `
  -ValidateOnly
```

### 6. Overwrite Existing Reports & Log to File

```powershell
pwsh -File .\src\NessusMerge.ps1 `
  -InputPath ".\scans" `
  -OutputPath ".\reports\daily_merged.nessus" `
  -LogPath ".\logs\daily_merge.log" `
  -Force
```

### 7. Display Help Menu

```powershell
pwsh -File .\src\NessusMerge.ps1 -Help
```

---

## Parameters

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `-InputPath` | `String[]` | Conditional | `None` | Path to a directory containing `.nessus` files or individual file paths. |
| `-Files` | `String[]` | Conditional | `None` | Array of explicit `.nessus` file paths. |
| `-OutputPath` | `String` | Yes* | `None` | Destination path for the consolidated `.nessus` report (*not required if `-ValidateOnly` is set). |
| `-DeduplicationMode` | `String` | No | `Safe` | Strategy: `Safe`, `None`, or `KeepSeparate`. |
| `-KeepSeparate` | `Switch` | No | `False` | Forces all host records to remain separate (equivalent to `-DeduplicationMode KeepSeparate`). |
| `-ValidateOnly` | `Switch` | No | `False` | Validates input scan files without generating a merged output file. |
| `-LogPath` | `String` | No | `None` | Optional file path to append execution and error logs. |
| `-Force` | `Switch` | No | `False` | Allows overwriting the destination file if it already exists. |
| `-Quiet` | `Switch` | No | `False` | Suppresses non-error console output (ideal for automation scripts). |
| `-Help` | `Switch` | No | `False` | Displays parameter documentation and usage examples. |

---

## Deduplication Architecture & Rules

### Host Identity Resolution Hierarchy

To accurately determine whether two `<ReportHost>` blocks represent the same machine, **Nessus Merge Tool** applies a prioritized identity hierarchy:

1. **Canonical IP Address**: Evaluates the `host-ip` tag in `<HostProperties>`, validating IPv4 and IPv6 format.
2. **ReportHost `name` Attribute**: If the attribute parses as a valid IP address.
3. **MAC Address**: Evaluates `mac-address` tag.
4. **Fully Qualified Domain Name (FQDN)**: Evaluates normalized lowercase `host-fqdn`.
5. **NetBIOS Name**: Evaluates normalized uppercase `netbios-name`.
6. **Hostname**: Evaluates normalized lowercase host name attribute.

#### Ambiguity Guard
If two host records share a name (e.g. `webserver`) but have conflicting IP addresses (`10.0.0.1` vs `192.168.1.1`), the tool detects the conflict and treats them as **separate hosts**, preventing cross-network data corruption.

### Host Metadata Merging
When two matching hosts are consolidated:
- **Scan Timestamps**: `HOST_START` adopts the earliest timestamp; `HOST_END` adopts the latest timestamp.
- **Host Tags**: Unique tags from both scans are unified.
- **Conflicting Metadata**: If tags conflict (e.g. differing operating system names), the primary value is retained and secondary values are recorded with source provenance tags (`<tag name="os_conflict_scanB">`).

### Finding Composite Keys & Evidence Consolidation

Each finding (`<ReportItem>`) is evaluated using a composite uniqueness key:

$$\text{FindingKey} = \text{PluginID} \parallel \text{Port} \parallel \text{Protocol} \parallel \text{ServiceName}$$

- **Distinct Ports/Protocols**: Findings for the same plugin on port `80` and port `443` produce distinct keys and are **never** collapsed.
- **Identical Findings**: If findings share the composite key and have identical `<plugin_output>`, the duplicate is deduplicated into a single `<ReportItem>`.
- **Differing Evidence**: If findings share the composite key but contain distinct `<plugin_output>` (e.g., credentialed scan revealed additional proof), the tool safely combines the plugin outputs:
  ```xml
  <plugin_output>
  [Source: network_scan.nessus]
  Port 445/tcp service banner found.

  ----------------------------------------
  [Source: credentialed_scan.nessus]
  Missing security update KB5001234 confirmed in registry.
  </plugin_output>
  ```
- **CVE & Reference Merging**: Child tags including `<cve>`, `<xref>`, `<see_also>`, and CVSS ratings are merged into a comprehensive set without duplicates.

---

## Terminal Summary Output

Upon completion, **Nessus Merge Tool** renders a clean summary table:

```
==========================================
       NESSUS MERGE TOOL SUMMARY
==========================================

Input files         : 4
Processed files     : 4
Failed files        : 0
Source host records : 152
Consolidated hosts  : 140
Findings processed  : 850
Findings deduplicated: 42
Unique findings     : 808

Output: .\reports\merged.nessus
Status: SUCCESS
==========================================
```

---

## Security & Reliability Architecture

- **XXE Prevention**: Strict prohibition of DTD processing (`DtdProcessing.Prohibit`) and entity resolution (`XmlResolver = $null`) prevents attacks such as CVE-2015-1828 / CWE-611.
- **Atomic Operations**: Merged data is written to a unique temporary file (`.tmp.<GUID>.nessus`). The temporary file is validated for Nessus schema compliance before moving to the destination.
- **Destructive Action Protection**: The output file is automatically excluded from the input list, and source files are never overwritten.
- **Confidentiality**: All processing occurs strictly on the local machine. Scan data is never transmitted over external networks or third-party APIs.

---

## Exit Codes

| Exit Code | Meaning |
|---|---|
| `0` | Success: All input files were processed and the merged file was validated. |
| `1` | Error: Validation failed, invalid parameters provided, or fatal error encountered. |

---

## Running Automated Tests

Run the full Pester test suite covering unit validation and end-to-end merge scenarios:

```powershell
# Run all tests
Invoke-Pester -Path .\tests -Output Detailed

# Run validation suite only
Invoke-Pester -Path .\tests\Validation.Tests.ps1 -Output Detailed

# Run merge integration suite only
Invoke-Pester -Path .\tests\Merge.Tests.ps1 -Output Detailed
```

---

## Known Limitations

- **Report Memory Footprint**: Uses .NET `System.Xml.XmlDocument` for deep document validation and cross-host node manipulation. Scanning massive batches totaling tens of gigabytes of XML requires appropriate RAM allocation.
- **Nessus Format Version**: Optimized for Nessus v2 XML format (`<NessusClientData_v2>`), which is the standard format used by Tenable Nessus, Tenable SecurityCenter, and Tenable.io exports.

---

## License

This project is licensed under the [MIT License](LICENSE).
