# Nessus Merge Tool

A simple, lightweight, single-file PowerShell CLI utility to merge and deduplicate multiple Tenable Nessus (`.nessus` v2) XML scan reports into a single consolidated file.

Designed for cybersecurity professionals, penetration testers, and vulnerability management engineers who need a reliable, self-contained tool without external dependencies, complex setups, or web services.

---

## Key Features

- **Single-Script Design**: The entire tool lives inside `NessusMerge.ps1`. No modules to import, no package managers, and no external dependencies.
- **Safe Deduplication**: Automatically merges matching host records and combines duplicate findings on the same port/service without losing distinct vulnerability evidence or plugin outputs.
- **Port & Protocol Isolation**: Findings across different ports (e.g., port 80 vs 443) or protocols (TCP vs UDP) are strictly kept separate.
- **Ambiguity Guard**: Keeps hosts with conflicting network identities (e.g., identical hostnames but differing IP addresses) separate to prevent data corruption.
- **Secure XML Processing**: Built on .NET's hardened `System.Xml` APIs with external entity resolution and DTD processing disabled to prevent XML External Entity (XXE) attacks.
- **Pre-Flight Validation**: Rapidly checks batches of scan files for syntax errors and Nessus schema validity using `-ValidateOnly` without creating an output file.
- **Atomic File Writing**: Writes merged data to a temporary file, verifies the output document, and only then finalizes the destination file.
- **Clear Terminal Summary**: Displays real-time progress and a clean summary box with accurate calculated metrics.

---

## Project Structure

```text
nessus-merge-tool/
├── NessusMerge.ps1
└── README.md
```

Everything required to run and maintain the project is contained in these two files.

---

## Prerequisites

- **PowerShell**: PowerShell 7+ (`pwsh`) or Windows PowerShell 5.1.
- **Operating System**: Windows, Linux, or macOS.
- **Dependencies**: None. Uses built-in .NET XML processing (`System.Xml`).

---

## Installation & Setup

Clone the repository or download `NessusMerge.ps1`:

```powershell
git clone https://github.com/karthitom/Nessus-Merger.git
cd Nessus-Merger
```

---

## CLI Usage

### 1. Merge All Scans in a Folder

Scan an entire folder and merge all discovered `.nessus` files into a single report:

```powershell
pwsh -File .\NessusMerge.ps1 `
  -InputPath ".\scans" `
  -OutputPath ".\merged.nessus"
```

### 2. Merge Selected Files

Merge specific scan files by providing their paths:

```powershell
pwsh -File .\NessusMerge.ps1 `
  -Files ".\scan1.nessus", ".\scan2.nessus" `
  -OutputPath ".\merged.nessus"
```

### 3. Validate Scan Files Without Merging

Check all scan files in a folder for XML errors or missing Nessus elements without creating an output file:

```powershell
pwsh -File .\NessusMerge.ps1 `
  -InputPath ".\scans" `
  -ValidateOnly
```

### 4. Overwrite Existing Output & Save Log

Use `-Force` to allow overwriting an existing output report and `-LogPath` to record operations:

```powershell
pwsh -File .\NessusMerge.ps1 `
  -InputPath ".\scans" `
  -OutputPath ".\reports\merged.nessus" `
  -LogPath ".\logs\merge.log" `
  -Force
```

### 5. Keep All Hosts Separate

Disable host consolidation (recommended for multi-tenant scans with overlapping private IP addresses):

```powershell
pwsh -File .\NessusMerge.ps1 `
  -InputPath ".\scans" `
  -OutputPath ".\merged.nessus" `
  -KeepSeparate
```

### 6. Show Help

```powershell
pwsh -File .\NessusMerge.ps1 -Help
```

---

## Parameter Reference

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `-InputPath` | `String[]` | No* | `None` | Folder containing `.nessus` files or paths to individual scan files. |
| `-Files` | `String[]` | No* | `None` | Array or comma-separated list of explicit `.nessus` files. |
| `-OutputPath` | `String` | Yes** | `None` | Destination path for the consolidated `.nessus` report. |
| `-DeduplicationMode` | `String` | No | `Safe` | Deduplication strategy: `Safe` (default), `None`, or `KeepSeparate`. |
| `-KeepSeparate` | `Switch` | No | `False` | Forces all host records to remain separate. |
| `-ValidateOnly` | `Switch` | No | `False` | Validates input files without generating an output file. |
| `-LogPath` | `String` | No | `None` | Optional file path to append execution and error logs. |
| `-Force` | `Switch` | No | `False` | Overwrite destination file if it already exists. |
| `-Quiet` | `Switch` | No | `False` | Suppresses non-error console output. |
| `-Help` | `Switch` | No | `False` | Displays the help menu and parameter reference. |

*\* Either `-InputPath` or `-Files` must be provided.*  
*\*\* `-OutputPath` is required unless `-ValidateOnly` is used.*

---

## Terminal Summary

After processing, `NessusMerge.ps1` displays a clear summary of actual counts:

```text
==========================================
       NESSUS MERGE TOOL SUMMARY
==========================================

Input files         : 4
Processed files     : 4
Failed files        : 0
Source host records : 28
Consolidated hosts  : 20
Findings processed  : 142
Findings deduplicated: 18
Unique findings     : 124

Output: .\merged.nessus
Status: SUCCESS
==========================================
```

---

## Deduplication Rules

1. **Host Identification**:
   - Primary: Canonical IP address (`host-ip` tag or ReportHost `name` attribute).
   - Secondary: MAC address (`mac-address` tag).
   - Tertiary: Fully Qualified Domain Name (`host-fqdn`).
   - Quaternary: NetBIOS name (`netbios-name`).
   - Fallback: Hostname attribute.
   - Ambiguity: If two hosts share a hostname but have different IP addresses, they are kept as separate host records.

2. **Host Metadata Merging**:
   - `HOST_START`: Takes the earliest scan start time.
   - `HOST_END`: Takes the latest scan end time.
   - Conflicting properties are preserved with source annotations (e.g. `operating-system_conflict_scan2`).

3. **Finding Identification**:
   - Identity key: `PluginID | Port | Protocol | ServiceName`.
   - Distinct services, ports, and protocols are never merged together.

4. **Finding Evidence Merging**:
   - If findings on the same host share the same identity key and identical `plugin_output`, they are deduplicated.
   - If `plugin_output` differs between scans, both outputs are combined with source headers so that proof of vulnerability is never lost.
   - Distinct CVEs, reference URLs, and highest CVSS scores are preserved.

---

## Exit Codes

| Exit Code | Meaning |
|---|---|
| `0` | Success: All input files were processed and the merged file was validated. |
| `1` | Error: Validation failed, required parameters were missing, or processing encountered an error. |

---

## Security & Privacy Considerations

- **Local Processing**: All scanning data is processed locally on your machine. Scan data is never transmitted over the internet.
- **XXE Protection**: Built-in .NET XML readers prohibit DTD processing (`DtdProcessing.Prohibit`) and entity resolvers (`XmlResolver = $null`).
- **Source Protection**: Source files are opened read-only and never modified. The output file is automatically excluded from input discovery.
- **Atomic Operations**: Merged data is validated before replacing the target file, ensuring failed operations never leave corrupt reports.

---

## Known Limitations

- **Nessus XML Version**: Designed for Nessus v2 XML format (`<NessusClientData_v2>`), the standard format used by Tenable Nessus, Tenable SecurityCenter, and Tenable.io exports.
- **Memory Considerations**: Loads XML files into memory for deep validation. For exceptionally large batches (tens of gigabytes), ensure adequate system RAM.

---

## License

This project is open-source and released under the [MIT License](https://opensource.org/licenses/MIT).
