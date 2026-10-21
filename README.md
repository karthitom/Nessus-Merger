# Nessus Merge Tool

A simple, lightweight, single-file PowerShell utility to merge multiple Tenable Nessus (`.nessus` v2) XML scan reports into a single consolidated report.

---

## Project Structure

```text
nessus-merge-tool/
├── NessusMerge.ps1
└── README.md
```

---

## Prerequisites

- **PowerShell**: Windows PowerShell 5.1 or PowerShell 7+ (`pwsh`) on Windows, Linux, or macOS.
- **Dependencies**: None. Uses built-in .NET XML functionality (`System.Xml`).

---

## Default Behavior

When run without arguments, `NessusMerge.ps1`:
- Scans the **current directory** for all `.nessus` files.
- Automatically excludes the output report if already present.
- Loads the first report as the base report and appends all `ReportHost` elements from the remaining reports.
- Sets the report name to **`Merged Report`**.
- Saves the consolidated file as **`merged_nessus_report.nessus`** in the target directory.
- Preserves all original input files without modification.
- Employs safe XML parsing (DTD processing prohibited and external entity resolution disabled).

---

## Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-FilePath` | String | Current directory | Path to the directory containing `.nessus` scan files. |
| `-OutputFileName` | String | `merged_nessus_report.nessus` | File name or full path for the merged report. |
| `-ReportName` | String | `Merged Report` | Name assigned to the consolidated `<Report>` element. |

---

## Usage Examples

### 1. Run with Defaults

Merges all `.nessus` files in the current folder into `merged_nessus_report.nessus`:

```powershell
.\NessusMerge.ps1
```

### 2. Specify an Input Folder

Scans a specific directory for `.nessus` files:

```powershell
.\NessusMerge.ps1 -FilePath "D:\NessusScans"
```

### 3. Specify Custom Output File and Report Name

Provide custom input path, output filename, and report title:

```powershell
.\NessusMerge.ps1 `
  -FilePath "D:\NessusScans" `
  -OutputFileName "FinalReport.nessus" `
  -ReportName "Consolidated Security Report"
```
