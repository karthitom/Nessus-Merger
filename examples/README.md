# Nessus Merge Tool - Examples & Workflows

This directory provides concrete, real-world command-line examples and automation recipes for common vulnerability assessment workflows using **Nessus Merge Tool**.

---

## Example 1: Consolidation of Multi-Segment Network Scans

When scanning large enterprise networks partitioned across multiple subnets, Nessus typically produces separate scan files for each segment (e.g., DMZ, Internal LAN, Management VLAN).

To merge all scans within a folder into a single unified audit report:

```powershell
pwsh -File .\src\NessusMerge.ps1 `
  -InputPath ".\scans\quarterly_audit" `
  -OutputPath ".\reports\unified_quarterly_audit.nessus" `
  -DeduplicationMode Safe `
  -LogPath ".\logs\audit_merge.log"
```

---

## Example 2: Merging Credentialed and Non-Credentialed Scans

Security teams frequently run an uncredentialed network discovery scan followed by a deep credentialed scan. The same hosts will be reported in both scans, but the credentialed scan will contain deeper plugin outputs and additional CVEs.

In `Safe` mode, **Nessus Merge Tool** matches the hosts by IP/FQDN and merges the finding records:
- Duplicate findings with identical evidence are consolidated into a single finding.
- Differing plugin evidence (e.g. detailed patch info) is safely combined with source markers.
- Distinct CVEs and CVSS scores are united.

```powershell
pwsh -File .\src\NessusMerge.ps1 `
  -Files ".\scans\uncredentialed.nessus", ".\scans\credentialed.nessus" `
  -OutputPath ".\reports\comprehensive_host_profile.nessus"
```

---

## Example 3: Pre-Flight Scan Validation

Before processing or ingesting scan files into SIEM or compliance systems, verify the health and integrity of all `.nessus` XML files without modifying or generating output files:

```powershell
pwsh -File .\src\NessusMerge.ps1 `
  -InputPath ".\incoming_scans" `
  -ValidateOnly
```

If any files contain malformed XML, missing `<Report>` blocks, or invalid root elements, the command displays the exact error and exits with code `1`.

---

## Example 4: Preserving Full Scan Provenance (`KeepSeparate` Mode)

If you have overlapping scans from different time periods or different customer environments where hosts may share private IPs (e.g., `192.168.1.1` in Customer A vs Customer B), run in `KeepSeparate` mode to ensure no host records are merged together:

```powershell
pwsh -File .\src\NessusMerge.ps1 `
  -InputPath ".\multi_tenant_scans" `
  -OutputPath ".\reports\multi_tenant_consolidated.nessus" `
  -DeduplicationMode KeepSeparate `
  -Force
```

---

## Example 5: Continuous Integration / Scheduled Pipeline

Integrate into automated CI/CD security validation scripts:

```powershell
$result = pwsh -File .\src\NessusMerge.ps1 `
  -InputPath "$env:WORKSPACE\artifacts\scans" `
  -OutputPath "$env:WORKSPACE\artifacts\consolidated.nessus" `
  -Force `
  -Quiet

if ($LASTEXITCODE -ne 0) {
    Write-Error "Nessus scan consolidation pipeline failed!"
    exit $LASTEXITCODE
}
```
