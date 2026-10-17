<#
.SYNOPSIS
    Pester test suite for Nessus Merge Tool core features and CLI workflows.
#>

BeforeAll {
    $scriptDir = Split-Path -Parent $PSScriptRoot
    $cliScript = Join-Path $scriptDir "src\NessusMerge.ps1"
    $fixtureDir = Join-Path $PSScriptRoot "Fixtures"
    . (Join-Path $scriptDir "src\XmlValidator.ps1")
}

Describe "Nessus Merge Tool - CLI & Core Features" {

    Context "Single File Input" {
        It "Processes and validates a single input scan" {
            $outFile = Join-Path $TestDrive "single_out.nessus"
            $file1 = Join-Path $fixtureDir "valid_scan1.nessus"

            & $cliScript -Files @($file1) -OutputPath $outFile -Force
            $LASTEXITCODE | Should -Be 0

            Test-Path -LiteralPath $outFile | Should -BeTrue
            $val = Test-NessusXmlFile -FilePath $outFile
            $val.IsValid | Should -BeTrue
            $val.HostCount | Should -Be 2
            $val.FindingCount | Should -Be 3
        }
    }

    Context "Multiple Files Input & Deduplication" {
        It "Consolidates multiple scans with Safe deduplication" {
            $outFile = Join-Path $TestDrive "multi_out.nessus"
            $file1 = Join-Path $fixtureDir "valid_scan1.nessus"
            $file2 = Join-Path $fixtureDir "valid_scan2.nessus"

            # scan1: 2 hosts (192.168.1.10, 192.168.1.20), 3 findings
            # scan2: 2 hosts (192.168.1.10, 192.168.1.30), 3 findings
            # Overlapping host: 192.168.1.10 -> consolidated into 1 host
            # Consolidated hosts: 3 (192.168.1.10, 192.168.1.20, 192.168.1.30)
            # Findings on 192.168.1.10:
            # - Plugin 10001 (port 445): exact duplicate -> deduplicated to 1
            # - Plugin 10002 (port 80 in scan1, port 443 in scan2): DIFFERENT PORTS -> preserved as 2 findings!
            # - Plugin 10004 (port 445 in scan2): distinct plugin -> 1 finding
            # Total unique findings = 3 (on .10) + 1 (on .20) + 1 (on .30) = 5 findings.

            & $cliScript -Files @($file1, $file2) -OutputPath $outFile -DeduplicationMode Safe -Force
            $LASTEXITCODE | Should -Be 0

            Test-Path -LiteralPath $outFile | Should -BeTrue
            $val = Test-NessusXmlFile -FilePath $outFile
            $val.IsValid | Should -BeTrue
            $val.HostCount | Should -Be 3
            $val.FindingCount | Should -Be 6
        }

        It "Preserves distinct findings on different ports for the same plugin ID" {
            $outFile = Join-Path $TestDrive "ports_out.nessus"
            $file1 = Join-Path $fixtureDir "valid_scan1.nessus"
            $file2 = Join-Path $fixtureDir "valid_scan2.nessus"

            & $cliScript -Files @($file1, $file2) -OutputPath $outFile -DeduplicationMode Safe -Force

            $doc = Load-SafeNessusDocument -FilePath $outFile
            $host10 = $doc.SelectSingleNode("//ReportHost[@name='192.168.1.10']")
            $host10 | Should -Not -BeNullOrEmpty

            $port80 = $host10.SelectSingleNode("ReportItem[@pluginID='10002' and @port='80']")
            $port443 = $host10.SelectSingleNode("ReportItem[@pluginID='10002' and @port='443']")

            $port80 | Should -Not -BeNullOrEmpty
            $port443 | Should -Not -BeNullOrEmpty
        }

        It "Combines differing plugin output and merges CVEs without data loss" {
            $outFile = Join-Path $TestDrive "combined_output.nessus"
            $file1 = Join-Path $fixtureDir "valid_scan1.nessus"
            $file3 = Join-Path $fixtureDir "valid_scan3_differing_output.nessus"

            & $cliScript -Files @($file1, $file3) -OutputPath $outFile -DeduplicationMode Safe -Force
            $LASTEXITCODE | Should -Be 0

            $doc = Load-SafeNessusDocument -FilePath $outFile
            $host10 = $doc.SelectSingleNode("//ReportHost[@name='192.168.1.10']")
            $item445 = $host10.SelectSingleNode("ReportItem[@pluginID='10001' and @port='445']")

            $item445 | Should -Not -BeNullOrEmpty
            # Check plugin_output contains both sources
            $outputNode = $item445.SelectSingleNode("plugin_output")
            $outputNode.InnerText | Should -Match "Source:"
            $outputNode.InnerText | Should -Match "SMB vulnerability detected on port 445"
            $outputNode.InnerText | Should -Match "Credentialed scan confirmed kernel patch missing"

            # Check both CVEs exist
            $cves = $item445.SelectNodes("cve") | ForEach-Object { $_.InnerText }
            $cves | Should -Contain "CVE-2020-0001"
            $cves | Should -Contain "CVE-2020-0002"
        }

        It "Keeps all hosts separate when KeepSeparate mode is specified" {
            $outFile = Join-Path $TestDrive "keep_separate.nessus"
            $file1 = Join-Path $fixtureDir "valid_scan1.nessus"
            $file2 = Join-Path $fixtureDir "valid_scan2.nessus"

            & $cliScript -Files @($file1, $file2) -OutputPath $outFile -DeduplicationMode KeepSeparate -Force
            $LASTEXITCODE | Should -Be 0

            $val = Test-NessusXmlFile -FilePath $outFile
            # 2 hosts in scan1 + 2 hosts in scan2 = 4 total separate hosts
            $val.HostCount | Should -Be 4
            # 3 findings in scan1 + 4 findings in scan2 = 7 total findings
            $val.FindingCount | Should -Be 7
        }

        It "Does not merge hosts with conflicting IP identities" {
            $outFile = Join-Path $TestDrive "conflicting_out.nessus"
            $conflictFile = Join-Path $fixtureDir "conflicting_hosts.nessus"

            & $cliScript -Files @($conflictFile) -OutputPath $outFile -DeduplicationMode Safe -Force
            $LASTEXITCODE | Should -Be 0

            $val = Test-NessusXmlFile -FilePath $outFile
            # The two webservers had different IPs (10.0.0.1 vs 192.168.1.1), must remain 2 separate hosts
            $val.HostCount | Should -Be 2
        }
    }

    Context "Directory Input & Output Exclusion" {
        It "Merges all .nessus files in a directory and excludes output file if inside input directory" {
            $testDir = Join-Path $TestDrive "scans"
            $null = New-Item -ItemType Directory -Path $testDir -Force
            Copy-Item -LiteralPath (Join-Path $fixtureDir "valid_scan1.nessus") -Destination $testDir
            Copy-Item -LiteralPath (Join-Path $fixtureDir "valid_scan2.nessus") -Destination $testDir

            # Output placed inside the same scans directory
            $outFile = Join-Path $testDir "merged_output.nessus"

            & $cliScript -InputPath $testDir -OutputPath $outFile -Force
            $LASTEXITCODE | Should -Be 0

            Test-Path -LiteralPath $outFile | Should -BeTrue
            $val = Test-NessusXmlFile -FilePath $outFile
            $val.HostCount | Should -Be 3
        }

        It "Fails gracefully when directory has no eligible files" {
            $emptyDir = Join-Path $TestDrive "empty_scans"
            $null = New-Item -ItemType Directory -Path $emptyDir -Force
            $outFile = Join-Path $TestDrive "out.nessus"

            & $cliScript -InputPath $emptyDir -OutputPath $outFile
            $LASTEXITCODE | Should -Be 1
        }
    }

    Context "Validation-Only Mode" {
        It "Performs validation without generating an output file" {
            $file1 = Join-Path $fixtureDir "valid_scan1.nessus"
            $file2 = Join-Path $fixtureDir "valid_scan2.nessus"
            $testOut = Join-Path $TestDrive "should_not_exist.nessus"

            & $cliScript -Files @($file1, $file2) -ValidateOnly
            $LASTEXITCODE | Should -Be 0
            Test-Path -LiteralPath $testOut | Should -BeFalse
        }

        It "Returns exit code 1 in ValidateOnly mode if any file is invalid" {
            $file1 = Join-Path $fixtureDir "valid_scan1.nessus"
            $malformed = Join-Path $fixtureDir "malformed.nessus"

            & $cliScript -Files @($file1, $malformed) -ValidateOnly
            $LASTEXITCODE | Should -Be 1
        }
    }

    Context "Safety, Overwrite Protection & Logging" {
        It "Refuses to overwrite existing output file unless -Force is specified" {
            $existingOut = Join-Path $TestDrive "existing.nessus"
            Set-Content -LiteralPath $existingOut -Value "Existing Content"
            $file1 = Join-Path $fixtureDir "valid_scan1.nessus"

            & $cliScript -Files @($file1) -OutputPath $existingOut
            $LASTEXITCODE | Should -Be 1
            Get-Content -LiteralPath $existingOut | Should -Be "Existing Content"

            # With -Force, overwrite succeeds
            & $cliScript -Files @($file1) -OutputPath $existingOut -Force
            $LASTEXITCODE | Should -Be 0
            (Get-Content -LiteralPath $existingOut -Raw) | Should -Match "NessusClientData_v2"
        }

        It "Writes a structured log file when -LogPath is provided" {
            $outFile = Join-Path $TestDrive "logged_out.nessus"
            $logFile = Join-Path $TestDrive "merge.log"
            $file1 = Join-Path $fixtureDir "valid_scan1.nessus"

            & $cliScript -Files @($file1) -OutputPath $outFile -LogPath $logFile -Force
            $LASTEXITCODE | Should -Be 0

            Test-Path -LiteralPath $logFile | Should -BeTrue
            $logContent = Get-Content -LiteralPath $logFile -Raw
            $logContent | Should -Match "\[INFO\]"
            $logContent | Should -Match "valid_scan1.nessus"
        }

        It "Preserves UTF-8 Unicode characters and encodings" {
            $outFile = Join-Path $TestDrive "unicode_out.nessus"
            $unicodeFile = Join-Path $fixtureDir "unicode_scan.nessus"

            & $cliScript -Files @($unicodeFile) -OutputPath $outFile -Force
            $LASTEXITCODE | Should -Be 0

            $val = Test-NessusXmlFile -FilePath $outFile
            $val.IsValid | Should -BeTrue

            $doc = Load-SafeNessusDocument -FilePath $outFile
            $hostNode = $doc.SelectSingleNode("//ReportHost[@name='10.200.1.5']")
            $hostNode | Should -Not -BeNullOrEmpty

            $tagFqdn = $hostNode.SelectSingleNode("HostProperties/tag[@name='host-fqdn']")
            $tagFqdn.InnerText | Should -Be "tokyo-srv.corp.local"

            $tagOs = $hostNode.SelectSingleNode("HostProperties/tag[@name='operating-system']")
            $tagOs.InnerText | Should -Match "Muenchen"
        }
    }
}
