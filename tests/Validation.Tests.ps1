<#
.SYNOPSIS
    Pester test suite for XML validation and security checks in Nessus Merge Tool.
#>

BeforeAll {
    $scriptDir = Split-Path -Parent $PSScriptRoot
    . (Join-Path $scriptDir "src\XmlValidator.ps1")
    $fixtureDir = Join-Path $PSScriptRoot "Fixtures"
}

Describe "XML Validator Security & Schema Verification" {

    It "Successfully validates a well-formed Nessus XML scan" {
        $file = Join-Path $fixtureDir "valid_scan1.nessus"
        $result = Test-NessusXmlFile -FilePath $file

        $result.IsValid | Should -BeTrue
        $result.HostCount | Should -Be 2
        $result.FindingCount | Should -Be 3
        $result.ErrorMessage | Should -BeNullOrEmpty
    }

    It "Rejects nonexistent files" {
        $file = Join-Path $fixtureDir "does_not_exist.nessus"
        $result = Test-NessusXmlFile -FilePath $file

        $result.IsValid | Should -BeFalse
        $result.ErrorMessage | Should -Match "does not exist"
    }

    It "Rejects 0-byte empty files" {
        $emptyFile = Join-Path $TestDrive "empty.nessus"
        [System.IO.File]::WriteAllBytes($emptyFile, @())
        $result = Test-NessusXmlFile -FilePath $emptyFile

        $result.IsValid | Should -BeFalse
        $result.ErrorMessage | Should -Match "empty"
    }

    It "Rejects malformed XML with syntax errors" {
        $file = Join-Path $fixtureDir "malformed.nessus"
        $result = Test-NessusXmlFile -FilePath $file

        $result.IsValid | Should -BeFalse
        $result.ErrorMessage | Should -Match "Malformed XML"
    }

    It "Rejects valid XML documents that lack the NessusClientData_v2 root element" {
        $file = Join-Path $fixtureDir "non_nessus.xml"
        $result = Test-NessusXmlFile -FilePath $file

        $result.IsValid | Should -BeFalse
        $result.ErrorMessage | Should -Match "Invalid root element"
    }

    It "Rejects Nessus documents that lack the required Report element" {
        $file = Join-Path $fixtureDir "missing_report.nessus"
        $result = Test-NessusXmlFile -FilePath $file

        $result.IsValid | Should -BeFalse
        $result.ErrorMessage | Should -Match "Missing required '<Report>' element"
    }

    It "Prohibits DTD processing and blocks XXE injection attempts" {
        $file = Join-Path $fixtureDir "xxe_injection.nessus"
        $result = Test-NessusXmlFile -FilePath $file

        $result.IsValid | Should -BeFalse
        $result.ErrorMessage | Should -Match "(DTD is prohibited|Malformed XML)"
    }

    It "Successfully validates merged output with matching expected counts" {
        $file = Join-Path $fixtureDir "valid_scan1.nessus"
        $result = Test-MergedNessusOutput -FilePath $file -ExpectedHosts 2 -ExpectedFindings 3

        $result.IsValid | Should -BeTrue
    }

    It "Fails output validation when host or finding counts do not match expected totals" {
        $file = Join-Path $fixtureDir "valid_scan1.nessus"
        $result = Test-MergedNessusOutput -FilePath $file -ExpectedHosts 5 -ExpectedFindings 3

        $result.IsValid | Should -BeFalse
        $result.ErrorMessage | Should -Match "host count mismatch"
    }
}
