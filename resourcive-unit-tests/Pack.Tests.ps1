# Offline checks of the RESOURCIVE pack against the Maester engine: no tenant connection and no test code runs.

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../powershell/Maester.psd1') -Force -ErrorAction Stop
    $script:packPath = Join-Path $PSScriptRoot '../resourcive-pack'
    $script:manifest = Get-Content (Join-Path $script:packPath 'maester-pack.json') -Raw | ConvertFrom-Json
    $script:sources = Get-ChildItem -Path $script:packPath -Recurse -Filter '*.ps1' | ForEach-Object { [pscustomobject]@{ File = $_.FullName; Text = Get-Content $_.FullName -Raw } }
}

Describe 'The pack as Maester loads it' {
    It 'passes Test-MtPack with no errors or warnings' {
        $result = Test-MtPack -Path $script:packPath
        $result.Errors | Should -BeNullOrEmpty
        $result.Warnings | Should -BeNullOrEmpty
        $result.IsValid | Should -BeTrue
    }
    It 'has only valid tests' {
        $tests = @(Get-MtTest -Path $script:packPath)
        $tests.Count | Should -BeGreaterThan 0
        @($tests | Where-Object { -not $_.IsValid } | ForEach-Object { "$($_.Id): $($_.Errors -join '; ')" }) | Should -BeNullOrEmpty
    }
}

Describe 'Declared settings' {
    BeforeAll {
        # Every Get-MtSetting call that names a Namespace.Key setting: the name and the literal default.
        $script:reads = foreach ($source in $script:sources) {
            foreach ($m in [regex]::Matches($source.Text, "Get-MtSetting\s+-Name\s+'(?<name>[A-Za-z]+(?:\.[A-Za-z]+)+)'(?:\s+-Default\s+(?<default>\S+?))?\)")) {
                [pscustomobject]@{ Name = $m.Groups['name'].Value; Default = $m.Groups['default'].Value; File = $source.File }
            }
        }
    }
    It 'finds the settings the pack reads' {
        @($script:reads).Count | Should -Be 10
    }
    It 'declares every Namespace.Key setting the pack reads' {
        $declared = @($script:manifest.Settings.PSObject.Properties.Name)
        @($script:reads | Where-Object { $_.Name -notin $declared } | ForEach-Object { $_.Name }) | Should -BeNullOrEmpty
    }
    It 'reads every setting it declares' {
        $read = @($script:reads.Name)
        @($script:manifest.Settings.PSObject.Properties.Name | Where-Object { $_ -notin $read }) | Should -BeNullOrEmpty
    }
    It 'uses the declared default where a read gives one' {
        $mismatch = foreach ($read in @($script:reads | Where-Object { $_.Default })) {
            $declared = $script:manifest.Settings.($read.Name).Default
            $literal = switch -Regex ($read.Default) { '^\$true$' { $true } '^\$false$' { $false } "^'(.*)'$" { $Matches[1] } '^-?\d+$' { [int]$read.Default } default { $read.Default } }
            if ($declared -ne $literal) { "$($read.Name): declared '$declared', read with '$literal'" }
        }
        $mismatch | Should -BeNullOrEmpty
    }
    It 'gives every setting a type, a default and a description' {
        foreach ($p in $script:manifest.Settings.PSObject.Properties) {
            $p.Value.Type | Should -BeIn 'int', 'bool', 'string' -Because $p.Name
            $p.Value.PSObject.Properties.Name | Should -Contain 'Default' -Because $p.Name
            $p.Value.Description | Should -Not -BeNullOrEmpty -Because $p.Name
        }
    }
    It 'accepts the repository config, which sets Resourcive.CA.MaxScenarios' {
        $config = Get-Content (Join-Path $PSScriptRoot '../tests/maester-config.json') -Raw | ConvertFrom-Json
        $config.GlobalSettings.'Resourcive.CA.MaxScenarios' | Should -BeOfType [long]
        $script:manifest.Settings.PSObject.Properties.Name | Should -Contain 'Resourcive.CA.MaxScenarios'
    }
}
