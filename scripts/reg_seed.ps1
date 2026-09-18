<#
.SYNOPSIS
  Synthetic registry corpus seeder for the .reg export-matrix study.
.DESCRIPTION
  Creates values of exact types under one probe key from a JSON spec.
  Confined to HKCU:\SOFTWARE\REStudyTmp* (own scratch keys, removed
  after the run). Binary/multi values go through .NET types so no
  text parser sits between the spec and the stored bytes.
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][string]$SpecPath
)

$ErrorActionPreference = "Stop"

$spec = Get-Content -LiteralPath $SpecPath -Encoding utf8 | ConvertFrom-Json
foreach ($probe in $spec.probes) {
  $key = $probe.key
  if (-not $key.StartsWith("HKCU\SOFTWARE\REStudyTmp", [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "key outside scratch scope."
  }
  $psKey = "HKCU:\" + $key.Substring(5)
  New-Item -Path $psKey -Force | Out-Null
  foreach ($value in $probe.values) {
    $name = $value.name
    switch ($value.type) {
      "REG_SZ" {
        if ($name -eq "@") {
          Set-ItemProperty -LiteralPath $psKey -Name "(default)" -Value $value.data
        } else {
          New-ItemProperty -Path $psKey -Name $name -Value $value.data -PropertyType String -Force | Out-Null
        }
      }
      "REG_EXPAND_SZ" {
        if ($name -eq "@") {
          Set-ItemProperty -LiteralPath $psKey -Name "(default)" -Value $value.data
        } else {
          New-ItemProperty -Path $psKey -Name $name -Value $value.data -PropertyType ExpandString -Force | Out-Null
        }
      }
      "REG_DWORD" {
        New-ItemProperty -Path $psKey -Name $name -Value ([int]$value.data) -PropertyType DWord -Force | Out-Null
      }
      "REG_QWORD" {
        New-ItemProperty -Path $psKey -Name $name -Value ([long]$value.data) -PropertyType QWord -Force | Out-Null
      }
      "REG_BINARY" {
        $bytes = [byte[]]($value.data -split " " | ForEach-Object { [Convert]::ToByte($_, 16) })
        New-ItemProperty -Path $psKey -Name $name -Value $bytes -PropertyType Binary -Force | Out-Null
      }
      "REG_MULTI_SZ" {
        $strings = [string[]]$value.data
        New-ItemProperty -Path $psKey -Name $name -Value $strings -PropertyType MultiString -Force | Out-Null
      }
      "SUBKEY" {
        New-Item -Path (Join-Path $psKey $value.data) -Force | Out-Null
        if ($value.with_value -eq $true) {
          New-ItemProperty -Path (Join-Path $psKey $value.data) -Name "v" -Value "x" -PropertyType String -Force | Out-Null
        }
      }
      default { throw "unknown spec type: $($value.type)" }
    }
  }
}
"SEEDED $($spec.probes.Count)"
