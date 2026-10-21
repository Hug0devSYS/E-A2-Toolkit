<#
  Lance la campagne de tests complets dans Windows Sandbox (VM Windows jetable, Windows 10/11 Pro).
  Prérequis (une fois, en administrateur) :
    Enable-WindowsOptionalFeature -Online -FeatureName "Containers-DisposableClientVM" -All   puis redémarrer
  Les .exe testés sont ceux de dist\ ; les résultats arrivent dans %TEMP%\ea2_vm\results.
  ATTENTION : ne jamais lancer --fulltest d'Install, Migration ou Scan hors d'une VM (installations,
  suppressions, réglages et actions de dépannage réellement exécutés).
#>
$Root = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$V = Join-Path $env:TEMP 'ea2_vm'
Remove-Item "$V\results" -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force "$V\bin", "$V\results" | Out-Null
Copy-Item (Join-Path $Root 'dist\*.exe') "$V\bin" -Force
Copy-Item (Join-Path $PSScriptRoot 'run_tests.ps1'), (Join-Path $PSScriptRoot 'plan.txt') $V -Force
New-Item -ItemType File -Force "$V\shutdown.flag" | Out-Null
(Get-Content (Join-Path $PSScriptRoot 'ea2_tests.wsb') -Raw).Replace('%HOSTDIR%', $V) | Set-Content "$V\ea2_tests.wsb" -Encoding UTF8
Start-Process "$V\ea2_tests.wsb"
Write-Host "VM lancée. Suivi : Get-Content '$V\results\runner.log' -Wait"
Write-Host "Résultats : python tools\show_results.py '$V\results' FAIL,WARN"
