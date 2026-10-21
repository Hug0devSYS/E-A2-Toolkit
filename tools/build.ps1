<#
  Compile les logiciels E-A2 en .exe autonomes (un seul fichier, sans Python sur le poste client).
  Usage :  powershell -ExecutionPolicy Bypass -File tools\build.ps1            (les 4)
           powershell -ExecutionPolicy Bypass -File tools\build.ps1 net scan   (au choix)
  Résultat : dossier dist\
#>
param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Apps)
if (-not $Apps) { $Apps = @('scan', 'net', 'install', 'migration') }
$Root = Split-Path $PSScriptRoot -Parent
$Src = Join-Path $Root 'src'; $Ico = Join-Path $Root 'icons'; $Dist = Join-Path $Root 'dist'
$Work = Join-Path $env:TEMP 'ea2_build'
New-Item -ItemType Directory -Force $Dist, $Work | Out-Null

python -m pip install --user --quiet pyinstaller pywebview psutil
$ver = (python -c "import sys;print('%d.%d.%d' % sys.version_info[:3])").Trim()
if ($ver -eq '3.10.0') { $pyi = @((Join-Path $PSScriptRoot 'pyi_fix.py')) } else { $pyi = @('-m', 'PyInstaller') }
Write-Host "Python $ver"

$def = @{
  scan      = @('E-A2 Scan',      'ea2_scan',      $true)
  net       = @('E-A2 Net',       'ea2_net',       $false)
  install   = @('E-A2 Install',   'ea2_install',   $true)
  migration = @('E-A2 Migration', 'ea2_migration', $true)
}
foreach ($a in $Apps) {
  if (-not $def.ContainsKey($a)) { Write-Warning "Inconnu : $a"; continue }
  $name, $mod, $uac = $def[$a]
  $args2 = @('--onefile', '--windowed', '--noconfirm', '--name', $name, '--icon', (Join-Path $Ico "$mod.ico"),
             '--paths', $Src, '--hidden-import', "${mod}_tests", '--distpath', $Dist,
             '--workpath', (Join-Path $Work $a), '--specpath', $Work)
  if ($uac) { $args2 += '--uac-admin' }
  Write-Host "Compilation de $name..."
  & python @pyi @args2 (Join-Path $Src "$mod.py") 2>&1 | Select-Object -Last 2
  $exe = Join-Path $Dist "$name.exe"
  if (Test-Path $exe) { Write-Host ("  OK  {0} ({1:N1} Mo)" -f $exe, ((Get-Item $exe).Length / 1MB)) -ForegroundColor Green }
  else { Write-Host "  ECHEC $name" -ForegroundColor Red }
}
