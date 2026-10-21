# Banc de test E-A2 - exécuté automatiquement au démarrage de Windows Sandbox
$ErrorActionPreference = 'Continue'
$R = 'C:\ea2\results'
New-Item -ItemType Directory -Force $R | Out-Null
function L($m) { "$(Get-Date -Format 'HH:mm:ss') $m" | Out-File "$R\runner.log" -Append -Encoding utf8 }
L 'VM démarrée'
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$admin = ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
L "utilisateur=$($id.Name) admin=$admin"
$uac = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -ErrorAction SilentlyContinue
L "UAC EnableLUA=$($uac.EnableLUA) ConsentPromptBehaviorAdmin=$($uac.ConsentPromptBehaviorAdmin)"
$os = Get-CimInstance Win32_OperatingSystem
L "OS=$($os.Caption) build=$($os.BuildNumber) RAM=$([math]::Round($os.TotalVisibleMemorySize/1MB,1)) Go"
$wv = (Get-ItemProperty 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}' -ErrorAction SilentlyContinue).pv
L "WebView2=$wv winget=$(Test-Path "$env:LOCALAPPDATA\Microsoft\WindowsApps\winget.exe")"
for ($i = 0; $i -lt 60; $i++) {
  try { $c = New-Object Net.Sockets.TcpClient; $c.Connect('1.1.1.1', 443); $c.Close(); break } catch { Start-Sleep 2 }
}
L "réseau prêt après $($i*2) s"
if (-not $admin) { L 'ARRET : la session de la VM n''a pas les droits administrateur'; return }
foreach ($line in Get-Content 'C:\ea2\plan.txt') {
  if (-not $line.Trim() -or $line.StartsWith('#')) { continue }
  $name, $exe, $min = $line.Split('|')
  $path = Join-Path 'C:\ea2\bin' $exe
  L "DEBUT $name ($exe, max $min min)"
  $t0 = Get-Date
  try {
    $p = Start-Process -FilePath $path -ArgumentList "--fulltest `"$R`"" -PassThru -ErrorAction Stop
    if (-not $p.WaitForExit([int]$min * 60000)) {
      L "TIMEOUT $name"
      Get-Process | Where-Object { $_.Path -like 'C:\ea2\bin\*' } | Stop-Process -Force -ErrorAction SilentlyContinue
    }
    L "FIN $name code=$($p.ExitCode) durée=$([int]((Get-Date)-$t0).TotalMinutes) min"
  } catch { L "ERREUR lancement $name : $($_.Exception.Message)" }
}
L 'TERMINE'
if (Test-Path 'C:\ea2\shutdown.flag') { shutdown /s /t 15 }
