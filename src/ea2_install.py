# -*- coding: utf-8 -*-
"""E-A2 Install - préparation de PC : logiciels (winget), nettoyage des applis préinstallées, réglages Windows."""
from __future__ import annotations

import argparse
import json
import os
import platform
import queue
import re
import socket
import tempfile
import threading
import time

from ea2ui import IS_WIN, BridgeBase, LiveRunner, build_page, finish, is_admin, ps_cmd, run, run_window

APP, VERSION = "E-A2 Install", "1.0.0"

# --------------------------------------------------------------------------- #
# Catalogue (identifiants winget vérifiés)  P = particulier, B = bureau/PME, T = technicien
# --------------------------------------------------------------------------- #
CATALOG = [
    ("Navigateurs", [
        ("Google.Chrome", "Google Chrome", "Navigateur le plus utilisé", "PB"),
        ("Mozilla.Firefox.fr", "Firefox", "Navigateur libre, version française", "PB"),
        ("Brave.Brave", "Brave", "Navigateur avec bloqueur de pubs intégré", ""),
        ("Opera.Opera", "Opera", "Navigateur avec VPN intégré", ""),
    ]),
    ("Bureautique et PDF", [
        ("TheDocumentFoundation.LibreOffice", "LibreOffice", "Suite bureautique gratuite (Word, Excel, PowerPoint)", "P"),
        ("ONLYOFFICE.DesktopEditors", "ONLYOFFICE", "Suite bureautique très compatible Office", ""),
        ("Microsoft.Office", "Microsoft 365 Apps", "Word, Excel, Outlook… (licence nécessaire)", ""),
        ("Adobe.Acrobat.Reader.64-bit", "Adobe Acrobat Reader", "Lecture, signature et formulaires PDF", "PB"),
        ("SumatraPDF.SumatraPDF", "SumatraPDF", "Lecteur PDF très léger", ""),
        ("PDFsam.PDFsam", "PDFsam Basic", "Fusionner et découper des PDF", "B"),
        ("Notepad++.Notepad++", "Notepad++", "Éditeur de texte avancé", "BT"),
    ]),
    ("Communication", [
        ("Zoom.Zoom", "Zoom", "Visioconférence", "B"),
        ("Microsoft.Teams", "Microsoft Teams", "Messagerie et réunions Microsoft 365", "B"),
        ("Mozilla.Thunderbird.fr", "Thunderbird", "Messagerie e-mail, version française", ""),
        ("9NKSQGP7F2NH", "WhatsApp", "Messagerie (Microsoft Store)", "P"),
        ("OpenWhisperSystems.Signal", "Signal", "Messagerie chiffrée", ""),
        ("Discord.Discord", "Discord", "Discussions vocales et texte", ""),
    ]),
    ("Multimédia", [
        ("VideoLAN.VLC", "VLC", "Lit toutes les vidéos et musiques", "PB"),
        ("Spotify.Spotify", "Spotify", "Musique en streaming", ""),
        ("IrfanSkiljan.IrfanView", "IrfanView", "Visionneuse et retouche photo rapide", ""),
        ("GIMP.GIMP", "GIMP", "Retouche photo avancée", ""),
        ("Audacity.Audacity", "Audacity", "Enregistrement et montage audio", ""),
        ("OBSProject.OBSStudio", "OBS Studio", "Enregistrement d'écran et diffusion", ""),
        ("Greenshot.Greenshot", "Greenshot", "Captures d'écran annotées", "B"),
    ]),
    ("Utilitaires", [
        ("7zip.7zip", "7-Zip", "Compression et extraction (zip, rar, 7z…)", "PBT"),
        ("voidtools.Everything", "Everything", "Recherche instantanée de fichiers", "T"),
        ("Microsoft.PowerToys", "PowerToys", "Outils avancés Microsoft", ""),
        ("JAMSoftware.TreeSize.Free", "TreeSize Free", "Ce qui occupe le disque", "T"),
        ("Klocman.BulkCrapUninstaller", "Bulk Crap Uninstaller", "Désinstallation en masse et nettoyage des restes", "T"),
        ("KeePassXCTeam.KeePassXC", "KeePassXC", "Gestionnaire de mots de passe local", ""),
        ("Bitwarden.Bitwarden", "Bitwarden", "Gestionnaire de mots de passe synchronisé", ""),
    ]),
    ("Stockage en ligne", [
        ("Google.GoogleDrive", "Google Drive", "Synchronisation Google Drive", ""),
        ("Dropbox.Dropbox", "Dropbox", "Synchronisation Dropbox", ""),
        ("Microsoft.OneDrive", "OneDrive", "Synchronisation OneDrive (réinstallation)", ""),
    ]),
    ("Assistance à distance", [
        ("AnyDesk.AnyDesk", "AnyDesk", "Prise en main à distance", "PB"),
        ("TeamViewer.TeamViewer", "TeamViewer", "Prise en main à distance", ""),
    ]),
    ("Sécurité", [
        ("Malwarebytes.Malwarebytes", "Malwarebytes", "Détection et suppression de logiciels malveillants", "P"),
    ]),
    ("Composants système", [
        ("Microsoft.VCRedist.2015+.x64", "Visual C++ 2015-2022 (x64)", "Requis par de nombreux logiciels", "B"),
        ("Microsoft.VCRedist.2015+.x86", "Visual C++ 2015-2022 (x86)", "Requis par les logiciels 32 bits", "B"),
        ("Microsoft.DotNet.DesktopRuntime.8", ".NET Desktop Runtime 8", "Requis par les applications .NET récentes", "B"),
        ("Oracle.JavaRuntimeEnvironment", "Java 8", "Requis par certains logiciels métier", ""),
        ("Microsoft.DirectX", "DirectX (runtime)", "Requis par certains jeux et logiciels anciens", ""),
    ]),
    ("Pilotes constructeur", [
        ("Dell.CommandUpdate", "Dell Command | Update", "Pilotes et BIOS des PC Dell", ""),
        ("Lenovo.SystemUpdate", "Lenovo System Update", "Pilotes et BIOS des PC Lenovo", ""),
        ("HP.SupportAssistant", "HP Support Assistant", "Pilotes et BIOS des PC HP", ""),
        ("Intel.IntelDriverAndSupportAssistant", "Intel Driver & Support Assistant", "Pilotes Intel (Wi-Fi, graphique…)", ""),
    ]),
    ("Outils technicien", [
        ("CrystalDewWorld.CrystalDiskInfo", "CrystalDiskInfo", "Santé des disques (SMART)", "T"),
        ("REALiX.HWiNFO", "HWiNFO", "Inventaire matériel et capteurs", "T"),
        ("CPUID.CPU-Z", "CPU-Z", "Processeur, carte mère, mémoire", "T"),
        ("Microsoft.Sysinternals.Suite", "Sysinternals Suite", "Autoruns, Process Explorer…", "T"),
        ("PuTTY.PuTTY", "PuTTY", "SSH et Telnet", "T"),
        ("WinSCP.WinSCP", "WinSCP", "Transferts SFTP / FTP", "T"),
        ("Famatech.AdvancedIPScanner", "Advanced IP Scanner", "Scan du réseau local", ""),
        ("WiresharkFoundation.Wireshark", "Wireshark", "Analyse de trames réseau", ""),
        ("Rufus.Rufus", "Rufus", "Clés USB d'installation Windows", "T"),
        ("Ventoy.Ventoy", "Ventoy", "Clé USB multi-ISO", ""),
        ("Microsoft.WindowsTerminal", "Windows Terminal", "Terminal moderne", ""),
    ]),
]
MSSTORE = {"9NKSQGP7F2NH"}
MAKER_PKG = {"dell": "Dell.CommandUpdate", "lenovo": "Lenovo.SystemUpdate", "hp": "HP.SupportAssistant",
             "hewlett": "HP.SupportAssistant"}
ALL_IDS = {i[0]: i for _, items in CATALOG for i in items}

WINGET_CODES = {
    0x8A150014: ("err", "logiciel introuvable dans winget"),
    0x8A15002B: ("ok", "déjà à jour"),
    0x8A150061: ("ok", "déjà installé"),
    0x8A15010D: ("ok", "déjà installé"),
    0x8A150101: ("err", "application en cours d'utilisation : la fermer puis réessayer"),
    0x8A150102: ("err", "une autre installation est en cours"),
    0x8A150103: ("err", "fichier en cours d'utilisation"),
    0x8A150104: ("err", "dépendance manquante"),
    0x8A150105: ("err", "disque plein"),
    0x8A150106: ("err", "mémoire insuffisante"),
    0x8A150107: ("err", "pas de connexion réseau"),
    0x8A150109: ("warn", "redémarrage nécessaire pour terminer"),
    0x8A15010A: ("err", "redémarrage nécessaire avant l'installation"),
    0x8A15010C: ("err", "annulé"),
    0x8A15010E: ("ok", "une version plus récente est déjà installée"),
    0x8A15010F: ("err", "bloqué par une stratégie"),
    0x8A15002E: ("err", "le hachage de l'installeur ne correspond pas"),
    3010: ("warn", "redémarrage nécessaire pour terminer"),
    1641: ("warn", "redémarrage lancé par l'installeur"),
}

# --------------------------------------------------------------------------- #
# Applications préinstallées superflues (Appx) : motif, libellé, coché par défaut
# --------------------------------------------------------------------------- #
BLOAT = [
    ("Microsoft.BingNews", "Actualités (Microsoft News)", True), ("Microsoft.BingWeather", "Météo", False),
    ("Microsoft.BingSearch", "Recherche Bing", True), ("Microsoft.GetHelp", "Obtenir de l'aide", True),
    ("Microsoft.Getstarted", "Astuces", True), ("Microsoft.MicrosoftSolitaireCollection", "Solitaire Collection", True),
    ("Microsoft.People", "Contacts", True), ("Microsoft.WindowsFeedbackHub", "Hub de commentaires", True),
    ("Microsoft.ZuneVideo", "Films et TV", True), ("Microsoft.MixedReality.Portal", "Portail de réalité mixte", True),
    ("Microsoft.SkypeApp", "Skype", True), ("Microsoft.MicrosoftOfficeHub", "Lanceur Microsoft 365 (Office)", True),
    ("Clipchamp.Clipchamp", "Clipchamp", True), ("Microsoft.549981C3F5F10", "Cortana", True),
    ("Microsoft.PowerAutomateDesktop", "Power Automate", True), ("MicrosoftTeams", "Teams personnel (ancien)", True),
    ("Microsoft.WindowsMaps", "Cartes", True), ("Microsoft.Windows.DevHome", "Dev Home", True),
    ("MicrosoftCorporationII.MicrosoftFamily", "Contrôle parental Family", False), ("Microsoft.Todos", "Microsoft To Do", False),
    ("Microsoft.Copilot", "Copilot", False), ("Microsoft.OutlookForWindows", "Nouvel Outlook", False),
    ("Microsoft.YourPhone", "Mobile connecté (Phone Link)", False), ("Microsoft.GamingApp", "Xbox", False),
    ("Microsoft.XboxGamingOverlay", "Xbox Game Bar", False), ("Microsoft.XboxApp", "Xbox (ancienne application)", False),
    ("*CandyCrush*", "Candy Crush", True), ("*Disney*", "Disney+", True), ("SpotifyAB.SpotifyMusic", "Spotify (préinstallé)", True),
    ("*TikTok*", "TikTok", True), ("Facebook.*", "Facebook / Instagram", True), ("*Netflix*", "Netflix", True),
    ("AmazonVideo.PrimeVideo", "Prime Video", True), ("*McAfee*", "McAfee (version Store)", True), ("*LinkedIn*", "LinkedIn", True),
    ("king.com.*", "Jeux King", True), ("*Hulu*", "Hulu", True), ("*Twitter*", "X (Twitter)", True),
]

# --------------------------------------------------------------------------- #
# Réglages Windows : lecture (PowerShell -> booléen) et application
# --------------------------------------------------------------------------- #
PS_HELP = r"""
function G($p,$n){ try { (Get-ItemProperty -Path $p -Name $n -ErrorAction Stop).$n } catch { $null } }
function S($p,$n,$v,$t='DWord'){ if(-not (Test-Path $p)){ New-Item -Path $p -Force | Out-Null }; Set-ItemProperty -Path $p -Name $n -Value $v -Type $t -Force }
$adv='HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
$cdm='HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'
$build=[int](Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').CurrentBuildNumber
"""
SETTINGS = [
    {"id": "ext", "label": "Afficher les extensions de fichiers", "desc": "facture.pdf.exe devient visible : protège des pièces jointes piégées.",
     "scope": "Utilisateur", "def": True, "explorer": True,
     "read": "(G $adv HideFileExt) -eq 0", "apply": "S $adv HideFileExt 0; 'Extensions affichées.'"},
    {"id": "thispc", "label": "Ouvrir l'Explorateur sur « Ce PC »", "desc": "Au lieu de l'Accueil / Accès rapide.",
     "scope": "Utilisateur", "def": True, "explorer": True,
     "read": "(G $adv LaunchTo) -eq 1", "apply": "S $adv LaunchTo 1; 'Explorateur ouvert sur Ce PC.'"},
    {"id": "ads", "label": "Supprimer les suggestions et publicités", "desc": "Menu Démarrer, écran de verrouillage, applis installées en douce, rappels « Terminer la configuration ».",
     "scope": "Utilisateur", "def": True, "explorer": True,
     "read": "((G $cdm SilentInstalledAppsEnabled) -eq 0) -and ((G $cdm 'SubscribedContent-338388Enabled') -eq 0)",
     "apply": r"""foreach($n in 'SilentInstalledAppsEnabled','SystemPaneSuggestionsEnabled','SoftLandingEnabled','RotatingLockScreenOverlayEnabled',
'SubscribedContent-310093Enabled','SubscribedContent-338388Enabled','SubscribedContent-338389Enabled','SubscribedContent-338393Enabled',
'SubscribedContent-353694Enabled','SubscribedContent-353696Enabled','PreInstalledAppsEnabled','OemPreInstalledAppsEnabled'){ S $cdm $n 0 }
S $adv Start_IrisRecommendations 0
S 'HKCU:\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement' ScoobeSystemSettingEnabled 0
'Suggestions et publicités désactivées.'"""},
    {"id": "taskleft", "label": "Barre des tâches alignée à gauche", "desc": "Disposition classique, comme Windows 10 (Windows 11 uniquement).",
     "scope": "Utilisateur", "def": False, "explorer": True,
     "read": "if($build -lt 22000){'na'}else{(G $adv TaskbarAl) -eq 0}", "apply": "S $adv TaskbarAl 0; 'Barre des tâches alignée à gauche.'"},
    {"id": "search", "label": "Recherche réduite à une icône", "desc": "Libère de la place dans la barre des tâches.",
     "scope": "Utilisateur", "def": False, "explorer": True,
     "read": "(G 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Search' SearchboxTaskbarMode) -eq 1",
     "apply": "S 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Search' SearchboxTaskbarMode 1; 'Recherche en icône.'"},
    {"id": "thispcicon", "label": "Icône « Ce PC » sur le bureau", "desc": "Très demandé par les utilisateurs habitués aux anciennes versions.",
     "scope": "Utilisateur", "def": False, "explorer": True,
     "read": "(G 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\HideDesktopIcons\\NewStartPanel' '{20D04FE0-3AEA-1069-A2D8-08002B30309D}') -eq 0",
     "apply": "S 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\HideDesktopIcons\\NewStartPanel' '{20D04FE0-3AEA-1069-A2D8-08002B30309D}' 0; 'Icône Ce PC affichée.'"},
    {"id": "classicmenu", "label": "Menu clic droit complet (classique)", "desc": "Supprime le « Afficher plus d'options » de Windows 11.",
     "scope": "Utilisateur", "def": False, "explorer": True,
     "read": "if($build -lt 22000){'na'}else{Test-Path 'HKCU:\\Software\\Classes\\CLSID\\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\\InprocServer32'}",
     "apply": "$k='HKCU:\\Software\\Classes\\CLSID\\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\\InprocServer32'; New-Item -Path $k -Force | Out-Null; Set-Item -Path $k -Value ''; 'Menu contextuel classique activé.'"},
    {"id": "numlock", "label": "Pavé numérique activé au démarrage", "desc": "Évite les erreurs de mot de passe à l'ouverture de session.",
     "scope": "Poste", "def": True, "explorer": False,
     "read": "(G 'Registry::HKEY_USERS\\.DEFAULT\\Control Panel\\Keyboard' InitialKeyboardIndicators) -match '^(2|2147483650)$'",
     "apply": "S 'Registry::HKEY_USERS\\.DEFAULT\\Control Panel\\Keyboard' InitialKeyboardIndicators '2' String; S 'HKCU:\\Control Panel\\Keyboard' InitialKeyboardIndicators '2' String; 'Verr. Num actif au démarrage.'"},
    {"id": "widgets", "label": "Désactiver les Widgets / Actualités", "desc": "Supprime le panneau d'actualités de la barre des tâches.",
     "scope": "Poste", "def": True, "explorer": True,
     "read": "(G 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Dsh' AllowNewsAndInterests) -eq 0",
     "apply": "S 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Dsh' AllowNewsAndInterests 0; S 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Feeds' EnableFeeds 0; 'Widgets désactivés.'"},
    {"id": "fastboot", "label": "Désactiver le démarrage rapide", "desc": "Un arrêt devient un vrai arrêt : évite les uptimes de plusieurs semaines et des soucis de pilotes.",
     "scope": "Poste", "def": True, "explorer": False,
     "read": "(G 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Power' HiberbootEnabled) -eq 0",
     "apply": "S 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Power' HiberbootEnabled 0; 'Démarrage rapide désactivé.'"},
    {"id": "nosleep", "label": "Pas de mise en veille sur secteur", "desc": "Le PC reste allumé quand il est branché (l'écran s'éteint après 15 min). Conseillé pour les fixes.",
     "scope": "Poste", "def": False, "explorer": False,
     "read": "$l=@(powercfg /query SCHEME_CURRENT SUB_SLEEP STANDBYIDLE | Select-String '0x[0-9a-fA-F]{8}\\s*$'); if($l.Count -ge 2){ [Convert]::ToInt32(($l[-2] -split '0x')[-1].Trim(),16) -eq 0 } else { $null }",
     "apply": "powercfg /change standby-timeout-ac 0; powercfg /change monitor-timeout-ac 15; 'Mise en veille désactivée sur secteur, écran éteint après 15 min.'"},
    {"id": "restore", "label": "Activer la protection système", "desc": "Active les points de restauration sur le disque système et en crée un.",
     "scope": "Poste", "def": True, "explorer": False,
     "read": "(G 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SystemRestore' RPSessionInterval) -eq 1",
     "apply": "Enable-ComputerRestore -Drive ($env:SystemDrive + '\\'); 'Protection système activée.'; try { Checkpoint-Computer -Description 'E-A2 Install' -RestorePointType MODIFY_SETTINGS -ErrorAction Stop 3>$null; 'Point de restauration créé.' } catch { 'Point de restauration : ' + $_.Exception.Message }"},
    {"id": "time", "label": "Synchroniser l'heure automatiquement", "desc": "Démarre le service Temps Windows en automatique et resynchronise.",
     "scope": "Poste", "def": True, "explorer": False,
     "read": "(Get-Service w32time).StartType -eq 'Automatic'",
     "apply": "Set-Service w32time -StartupType Automatic; Start-Service w32time -ErrorAction SilentlyContinue; w32tm /resync /force | Out-Null; 'Heure synchronisée.'"},
]
SET_BY_ID = {s["id"]: s for s in SETTINGS}


def winget_path():
    for c in ("winget",):
        p = run(["where", c], timeout=10).strip().splitlines()
        if p and p[0].lower().endswith(".exe"):
            return p[0]
    lp = os.path.join(os.environ.get("LOCALAPPDATA", ""), "Microsoft", "WindowsApps", "winget.exe")
    return lp if os.path.exists(lp) else ""


def _winget_line(text):
    t = text.strip()
    if not t or re.fullmatch(r"[\-\\|/\s]+", t):
        return None
    if "█" in t or "▒" in t or re.search(r"\d+(\.\d+)?\s*(KB|MB|GB|Ko|Mo|Go)\s*/\s*\d", t):
        return "prog"
    return "out"


class InstallBridge(BridgeBase):
    def __init__(self, args):
        super().__init__()
        self._args = args
        self._q = queue.Queue()
        self._jid = 0
        self._cur = None
        self._runner = None
        self._pending = []
        self._done = []
        self._lock = threading.Lock()
        self._winget = ""
        threading.Thread(target=self._worker, daemon=True).start()

    # ---- informations -------------------------------------------------------- #
    def info(self):
        maker = ""
        if IS_WIN:
            maker = run(ps_cmd("(Get-CimInstance Win32_ComputerSystem).Manufacturer"), timeout=20).strip()
        build = platform.version()
        rel = run(ps_cmd("(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion').DisplayVersion"), timeout=20).strip() if IS_WIN else ""
        rec = ""
        for k, pid in MAKER_PKG.items():
            if k in maker.lower():
                rec = pid
        cat = [{"cat": c, "items": [{"id": i[0], "name": i[1], "desc": i[2], "presets": i[3]} for i in items]} for c, items in CATALOG]
        return {"host": socket.gethostname(), "admin": is_admin(), "win": IS_WIN, "maker": maker, "makerPkg": rec,
                "os": f"Windows {('11' if int(build.split('.')[-1]) >= 22000 else '10')} {rel}" if IS_WIN and build else platform.platform(),
                "catalog": cat, "bloat": [{"pat": p, "label": l, "def": d} for p, l, d in BLOAT],
                "settings": [{k: s[k] for k in ("id", "label", "desc", "scope", "def")} for s in SETTINGS]}

    def ready(self):
        if getattr(self._args, "fulltest", ""):
            threading.Thread(target=self._fulltest, daemon=True).start()
        elif self._args.selftest:
            threading.Thread(target=self._selftest, daemon=True).start()
        return True

    def winget_status(self):
        self._winget = winget_path() if IS_WIN else ""
        ver = run([self._winget, "--version"], timeout=20).strip() if self._winget else ""
        return {"path": self._winget, "version": ver if ver.startswith("v") else ""}

    def installed(self):
        """Identifiants winget déjà installés (via winget export)."""
        if not self._winget:
            self.winget_status()
        if not self._winget:
            return {"ids": [], "error": "winget absent"}
        f = os.path.join(tempfile.gettempdir(), f"ea2_export_{os.getpid()}.json")
        run([self._winget, "export", "-o", f, "--accept-source-agreements", "--disable-interactivity"], timeout=180)
        ids = []
        try:
            with open(f, encoding="utf-8-sig") as fh:
                data = json.load(fh)
            for src in data.get("Sources", []):
                for p in src.get("Packages", []):
                    ids.append(p.get("PackageIdentifier", ""))
        except Exception as e:
            return {"ids": [], "error": f"lecture impossible : {e}"}
        finally:
            try:
                os.remove(f)
            except OSError:
                pass
        return {"ids": ids}

    def bloat_scan(self):
        if not IS_WIN:
            return {"found": []}
        out = run(ps_cmd("Get-AppxPackage | Select-Object -ExpandProperty Name"), timeout=60)
        names = [n.strip() for n in out.splitlines() if n.strip()]
        import fnmatch
        found = []
        for p, l, d in BLOAT:
            hits = [n for n in names if fnmatch.fnmatch(n.lower(), p.lower())]
            if hits:
                found.append({"pat": p, "label": l, "def": d, "pkgs": hits})
        return {"found": found}

    def settings_read(self):
        if not IS_WIN:
            return {}
        script = PS_HELP + "$r=@{};" + "".join(
            f"try {{ $v = & {{ {s['read']} }}; $r['{s['id']}'] = if(($v -is [string]) -and ($v -eq 'na')){{'na'}}elseif($null -eq $v){{'?'}}elseif([bool]$v){{'1'}}else{{'0'}} }} catch {{ $r['{s['id']}']='?' }};"
            for s in SETTINGS) + "$r | ConvertTo-Json -Compress"
        out = run(ps_cmd(script), timeout=60)
        try:
            return json.loads(out[out.index("{"):])
        except Exception:
            return {}

    def pc_name(self):
        return socket.gethostname()

    # ---- file d'attente ------------------------------------------------------- #
    def enqueue(self, jobs):
        """jobs : [{kind, ref, title, ...}] -> [{jid, ref, title}]"""
        out = []
        with self._lock:
            for j in jobs:
                self._jid += 1
                j = dict(j, jid=self._jid)
                self._pending.append(j)
                self._q.put(j)
                out.append({"jid": j["jid"], "ref": j.get("ref", ""), "title": j.get("title", "")})
        self._js("queue", {"left": len(self._pending) + (1 if self._cur else 0)})
        return out

    def stop_all(self):
        with self._lock:
            for j in self._pending:
                j["cancel"] = True
        if self._runner:
            self._runner.cancel()
        return True

    def _emit(self, lines):
        self._js("log", {"lines": lines})

    def _steps(self, j):
        k = j["kind"]
        wg = self._winget or winget_path() or "winget"
        common = ["--accept-source-agreements", "--disable-interactivity"]
        if k == "install":
            src = "msstore" if j["id"] in MSSTORE else "winget"
            return [("winget install " + j["id"], [wg, "install", "--id", j["id"], "-e", "--silent", "--source", src,
                                                    "--accept-package-agreements"] + common, "winget")]
        if k == "upgrade_all":
            return [("winget upgrade --all", [wg, "upgrade", "--all", "--silent", "--accept-package-agreements"] + common, "winget")]
        if k == "bloat":
            p = j["pat"].replace("'", "''")
            allu = bool(j.get("all"))
            sc = (f"$p='{p}'; $n=0\n"
                  f"Get-AppxPackage {'-AllUsers ' if allu else ''}-Name $p | ForEach-Object {{ try {{ Remove-AppxPackage -Package $_.PackageFullName "
                  f"{'-AllUsers ' if allu else ''}-ErrorAction Stop; 'Supprimé : ' + $_.Name; $n++ }} catch {{ 'Échec : ' + $_.Name + ' - ' + $_.Exception.Message }} }}\n")
            if allu:
                sc += ("Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $p | ForEach-Object { "
                       "Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName -ErrorAction SilentlyContinue | Out-Null; "
                       "'Retiré pour les nouveaux comptes : ' + $_.DisplayName }\n")
            sc += "if(-not $n){ 'Rien à supprimer pour ce compte.' }"
            return [("Remove-AppxPackage " + j["pat"], ps_cmd(sc), "ps")]
        if k == "setting":
            s = SET_BY_ID[j["id"]]
            return [(s["label"], ps_cmd(PS_HELP + s["apply"]), "ps")]
        if k == "explorer":
            return [("Redémarrage de l'Explorateur", ps_cmd("Stop-Process -Name explorer -Force; Start-Sleep 2; "
                                                             "if(-not (Get-Process explorer -ErrorAction SilentlyContinue)){ Start-Process explorer.exe }; "
                                                             "'Explorateur redémarré.'"), "ps")]
        if k == "rename":
            n = re.sub(r"[^A-Za-z0-9-]", "", j["name"])[:15]
            return [("Rename-Computer " + n, ps_cmd(f"Rename-Computer -NewName '{n}' -Force -ErrorAction Stop; "
                                                     f"'Le poste s''appellera {n} après redémarrage.'"), "ps")]
        if k == "winget_fix":
            return [("Réparation / installation de winget", ps_cmd(r"""
try { Add-AppxPackage -RegisterByFamilyName -MainPackage Microsoft.DesktopAppInstaller_8wekyb3d8bbwe -ErrorAction Stop; 'App Installer réenregistré.' }
catch { 'Réenregistrement impossible : ' + ($_.Exception.Message -split "`n")[0] }
$wg = "$env:LOCALAPPDATA\Microsoft\WindowsApps\winget.exe"
if (-not (Test-Path $wg)) {
  'Téléchargement de winget et de ses dépendances (dépôt GitHub officiel de Microsoft)...'
  $d = Join-Path $env:TEMP 'ea2_winget'; New-Item -ItemType Directory -Force $d | Out-Null
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
  $base = 'https://github.com/microsoft/winget-cli/releases/latest/download/'
  try {
    Invoke-WebRequest ($base + 'DesktopAppInstaller_Dependencies.zip') -OutFile "$d\deps.zip" -UseBasicParsing -ErrorAction Stop
    Expand-Archive "$d\deps.zip" "$d\deps" -Force
    $arch = if ([Environment]::Is64BitOperatingSystem) { 'x64' } else { 'x86' }
    Get-ChildItem "$d\deps" -Recurse -Filter *.appx | Where-Object { $_.FullName -match "\\$arch\\" } | ForEach-Object {
      try { Add-AppxPackage $_.FullName -ErrorAction Stop; 'Dépendance installée : ' + $_.Name }
      catch { 'Dépendance ' + $_.Name + ' : ' + ($_.Exception.Message -split "`n")[0] } }
    Invoke-WebRequest ($base + 'Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle') -OutFile "$d\winget.msixbundle" -UseBasicParsing -ErrorAction Stop
    Add-AppxPackage "$d\winget.msixbundle" -ErrorAction Stop
    'winget installé.'
  } catch { 'Installation impossible : ' + ($_.Exception.Message -split "`n")[0]; exit 1 }
  finally { Remove-Item $d -Recurse -Force -ErrorAction SilentlyContinue }
} else { 'winget est disponible.' }"""), "ps")]
        if k == "test":
            return [("winget show 7zip.7zip", [wg, "show", "--id", "7zip.7zip", "-e"] + common, "winget")]
        return []

    def _worker(self):
        while True:
            j = self._q.get()
            with self._lock:
                if j in self._pending:
                    self._pending.remove(j)
            if j.get("cancel"):
                self._js("job", {"jid": j["jid"], "ref": j.get("ref", ""), "st": "stopped", "msg": "Annulé"})
                self._js("queue", {"left": len(self._pending)})
                continue
            self._cur = j
            t0 = time.time()
            r = LiveRunner(self._emit)
            self._runner = r
            r.start_flusher()
            self._js("job", {"jid": j["jid"], "ref": j.get("ref", ""), "st": "run", "title": j.get("title", ""),
                             "time": time.strftime("%H:%M:%S"), "left": len(self._pending)})
            st, msg = "ok", ""
            try:
                for show, cmd, mode in self._steps(j):
                    r.line("> " + show, "cmd")
                    if mode == "winget":
                        code = self._stream_winget(r, cmd)
                    else:
                        code = r.stream(cmd)
                    if r.cancelled:
                        st, msg = "stopped", "Arrêté"
                        break
                    if code:
                        u = code & 0xFFFFFFFF
                        lvl, m = WINGET_CODES.get(u, ("err", f"code {u:#x}" if u > 0xFFFF else f"code {u}"))
                        st, msg = lvl, m
                        r.line(("Terminé : " if lvl != "err" else "Échec : ") + m, "ok" if lvl == "ok" else ("warn" if lvl == "warn" else "err"))
                        if lvl == "err":
                            txt = " ".join(t for t, _ in r.out[-15:]).lower()
                            if re.search(r"élévation|elevation|access is denied|accès refusé", txt):
                                msg = "droits administrateur requis"
                            break
            except FileNotFoundError:
                st, msg = "err", "winget introuvable : utiliser « Réparer winget »"
                r.line("Commande introuvable (winget absent ?)", "err")
            except Exception as e:
                st, msg = "err", f"{type(e).__name__}: {e}"
                r.line(msg, "err")
            r.stop_flusher()
            self._runner = None
            self._cur = None
            self._done.append({"jid": j["jid"], "kind": j["kind"], "ref": j.get("ref", ""), "st": st, "msg": msg,
                               "log": r.out[-40:]})
            self._js("job", {"jid": j["jid"], "ref": j.get("ref", ""), "st": st, "msg": msg, "dur": round(time.time() - t0),
                             "left": len(self._pending)})
            if self._q.empty():
                self._js("idle", {})

    def _stream_winget(self, r, cmd):
        orig = r.line

        def filt(text, kind="out"):
            if kind == "out":
                k = _winget_line(text)
                if k is None:
                    return
                kind = k
            elif kind == "prog" and not text.strip(" -\\|/"):
                return
            orig(text, kind)
        r.line = filt
        try:
            return r.stream(cmd)
        finally:
            r.line = orig

    # ---- autotest -------------------------------------------------------------- #
    def _fulltest(self):
        import ea2_install_tests
        ea2_install_tests.run_full(self)

    def _selftest(self):
        log = []
        try:
            time.sleep(2)
            ws = self.winget_status()
            log.append(f"winget={ws}")
            t = time.time()
            ins = self.installed()
            log.append(f"installés: {len(ins['ids'])} en {time.time() - t:.0f} s ; catalogue présents="
                       f"{[i for i in ins['ids'] if i in ALL_IDS]} err={ins.get('error')}")
            b = self.bloat_scan()
            log.append(f"bloat détectés: {[(x['label'], x['pkgs']) for x in b['found']]}")
            log.append(f"réglages: {self.settings_read()}")
            for _ in range(60):
                if self._eval("window.READY===true") is True:
                    break
                time.sleep(1)
            log.append("ui: tuiles=" + str(self._eval("document.querySelectorAll('.app-t').length")) +
                       " installées=" + str(self._eval("document.querySelectorAll('.app-t.inst').length")) +
                       " bloat_ui=" + str(self._eval("document.querySelectorAll('#bloatL .rowc').length")) +
                       " réglages_ui=" + str(self._eval("document.querySelectorAll('#setL .rowc').length")) +
                       " reco_constructeur=" + repr(self._eval("document.getElementById('maker').innerText")))
            self._eval("presetSel('B')")
            log.append("préréglage PME coché=" + str(self._eval("SEL.size")))
            self._eval("presetSel('none')")
            self.enqueue([{"kind": "test", "ref": "test", "title": "Test winget (show 7zip)"}])
            for _ in range(120):
                time.sleep(1)
                if self._done and self._done[-1]["kind"] == "test":
                    break
            d = self._done[-1] if self._done else {}
            log.append(f"job test: st={d.get('st')} msg={d.get('msg')!r} lignes={len(d.get('log', []))}")
            for tl, k in d.get("log", [])[:12]:
                log.append(f"   [{k}] {tl[:110]}")
            time.sleep(1)
            log.append("journal_ui=" + repr((self._eval("document.getElementById('jb').innerText") or "")[:300]))
            log.append("openSans=" + str(self._eval("document.fonts.check(\"600 16px 'Open Sans'\")")))
        except Exception as e:
            log.append(f"FAIL {type(e).__name__}: {e}")
        try:
            with open(self._args.selftest, "w", encoding="utf-8") as fh:
                fh.write("\n".join(str(x) for x in log))
        finally:
            self._window.destroy()


# --------------------------------------------------------------------------- #
# Interface
# --------------------------------------------------------------------------- #
CSS = r"""
.split{display:grid;grid-template-columns:minmax(0,1fr) 400px;gap:24px;max-width:1380px;margin:0 auto;padding:26px 30px 40px}
.split .view{padding:0;max-width:none;margin:0}
.side{position:sticky;top:0;align-self:start}
.jr{height:calc(100vh - 120px)}
.qbar{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.agrid{display:grid;grid-template-columns:repeat(auto-fill,minmax(250px,1fr));gap:10px;margin-bottom:22px}
.app-t{display:flex;gap:11px;align-items:flex-start;background:var(--panel);border:1px solid var(--line);border-radius:5px;padding:11px 13px;cursor:pointer;user-select:none}
.app-t:hover{border-color:rgba(245,156,26,.45)}.app-t.sel{border-color:var(--or);background:rgba(245,156,26,.07)}
.app-t.inst{opacity:.62;cursor:default}.app-t.inst:hover{border-color:var(--line)}
.app-t b{display:block;font-weight:600;color:#fff;font-size:13.5px}.app-t small{display:block;color:var(--mut);font-size:12px;line-height:1.35}
.app-t input{margin-top:2px;flex:none}.app-t .st{margin-top:5px}
.app-t.rec{border-color:rgba(73,182,214,.6)}
.rowc{display:flex;gap:14px;align-items:flex-start;padding:12px 4px;border-bottom:1px dashed var(--line)}.rowc:last-child{border:0}
.rowc .tx{flex:1}.rowc b{font-weight:600;color:#fff}.rowc small{display:block;color:var(--mut);font-size:12.5px}
.rowc input[type=checkbox]{margin-top:3px}
.right{display:flex;gap:6px;align-items:center;flex-wrap:wrap;justify-content:flex-end}
.cnt{color:var(--or);font-weight:700}
"""

BODY = r"""
<div class="split"><div>
<section class="view" id="v-apps">
 <div class="card"><h2>Installer des logiciels</h2>
  <p class="lead">Coche les logiciels puis lance l'installation : tout s'installe à la suite, en silencieux, depuis les sources officielles (winget).</p>
  <div id="wgNote"></div>
  <div class="qbar"><span class="lbl">Préréglages</span>
   <button class="btn2" onclick="presetSel('P')">Particulier</button><button class="btn2" onclick="presetSel('B')">Bureau / PME</button>
   <button class="btn2" onclick="presetSel('T')">Technicien</button><button class="lnk" onclick="presetSel('none')">Tout décocher</button>
   <input type="text" id="aFilter" placeholder="Rechercher un logiciel…" style="width:220px;margin-left:auto" oninput="appFilter()"></div>
  <div class="qbar" style="margin-top:14px"><span id="selInfo" class="host"></span><span id="instInfo" class="host"></span>
   <span style="margin-left:auto"></span><button class="btn2" onclick="upgradeAll()">Mettre à jour tous les logiciels</button>
   <button class="btn" id="bInst" onclick="installSel()" disabled>Installer la sélection</button></div>
  <div id="maker" style="margin-top:12px"></div></div>
 <div id="cat"></div>
</section>
<section class="view" id="v-bloat">
 <div class="card"><h2>Nettoyage des applications préinstallées</h2>
  <p class="lead">Retire les applications publicitaires ou inutiles livrées avec Windows ou le constructeur. Elles restent réinstallables depuis le Microsoft Store.</p>
  <div class="qbar"><label class="row" style="gap:8px;font-size:13px"><input type="checkbox" id="bAll">Supprimer aussi pour tous les comptes et les futurs comptes</label>
   <span style="margin-left:auto"></span><button class="btn2" onclick="bloatScan()">Analyser</button><button class="btn" id="bBloat" onclick="bloatRun()">Supprimer la sélection</button></div></div>
 <div class="card"><div id="bloatL"><div class="empty">Analyse en cours…</div></div></div>
</section>
<section class="view" id="v-set">
 <div class="card"><h2>Réglages Windows</h2>
  <p class="lead">Les réglages courants d'une mise en service, avec leur état actuel. Les réglages « Utilisateur » s'appliquent au compte connecté.</p>
  <div class="qbar"><button class="lnk" onclick="setAll(true)">Tout cocher</button><button class="lnk" onclick="setAll(false)">Tout décocher</button>
   <span style="margin-left:auto"></span><button class="btn2" onclick="setRead()">Relire l'état</button><button class="btn" id="bSet" onclick="setRun()">Appliquer la sélection</button></div></div>
 <div class="card"><div id="setL"></div></div>
 <div class="card"><h2>Nom du poste</h2><div class="row"><span class="host">Nom actuel : <b id="pcName" style="color:#fff"></b></span>
  <input type="text" id="newName" maxlength="15" placeholder="Nouveau nom (15 caractères max)" style="width:260px">
  <button class="btn2" onclick="renamePc()">Renommer</button><span class="host">Redémarrage nécessaire.</span></div></div>
</section>
</div>
<aside class="side"><div class="jr"><div class="jh"><span class="jt">Journal</span><span class="jcur" id="jcur">En attente</span>
 <button id="jStop" disabled onclick="stopAll()">Arrêter</button><button onclick="copyText($('#jb').innerText,'Journal copié.')">Copier</button></div>
 <div class="jb" id="jb"><div class="jl k-mut" data-placeholder="1">Les installations et actions s'affichent ici en direct.</div></div></div></aside>
</div>
<div class="ov" id="ov"><div class="md"><h3 id="mT"></h3><p id="mD"></p><div id="mL" class="pl mono" style="max-height:220px;overflow:auto;color:#cfd8e0;font-size:12.5px"></div>
 <div class="mb"><button class="btn2" onclick="$('#ov').classList.remove('show')">Annuler</button><button class="btn" id="mGo">Confirmer</button></div></div></div>
"""

JS = r"""
let INFO=null,INST=new Set(),SEL=new Set(),RUN=0,JOBREF={};window.READY=false;
const ST={queued:['','En file d\'attente'],run:['run','<span class="spin"></span>En cours…'],ok:['ok','✓ Terminé'],warn:['warn','Terminé (voir journal)'],err:['err','✗ Échec'],stopped:['','Annulé']};
window.addEventListener('pywebviewready',async()=>{const a=api();INFO=await a.info();
 $('#host').textContent=INFO.host+'  ·  '+INFO.os+(INFO.admin?'':'  ·  sans droits admin');buildCat();buildSet();$('#pcName').textContent=INFO.host;
 const w=await a.winget_status();wgShow(w);
 a.settings_read().then(setShow);bloatScan();
 if(w.version){$('#instInfo').innerHTML='<span class="spin"></span>Recherche des logiciels déjà installés…';a.installed().then(instShow)}
 window.READY=true;a.ready()});
function wgShow(w){const n=$('#wgNote');n.innerHTML='';if(!INFO.win){n.append(el('div','note w','Disponible sous Windows uniquement.'));return}
 if(!w.version){const d=el('div','note w');d.append(el('span',null,'winget est absent ou non initialisé sur ce poste (fréquent sur un PC neuf). '));
  const b=el('button','btn','Réparer winget');b.style.marginLeft='10px';b.onclick=()=>enq([{kind:'winget_fix',ref:'wg',title:'Réparation de winget'}]);d.append(b);n.append(d)}
 else n.append(el('div','note','winget '+w.version+' prêt.'+(INFO.admin?'':' Attention : lancé sans droits administrateur, certaines installations échoueront.')))}
function buildCat(){const box=$('#cat');box.innerHTML='';
 if(INFO.makerPkg){const m=$('#maker');m.innerHTML='';const d=el('div','note');d.append(el('span',null,'PC '+INFO.maker+' détecté : l\'outil de mise à jour des pilotes du constructeur est mis en avant.'));m.append(d)}
 for(const c of INFO.catalog){const h=el('div','grp',c.cat);box.append(h);const g=el('div','agrid');
  for(const it of c.items){const t=el('label','app-t'+(it.id===INFO.makerPkg?' rec':''));t.dataset.id=it.id;t.dataset.s=(it.name+' '+it.desc+' '+it.id).toLowerCase();
   const cb=el('input');cb.type='checkbox';cb.onchange=()=>{cb.checked?SEL.add(it.id):SEL.delete(it.id);t.classList.toggle('sel',cb.checked);selInfo()};
   const tx=el('div');tx.append(el('b',null,it.name),el('small',null,it.desc));const st=el('span','st');st.id='s-'+cssId(it.id);tx.append(st);
   if(it.id===INFO.makerPkg){tx.append(el('span','chip c-info','Recommandé pour ce PC'))}
   t.append(cb,tx);g.append(t)}box.append(g)}selInfo()}
const cssId=s=>s.replace(/[^A-Za-z0-9]/g,'_');
function tile(id){return $('.app-t[data-id="'+CSS.escape(id)+'"]')}
function instShow(r){INST=new Set(r.ids||[]);let n=0;for(const t of $$('.app-t')){const on=INST.has(t.dataset.id);t.classList.toggle('inst',on);
  const cb=t.querySelector('input');if(on){n++;cb.checked=false;cb.disabled=true;SEL.delete(t.dataset.id);t.classList.remove('sel');setTileSt(t.dataset.id,'ok','Installé')}else cb.disabled=false}
 $('#instInfo').textContent=r.error?'Détection des logiciels installés impossible ('+r.error+')':n+' logiciel(s) du catalogue déjà installé(s)';selInfo()}
function setTileSt(id,cls,html){const e=document.getElementById('s-'+cssId(id));if(e){e.className='st '+cls;e.innerHTML=html}}
function selInfo(){$('#selInfo').innerHTML=SEL.size?'<span class="cnt">'+SEL.size+'</span> logiciel(s) sélectionné(s)':'Aucun logiciel sélectionné';$('#bInst').disabled=!SEL.size}
function presetSel(p){SEL.clear();for(const c of INFO.catalog)for(const it of c.items)if(p!=='none'&&(it.presets.includes(p)||(p!=='T'&&it.id===INFO.makerPkg))&&!INST.has(it.id))SEL.add(it.id);
 for(const t of $$('.app-t')){const on=SEL.has(t.dataset.id);t.querySelector('input').checked=on;t.classList.toggle('sel',on)}selInfo()}
function appFilter(){const q=$('#aFilter').value.toLowerCase();for(const t of $$('.app-t'))t.style.display=!q||t.dataset.s.includes(q)?'':'none';
 for(const g of $$('#cat .agrid')){const any=[...g.children].some(t=>t.style.display!=='none');g.style.display=any?'':'none';g.previousElementSibling.style.display=any?'':'none'}}
function confirmBox(title,desc,lines,go){$('#mT').textContent=title;$('#mD').textContent=desc;const l=$('#mL');l.innerHTML='';for(const x of lines)l.append(el('div',null,'• '+x));
 $('#mGo').onclick=()=>{$('#ov').classList.remove('show');go()};$('#ov').classList.add('show')}
function installSel(){const ids=[...SEL];const names=ids.map(i=>INFO.catalog.flatMap(c=>c.items).find(x=>x.id===i).name);
 confirmBox('Installer '+ids.length+' logiciel(s)','Installation silencieuse, l\'une après l\'autre. Les licences des éditeurs sont acceptées automatiquement.',names,()=>{
  enq(ids.map((i,k)=>({kind:'install',id:i,ref:'app:'+i,title:'Installation de '+names[k]})));SEL.clear();
  for(const t of $$('.app-t')){t.querySelector('input').checked=false;t.classList.remove('sel')}selInfo()})}
function upgradeAll(){confirmBox('Mettre à jour tous les logiciels','winget met à jour tous les logiciels qu\'il sait gérer, en silencieux. Les applications ouvertes peuvent être fermées.',[],()=>enq([{kind:'upgrade_all',ref:'up',title:'Mise à jour de tous les logiciels'}]))}
function enq(jobs){const a=api();if(!a)return;a.enqueue(jobs).then(list=>{for(const j of list){JOBREF[j.jid]=j.ref;refSt(j.ref,'queued')}RUN+=list.length;$('#jStop').disabled=false})}
function refSt(ref,st,msg){const [c,h]=ST[st]||['',st];const html=h+(msg&&st!=='ok'?' : '+msg:'')+(st==='ok'&&msg?' ('+msg+')':'');
 if(ref.startsWith('app:'))setTileSt(ref.slice(4),c,html);else{const e=document.getElementById('s-'+cssId(ref));if(e){e.className='st '+c;e.innerHTML=html}}}
E.job=j=>{const ref=j.ref||JOBREF[j.jid]||'';if(j.st==='run'){$('#jcur').textContent=j.title+(j.left?'  ('+j.left+' en attente)':'');jline($('#jb'),j.time+'  ·  '+j.title,'hd')}
 else{RUN=Math.max(0,RUN-1);if(ref.startsWith('app:')&&j.st==='ok')INST.add(ref.slice(4))}
 refSt(ref,j.st,j.msg)};
E.log=d=>{for(const l of d.lines)jline($('#jb'),l.t,l.k)};
E.queue=q=>{};
E.idle=()=>{RUN=0;$('#jcur').textContent='Terminé';$('#jStop').disabled=true;toast('Toutes les tâches sont terminées.');
 const a=api();if(a){a.installed().then(instShow);a.settings_read().then(setShow)}};
function stopAll(){const a=api();if(a)a.stop_all()}
/* nettoyage */
let BL=[];
function bloatScan(){const a=api();if(!a)return;$('#bloatL').innerHTML='<div class="empty"><span class="spin"></span>Analyse des applications installées…</div>';
 a.bloat_scan().then(r=>{BL=r.found;const box=$('#bloatL');box.innerHTML='';
  if(!BL.length){box.append(el('div','empty','Aucune application superflue détectée sur ce compte.'));return}
  for(const b of BL){const row=el('label','rowc');const cb=el('input');cb.type='checkbox';cb.checked=b.def;cb.dataset.pat=b.pat;
   const tx=el('div','tx');tx.append(el('b',null,b.label),el('small',null,b.pkgs.join(', ')));const st=el('span','st');st.id='s-'+cssId('bl:'+b.pat);
   row.append(cb,tx,st);box.append(row)}})}
function bloatRun(){const pats=$$('#bloatL input:checked').map(c=>c.dataset.pat);if(!pats.length){toast('Rien de sélectionné.');return}
 const all=$('#bAll').checked;const labels=pats.map(p=>BL.find(b=>b.pat===p).label);
 confirmBox('Supprimer '+pats.length+' application(s)',all?'Suppression pour tous les comptes du poste et pour les futurs comptes.':'Suppression pour le compte actuel.',labels,
  ()=>enq(pats.map((p,i)=>({kind:'bloat',pat:p,all:all,ref:'bl:'+p,title:'Suppression : '+labels[i]}))))}
/* réglages */
function buildSet(){const box=$('#setL');box.innerHTML='';for(const s of INFO.settings){const row=el('label','rowc');const cb=el('input');cb.type='checkbox';cb.checked=s.def;cb.dataset.id=s.id;
 const tx=el('div','tx');tx.append(el('b',null,s.label),el('small',null,s.desc));const r=el('div','right');r.append(el('span','chip',s.scope));
 const cur=el('span','chip');cur.id='cur-'+s.id;cur.textContent='…';r.append(cur);const st=el('span','st');st.id='s-'+cssId('set:'+s.id);
 const col=el('div');col.style.textAlign='right';col.append(r,st);row.append(cb,tx,col);box.append(row)}}
function setRead(){const a=api();if(a)a.settings_read().then(setShow)}
function setShow(r){for(const s of INFO.settings){const c=document.getElementById('cur-'+s.id);if(!c)continue;const v=r[s.id];
 c.className='chip '+(v==='1'?'c-ok':v==='0'?'c-warn':'');c.textContent=v==='1'?'✓ Déjà appliqué':v==='0'?'Non appliqué':v==='na'?'Non concerné':'État inconnu';
 const cb=$('#setL input[data-id="'+s.id+'"]');if(v==='1'||v==='na')cb.checked=false}}
function setAll(v){for(const c of $$('#setL input'))c.checked=v}
function setRun(){const ids=$$('#setL input:checked').map(c=>c.dataset.id);if(!ids.length){toast('Rien de sélectionné.');return}
 const lab=ids.map(i=>INFO.settings.find(s=>s.id===i).label);
 confirmBox('Appliquer '+ids.length+' réglage(s)','L\'Explorateur Windows sera redémarré à la fin si nécessaire (la barre des tâches clignote quelques secondes).',lab,()=>{
  const jobs=ids.map((i,k)=>({kind:'setting',id:i,ref:'set:'+i,title:lab[k]}));jobs.push({kind:'explorer',ref:'exp',title:'Redémarrage de l\'Explorateur'});enq(jobs)})}
function renamePc(){const n=$('#newName').value.trim();if(!/^[A-Za-z0-9-]{1,15}$/.test(n)||/^\d+$/.test(n)){toast('Nom invalide : lettres, chiffres et tirets, 15 caractères maximum.');return}
 confirmBox('Renommer le poste en '+n,'Le nouveau nom sera pris en compte après le redémarrage.',[],()=>enq([{kind:'rename',name:n,ref:'ren',title:'Renommage du poste en '+n}]))}
"""


def main():
    ap = argparse.ArgumentParser(description=f"{APP} - préparation de PC")
    ap.add_argument("--selftest", default="", help=argparse.SUPPRESS)
    ap.add_argument("--fulltest", default="", help=argparse.SUPPRESS)
    args = ap.parse_args()
    html = build_page("install", APP, "Préparation de PC",
                      [("apps", "Logiciels"), ("bloat", "Nettoyage"), ("set", "Réglages")],
                      BODY, CSS, JS, nav="<span class='host' id='host'></span>")
    return run_window(f"{APP} - Préparation de PC", html, InstallBridge(args))


if __name__ == "__main__":
    finish(main())
