#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
E-A2 Scan - Collecteur de diagnostic poste (Windows / macOS / Linux)

Lance un diagnostic complet de la machine sur laquelle il s'exécute et produit
un rapport HTML autonome (imprimable / exportable en PDF) + un JSON brut.

Dépendances : aucune obligatoire (stdlib). `psutil` est utilisé s'il est présent
(plus précis, plus rapide). Python >= 3.8.

Exemples :
    python diag_poste.py
    python diag_poste.py --client "Dupont SARL" --tech "Prénom Nom"
    python diag_poste.py --quick --no-open
    python diag_poste.py --software --public-ip

Pour un diagnostic complet (SMART, BitLocker, journaux, pare-feu), lancer en
administrateur (Windows) ou avec sudo (Linux / macOS).
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import datetime as dt
import glob
import html
import json
import os
import platform
import plistlib
import re
import shutil
import socket
import string
import struct
import subprocess
import sys
import tempfile
import threading
import time
import webbrowser
from pathlib import Path

try:
    import psutil  # type: ignore
except Exception:  # pragma: no cover
    psutil = None

APP_NAME = "E-A2 Scan"
VERSION = "1.0.0"
SYSTEM = platform.system()
IS_WIN, IS_MAC, IS_LINUX = SYSTEM == "Windows", SYSTEM == "Darwin", SYSTEM == "Linux"
OK, WARN, CRIT, INFO = "ok", "warn", "crit", "info"


# --------------------------------------------------------------------------- #
# Utilitaires
# --------------------------------------------------------------------------- #
def base_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


def run(cmd, timeout=20, shell=False, encoding=None, merge=False) -> str:
    """Exécute une commande, renvoie la sortie texte ('' en cas d'échec)."""
    kw = {}
    if IS_WIN:
        kw["creationflags"] = 0x08000000  # CREATE_NO_WINDOW
    try:
        p = subprocess.run(
            cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT if merge else subprocess.PIPE,
            text=True, encoding=encoding, errors="replace",
            timeout=timeout, shell=shell, **kw)
        return (p.stdout or "").strip()
    except Exception:
        return ""


def ps(script: str, timeout=40) -> str:
    if not IS_WIN:
        return ""
    pre = ("[Console]::OutputEncoding=[Text.Encoding]::UTF8;"
           "$ProgressPreference='SilentlyContinue';")
    return run(["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy",
                "Bypass", "-Command", pre + script], timeout=timeout, encoding="utf-8")


def ps_json(script: str, timeout=40):
    out = ps(script, timeout)
    if not out:
        return None
    try:
        return json.loads(out)
    except Exception:
        return None


def as_list(x):
    if x is None:
        return []
    return x if isinstance(x, list) else [x]


def which(name):
    return shutil.which(name)


def is_admin() -> bool:
    try:
        if IS_WIN:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0
    except Exception:
        return False


def hsize(n) -> str:
    n = float(n)
    for u in ("o", "Ko", "Mo", "Go", "To"):
        if n < 1024 or u == "To":
            return f"{n:.0f} {u}" if u == "o" else f"{n:.1f} {u}"
        n /= 1024
    return str(n)


def hdur(sec) -> str:
    sec = int(sec)
    d, r = divmod(sec, 86400)
    h, r = divmod(r, 3600)
    m, _ = divmod(r, 60)
    return (f"{d} j " if d else "") + f"{h} h {m:02d} min"


def f(level, title, detail=""):
    return {"level": level, "title": title, "detail": detail}


def section(key, title, findings=None, tables=None, pre="", collapse=False):
    return {"key": key, "title": title, "findings": findings or [],
            "tables": tables or [], "pre": pre, "collapse": collapse}


def table(caption, headers, rows):
    return {"caption": caption, "headers": headers, "rows": rows}


def boot_time():
    try:
        if psutil:
            return psutil.boot_time()
        if IS_LINUX:
            with open("/proc/uptime") as fh:
                return time.time() - float(fh.read().split()[0])
        if IS_WIN:
            import ctypes
            k = ctypes.windll.kernel32
            k.GetTickCount64.restype = ctypes.c_ulonglong
            return time.time() - k.GetTickCount64() / 1000.0
        if IS_MAC:
            m = re.search(r"sec = (\d+)", run(["sysctl", "-n", "kern.boottime"]))
            return float(m.group(1)) if m else None
    except Exception:
        pass
    return None


def pending_reboot():
    try:
        if IS_WIN:
            import winreg  # type: ignore
            keys = [r"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending",
                    r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"]
            for k in keys:
                try:
                    winreg.CloseKey(winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, k))
                    return True
                except OSError:
                    pass
            return False
        if IS_LINUX:
            return os.path.exists("/var/run/reboot-required")
    except Exception:
        pass
    return None


def kv_lines(text, sep=":"):
    d = {}
    for line in text.splitlines():
        if sep in line:
            k, _, v = line.partition(sep)
            d.setdefault(k.strip(), v.strip())
    return d


# --------------------------------------------------------------------------- #
# Section : Système
# --------------------------------------------------------------------------- #
def sec_system(args):
    F, rows = [], []
    host = socket.gethostname()
    osname = f"{platform.system()} {platform.release()}"
    manu = model = serial = cpu = ""
    extra = []

    if IS_WIN:
        j = ps_json(
            r"""$o=Get-CimInstance Win32_OperatingSystem;$c=Get-CimInstance Win32_ComputerSystem;$b=Get-CimInstance Win32_BIOS;$p=Get-CimInstance Win32_Processor|Select-Object -First 1;$v=(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue).DisplayVersion;[pscustomobject]@{os=$o.Caption;build=$o.BuildNumber;ver=$v;man=$c.Manufacturer;model=$c.Model;serial=$b.SerialNumber;cpu=$p.Name;domain=$c.Domain;pd=[bool]$c.PartOfDomain}|ConvertTo-Json""") or {}
        cap = (j.get("os") or osname).strip()
        osname = f"{cap} (build {j.get('build', '?')}" + (f", {j['ver']}" if j.get("ver") else "") + ")"
        manu, model, serial, cpu = j.get("man", ""), j.get("model", ""), j.get("serial", ""), j.get("cpu", "")
        extra.append(["Domaine / groupe de travail",
                      (j.get("domain") or "?") + (" (domaine AD)" if j.get("pd") else " (workgroup)")])
        low = cap.lower()
        if re.search(r"windows (xp|vista|7|8)\b|server 200[38]", low):
            F.append(f(CRIT, "Système d'exploitation en fin de vie", cap))
        elif "windows 10" in low or "server 2012" in low:
            F.append(f(WARN, "OS en fin de support standard",
                       f"{cap} : plus de mises à jour de sécurité gratuites sauf programme ESU. Prévoir la migration."))
    elif IS_MAC:
        ver = run(["sw_vers", "-productVersion"])
        osname = f"macOS {ver}" if ver else osname
        hw = kv_lines(run(["system_profiler", "SPHardwareDataType"], timeout=30))
        manu = "Apple"
        model = f"{hw.get('Model Name', '')} ({hw.get('Model Identifier', '')})".strip()
        serial = hw.get("Serial Number (system)", "")
        cpu = hw.get("Chip") or hw.get("Processor Name", "")
        if hw.get("Total Number of Cores"):
            cpu += f" - {hw['Total Number of Cores']} cœurs"
    else:
        try:
            osr = kv_lines(Path("/etc/os-release").read_text(), "=")
            osname = osr.get("PRETTY_NAME", osname).strip('"') + f" (noyau {platform.release()})"
        except Exception:
            pass

        def dmi(n):
            try:
                return Path(f"/sys/class/dmi/id/{n}").read_text().strip()
            except Exception:
                return ""
        manu, model, serial = dmi("sys_vendor"), dmi("product_name"), dmi("product_serial")
        try:
            for line in Path("/proc/cpuinfo").read_text().splitlines():
                if line.lower().startswith(("model name", "hardware", "model\t")):
                    cpu = line.split(":", 1)[1].strip()
                    break
        except Exception:
            pass
        if not cpu:
            cpu = platform.processor()

    if not cpu and IS_WIN is False:
        cpu = platform.processor()

    cpu = re.sub(r"\s+", " ", cpu or "").strip()
    if re.search(r"o\.?e\.?m|default string|not specified|system serial|^0+$|^none$", serial or "", re.I):
        serial = "non renseigné par le constructeur"
    rows += [["Nom de la machine", host], ["Système", osname],
             ["Architecture", platform.machine()],
             ["Constructeur / modèle", f"{manu} {model}".strip() or "n/a"],
             ["N° de série", serial or "n/a (droits root requis ?)"],
             ["Processeur", f"{cpu} ({os.cpu_count()} threads)" if cpu else f"{os.cpu_count()} threads"]]
    rows += extra
    rows.append(["Utilisateur courant", os.environ.get("USERNAME") or os.environ.get("USER") or "?"])
    rows.append(["Droits administrateur", "oui" if is_admin() else "non (certains contrôles seront limités)"])

    bt = boot_time()
    if bt:
        up = time.time() - bt
        rows.append(["Dernier démarrage", dt.datetime.fromtimestamp(bt).strftime("%d/%m/%Y %H:%M")])
        rows.append(["Uptime", hdur(up)])
        if up > 30 * 86400:
            F.append(f(WARN, f"Uptime élevé : {hdur(up)}",
                       "Redémarrage conseillé (mises à jour en attente, fuites mémoire). "
                       "Sous Windows, le démarrage rapide peut masquer un vrai redémarrage."))
    pr = pending_reboot()
    if pr:
        F.append(f(WARN, "Redémarrage en attente", "Une mise à jour ou installation demande un redémarrage."))
    if not F:
        F.append(f(OK, "Informations système collectées"))
    return section("system", "Système", F, [table(None, ["Élément", "Valeur"], rows)])


# --------------------------------------------------------------------------- #
# Section : Ressources (CPU, RAM, batterie, température)
# --------------------------------------------------------------------------- #
def mem_info():
    try:
        if psutil:
            v = psutil.virtual_memory()
            return v.total, v.available
        if IS_LINUX:
            d = {}
            for line in Path("/proc/meminfo").read_text().splitlines():
                k, _, v = line.partition(":")
                d[k] = int(v.split()[0]) * 1024
            return d["MemTotal"], d.get("MemAvailable", d.get("MemFree", 0))
        if IS_WIN:
            import ctypes

            class MS(ctypes.Structure):
                _fields_ = [("dwLength", ctypes.c_ulong), ("dwMemoryLoad", ctypes.c_ulong),
                            ("ullTotalPhys", ctypes.c_ulonglong), ("ullAvailPhys", ctypes.c_ulonglong),
                            ("ullTotalPageFile", ctypes.c_ulonglong), ("ullAvailPageFile", ctypes.c_ulonglong),
                            ("ullTotalVirtual", ctypes.c_ulonglong), ("ullAvailVirtual", ctypes.c_ulonglong),
                            ("sullAvailExtendedVirtual", ctypes.c_ulonglong)]
            s = MS()
            s.dwLength = ctypes.sizeof(MS)
            ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(s))
            return s.ullTotalPhys, s.ullAvailPhys
        if IS_MAC:
            return int(run(["sysctl", "-n", "hw.memsize"]) or 0), None
    except Exception:
        pass
    return None, None


def battery_health():
    """Retourne dict(design, full, cycles, condition) ou None."""
    try:
        if IS_LINUX:
            for b in glob.glob("/sys/class/power_supply/BAT*"):
                def rd(n):
                    try:
                        return int(Path(b, n).read_text())
                    except Exception:
                        return None
                full = rd("energy_full") or rd("charge_full")
                design = rd("energy_full_design") or rd("charge_full_design")
                if full and design:
                    return {"design": design, "full": full, "cycles": rd("cycle_count")}
        elif IS_WIN:
            tmp = os.path.join(tempfile.gettempdir(), "diag_batt.xml")
            run(["powercfg", "/batteryreport", "/xml", "/output", tmp], timeout=30)
            if os.path.exists(tmp):
                txt = Path(tmp).read_text(encoding="utf-8", errors="replace")
                os.remove(tmp)
                d = re.search(r"<DesignCapacity>(\d+)</DesignCapacity>", txt)
                fc = re.search(r"<FullChargeCapacity>(\d+)</FullChargeCapacity>", txt)
                cc = re.search(r"<CycleCount>(\d+)</CycleCount>", txt)
                if d and fc:
                    return {"design": int(d.group(1)), "full": int(fc.group(1)),
                            "cycles": int(cc.group(1)) if cc else None}
        elif IS_MAC:
            out = run(["system_profiler", "SPPowerDataType"], timeout=30)
            m = re.search(r"Maximum Capacity:\s*(\d+)%", out)
            c = re.search(r"Cycle Count:\s*(\d+)", out)
            cond = re.search(r"Condition:\s*(\w+)", out)
            if m:
                return {"design": 100, "full": int(m.group(1)),
                        "cycles": int(c.group(1)) if c else None,
                        "condition": cond.group(1) if cond else None}
    except Exception:
        pass
    return None


def sec_resources(args):
    F, rows = [], []
    n = os.cpu_count() or 1
    if psutil:
        cpu = psutil.cpu_percent(interval=1.0)
        rows.append(["Charge CPU (échantillon 1 s)", f"{cpu:.0f} %"])
        if cpu > 90:
            F.append(f(WARN, f"CPU très chargé ({cpu:.0f} %)", "Voir les processus gourmands plus bas."))
    elif hasattr(os, "getloadavg"):
        l1, l5, l15 = os.getloadavg()
        rows.append(["Load average (1/5/15 min)", f"{l1:.2f} / {l5:.2f} / {l15:.2f} ({n} threads)"])
        if l5 / n > 1.5:
            F.append(f(WARN, "Charge système élevée", f"Load 5 min = {l5:.2f} pour {n} threads."))

    total, avail = mem_info()
    if total:
        rows.append(["RAM totale", hsize(total)])
        if avail is not None:
            used_pct = 100 * (total - avail) / total
            rows.append(["RAM utilisée", f"{hsize(total - avail)} ({used_pct:.0f} %)"])
            if used_pct > 95:
                F.append(f(CRIT, f"Mémoire quasi saturée ({used_pct:.0f} %)"))
            elif used_pct > 85:
                F.append(f(WARN, f"Mémoire fortement utilisée ({used_pct:.0f} %)"))
        if total < 7.5 * 1024 ** 3:
            F.append(f(WARN, f"RAM limitée : {hsize(total)}",
                       "Moins de 8 Go : une extension améliore nettement le confort en usage actuel."))
    if psutil:
        try:
            sw = psutil.swap_memory()
            if sw.total:
                rows.append(["Swap / fichier d'échange", f"{hsize(sw.used)} / {hsize(sw.total)} ({sw.percent:.0f} %)"])
                if sw.percent > 80:
                    F.append(f(WARN, f"Swap très utilisé ({sw.percent:.0f} %)", "Signe de manque de RAM."))
        except Exception:
            pass
        try:
            temps = psutil.sensors_temperatures() if hasattr(psutil, "sensors_temperatures") else {}
            vals = [t.current for lst in temps.values() for t in lst if t.current]
            if vals:
                mx = max(vals)
                rows.append(["Température max relevée", f"{mx:.0f} °C"])
                if mx >= 95:
                    F.append(f(CRIT, f"Température critique ({mx:.0f} °C)"))
                elif mx >= 85:
                    F.append(f(WARN, f"Température élevée ({mx:.0f} °C)", "Nettoyage ventilation / pâte thermique à envisager."))
        except Exception:
            pass

    has_batt = None
    try:
        if psutil and hasattr(psutil, "sensors_battery"):
            b = psutil.sensors_battery()
            has_batt = b is not None
            if b:
                rows.append(["Batterie (charge)", f"{b.percent:.0f} % ({'secteur' if b.power_plugged else 'sur batterie'})"])
    except Exception:
        pass
    if has_batt is not False:
        bh = battery_health()
        if bh:
            pct = 100.0 * bh["full"] / bh["design"] if bh["design"] else None
            if pct is not None:
                rows.append(["Santé batterie", f"{pct:.0f} % de la capacité d'origine"])
                if pct < 60:
                    F.append(f(CRIT, f"Batterie très usée ({pct:.0f} %)", "Remplacement recommandé."))
                elif pct < 80:
                    F.append(f(WARN, f"Batterie usée ({pct:.0f} %)", "Autonomie dégradée."))
            if bh.get("cycles") is not None:
                rows.append(["Cycles de charge", str(bh["cycles"])])
            if bh.get("condition") and bh["condition"].lower() not in ("normal",):
                F.append(f(WARN, f"État batterie macOS : {bh['condition']}"))
    if not F:
        F.append(f(OK, "Ressources normales"))
    return section("resources", "Ressources & matériel", F, [table(None, ["Mesure", "Valeur"], rows)])


# --------------------------------------------------------------------------- #
# Section : Disques & SMART
# --------------------------------------------------------------------------- #
SKIP_FS = {"squashfs", "iso9660", "udf", "tmpfs", "devtmpfs", "overlay", "proc", "sysfs", "cgroup",
           "autofs", "fuse.portal", "fuse.gvfsd-fuse", "efivarfs", ""}


def disk_usages():
    out = []
    if psutil:
        for p in psutil.disk_partitions(all=False):
            if p.fstype.lower() in SKIP_FS or "loop" in p.device:
                continue
            mp = p.mountpoint
            if mp.startswith(("/snap", "/var/lib/snapd", "/boot/efi")):
                continue
            if IS_MAC and mp.startswith("/System/Volumes/") and mp != "/System/Volumes/Data":
                continue
            try:
                u = psutil.disk_usage(mp)
            except Exception:
                continue
            if u.total:
                out.append((mp, p.device, p.fstype, u.total, u.used, u.free))
    else:
        mounts = [f"{l}:\\" for l in string.ascii_uppercase if os.path.exists(f"{l}:\\")] if IS_WIN else ["/"]
        for mp in mounts:
            try:
                u = shutil.disk_usage(mp)
                out.append((mp, "", "", u.total, u.used, u.free))
            except Exception:
                pass
    return out


def find_smartctl():
    cands = [which("smartctl")]
    for b in (base_dir(), base_dir() / "bin"):
        cands += [str(b / "smartctl.exe"), str(b / "smartctl")]
    cands += [r"C:\Program Files\smartmontools\bin\smartctl.exe",
              r"C:\Program Files (x86)\smartmontools\bin\smartctl.exe",
              "/opt/homebrew/bin/smartctl", "/usr/local/sbin/smartctl", "/usr/sbin/smartctl"]
    for c in cands:
        if c and os.path.exists(c):
            return c
    return None


def parse_smart(out):
    r = {"model": "", "health": None, "alerts": [], "facts": []}
    m = re.search(r"(?:Device Model|Model Number|Product|Model Family):\s*(.+)", out)
    if m:
        r["model"] = m.group(1).strip()
    m = re.search(r"overall-health self-assessment test result:\s*(\w+)", out)
    if m:
        r["health"] = m.group(1).upper()
    m = re.search(r"SMART Health Status:\s*(\w+)", out)
    if m and not r["health"]:
        r["health"] = "PASSED" if m.group(1).upper() == "OK" else m.group(1).upper()
    attrs = {}
    for line in out.splitlines():
        mm = re.match(r"^\s*(\d+)\s+(\S+)\s+0x\w+\s+\d+\s+\d+\s+\d+\s+\S+\s+\S+\s+\S+\s+(\d+)", line)
        if mm:
            attrs[int(mm.group(1))] = (mm.group(2), int(mm.group(3)))
    if 9 in attrs:
        r["facts"].append(f"{attrs[9][1]} h de fonctionnement")
    for tid in (194, 190):
        if tid in attrs:
            r["facts"].append(f"{attrs[tid][1] & 0xFF} °C")
            break
    for aid, label, lvl in ((197, "secteurs en attente de réallocation", CRIT),
                            (198, "secteurs non corrigibles hors-ligne", CRIT),
                            (5, "secteurs réalloués", WARN), (187, "erreurs non corrigées signalées", WARN)):
        if aid in attrs and attrs[aid][1] > 0:
            r["alerts"].append((lvl, f"{attrs[aid][1]} {label}"))
    m = re.search(r"Percentage Used:\s+(\d+)%", out)
    if m:
        used = int(m.group(1))
        r["facts"].append(f"usure NVMe {used} %")
        if used >= 90:
            r["alerts"].append((CRIT, f"SSD usé à {used} %"))
        elif used >= 80:
            r["alerts"].append((WARN, f"SSD usé à {used} %"))
    m = re.search(r"Media and Data Integrity Errors:\s+(\d+)", out)
    if m and int(m.group(1)) > 0:
        r["alerts"].append((WARN, f"{m.group(1)} erreurs d'intégrité NVMe"))
    m = re.search(r"Critical Warning:\s+0x([0-9a-fA-F]+)", out)
    if m and int(m.group(1), 16) != 0:
        r["alerts"].append((CRIT, f"Critical Warning NVMe = 0x{m.group(1)}"))
    m = re.search(r"^Temperature:\s+(\d+) Celsius", out, re.M)
    if m:
        r["facts"].append(f"{m.group(1)} °C")
        if int(m.group(1)) >= 70:
            r["alerts"].append((WARN, f"Température disque {m.group(1)} °C"))
    return r


def sec_disks(args):
    F, tables = [], []
    rows = []
    for mp, dev, fs, total, used, free in disk_usages():
        pct_free = 100.0 * free / total if total else 0
        status = "OK"
        if total >= 1024 ** 3:
            if pct_free < 5:
                status = "CRITIQUE"
                F.append(f(CRIT, f"Volume {mp} presque plein", f"{hsize(free)} libres ({pct_free:.0f} %)."))
            elif pct_free < 15:
                status = "FAIBLE"
                F.append(f(WARN, f"Peu d'espace libre sur {mp}", f"{hsize(free)} libres ({pct_free:.0f} %)."))
        rows.append([mp, dev, fs, hsize(total), hsize(used), f"{hsize(free)} ({pct_free:.0f} %)", status])
    tables.append(table("Volumes", ["Montage", "Périphérique", "FS", "Taille", "Utilisé", "Libre", "État"], rows))

    srows = []
    sc = find_smartctl()
    smart_done = False
    if sc:
        scan = run([sc, "--scan"], timeout=20)
        devs = []
        for line in scan.splitlines():
            parts = line.split("#")[0].split()
            if parts:
                dev = parts[0]
                dtype = parts[parts.index("-d") + 1] if "-d" in parts and parts.index("-d") + 1 < len(parts) else None
                devs.append((dev, dtype))
        for dev, dtype in devs:
            cmd = [sc, "-H", "-A", "-i", dev] + (["-d", dtype] if dtype else [])
            out = run(cmd, timeout=30, merge=True)
            if "Permission denied" in out or "Operation not permitted" in out:
                F.append(f(INFO, f"SMART {dev} : droits insuffisants", "Relancer en administrateur / root."))
                continue
            r = parse_smart(out)
            if not r["health"] and not r["facts"]:
                continue
            smart_done = True
            state = r["health"] or "?"
            srows.append([dev, r["model"] or "?", state, "; ".join(r["facts"]) or "-",
                          "; ".join(a[1] for a in r["alerts"]) or "-"])
            if r["health"] == "FAILED":
                F.append(f(CRIT, f"SMART en échec sur {dev}", f"{r['model']} : sauvegarder immédiatement les données."))
            for lvl, msg in r["alerts"]:
                F.append(f(lvl, f"{dev} ({r['model']}) : {msg}"))
    if IS_WIN:
        j = ps_json(r"Get-PhysicalDisk -ErrorAction SilentlyContinue|ForEach-Object{[pscustomobject]@{n=$_.FriendlyName;t=[string]$_.MediaType;h=[string]$_.HealthStatus;o=[string]$_.OperationalStatus;s=[int64]$_.Size}}|ConvertTo-Json")
        for d in as_list(j):
            h = d.get("h", "")
            srows.append([d.get("n", "?"), d.get("t", ""), f"Windows: {h}", hsize(d.get("s", 0)), d.get("o", "")])
            smart_done = True
            if h and h.lower() != "healthy":
                F.append(f(CRIT if h.lower() == "unhealthy" else WARN, f"Disque {d.get('n')} : santé Windows « {h} »"))
    elif IS_MAC and not smart_done:
        out = run(["diskutil", "info", "disk0"], timeout=20)
        m = re.search(r"SMART Status:\s*(.+)", out)
        if m:
            st = m.group(1).strip()
            srows.append(["disk0", "interne", st, "-", "-"])
            if st.lower().startswith("fail"):
                F.append(f(CRIT, "SMART macOS : disque défaillant"))
    elif IS_LINUX:
        lb = run(["lsblk", "-d", "-o", "NAME,MODEL,SIZE,ROTA,TYPE"], timeout=10)
        if lb:
            tables.append(table("Disques physiques (lsblk)", ["Détail"], [[l] for l in lb.splitlines()]))
    if not sc and not IS_WIN:
        F.append(f(INFO, "smartctl absent : santé SMART détaillée non évaluée",
                   "Installer smartmontools (apt/dnf/brew install smartmontools) et lancer en root."))
    elif not sc and IS_WIN:
        F.append(f(INFO, "smartctl.exe absent : seul l'état de santé Windows est lu",
                   "Placer smartctl.exe (smartmontools) à côté de diag_poste.exe pour les attributs SMART détaillés."))
    if srows:
        tables.append(table("Santé des disques", ["Disque", "Modèle", "Santé", "Infos", "Alertes"], srows))
    if not any(x["level"] in (WARN, CRIT) for x in F):
        F.insert(0, f(OK, "Espace disque et santé disque corrects"))
    return section("disks", "Disques & SMART", F, tables)


# --------------------------------------------------------------------------- #
# Section : Réseau
# --------------------------------------------------------------------------- #
def default_gateway():
    try:
        if IS_WIN:
            return ps(r"(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue|Sort-Object RouteMetric|Select-Object -First 1).NextHop").strip() or None
        if IS_LINUX:
            m = re.search(r"default via (\S+)", run(["ip", "route", "show", "default"]))
            return m.group(1) if m else None
        if IS_MAC:
            m = re.search(r"gateway:\s*(\S+)", run(["route", "-n", "get", "default"]))
            return m.group(1) if m else None
    except Exception:
        pass
    return None


def dns_servers():
    res = []
    try:
        if IS_WIN:
            res = ps(r"Get-DnsClientServerAddress -AddressFamily IPv4|ForEach-Object{$_.ServerAddresses}|Select-Object -Unique").split()
        elif IS_MAC:
            res = re.findall(r"nameserver\[\d+\]\s*:\s*(\S+)", run(["scutil", "--dns"]))
        else:
            res = re.findall(r"^nameserver\s+(\S+)", Path("/etc/resolv.conf").read_text(), re.M)
            if res and all(r.startswith("127.") for r in res) and which("resolvectl"):
                real = re.findall(r"(\d+\.\d+\.\d+\.\d+)", run(["resolvectl", "dns"]))
                res = real or res
    except Exception:
        pass
    seen, out = set(), []
    for r in res:
        if r not in seen:
            seen.add(r)
            out.append(r)
    return out


def ping(host, count=5):
    if not which("ping"):
        return None
    if IS_WIN:
        cmd = ["ping", "-n", str(count), "-w", "2000", host]
    elif IS_LINUX:
        cmd = ["ping", "-c", str(count), "-W", "2", host]
    else:
        cmd = ["ping", "-c", str(count), "-W", "2000", host]
    out = run(cmd, timeout=count * 3 + 5, merge=True)
    if not out:
        return None
    loss = re.search(r"(\d+(?:\.\d+)?)\s*%", out)
    r = {"loss": float(loss.group(1)) if loss else 100.0, "avg": None, "jitter": None}
    m = re.search(r"=\s*([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)", out)
    if m:
        r["avg"], r["jitter"] = float(m.group(2)), float(m.group(4))
    else:
        ms = re.findall(r"=\s*(\d+)\s*ms", out)
        if ms:
            r["avg"] = float(ms[-1])
    return r


def dns_query(server, name="example.com", timeout=2.0):
    import random
    tid = random.randint(0, 65535)
    hdr = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    q = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00" + struct.pack(">HH", 1, 1)
    if "%" in server:
        return False, None
    fam = socket.AF_INET6 if ":" in server else socket.AF_INET
    s = socket.socket(fam, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    t = time.perf_counter()
    try:
        s.sendto(hdr + q, (server, 53))
        data, _ = s.recvfrom(512)
        ms = (time.perf_counter() - t) * 1000
        ok = len(data) >= 12 and struct.unpack(">H", data[:2])[0] == tid and (data[3] & 0x0F) == 0
        return ok, ms
    except Exception:
        return False, None
    finally:
        s.close()


def resolve(name):
    t = time.perf_counter()
    try:
        socket.getaddrinfo(name, 443)
        return True, (time.perf_counter() - t) * 1000
    except Exception:
        return False, None


def tcp_connect(host, port, timeout=4.0):
    t = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True, (time.perf_counter() - t) * 1000
    except Exception:
        return False, None


def http_get(url, timeout=5.0):
    import urllib.request
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "diag_poste"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read(200).decode("utf-8", "replace")
    except Exception as e:
        code = getattr(e, "code", None)
        return code, ""


def wifi_info():
    rows, sig = "", None
    try:
        if IS_WIN:
            out = run(["netsh", "wlan", "show", "interfaces"], timeout=10, merge=True)
            if re.search(r"SSID\s*:", out):
                rows = out
                m = re.search(r"Signal\s*:\s*(\d+)\s*%", out)
                sig = int(m.group(1)) if m else None
        elif IS_LINUX and which("nmcli"):
            out = run(["nmcli", "-t", "-f", "ACTIVE,SSID,SIGNAL,CHAN,RATE,SECURITY", "dev", "wifi"], timeout=10)
            for line in out.splitlines():
                if line.startswith("yes"):
                    rows = line.replace(":", "  |  ")
                    parts = line.split(":")
                    sig = int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else None
                    break
    except Exception:
        pass
    return rows, sig


def sec_network(args):
    F, tables = [], []
    pre = ""
    gw, dns = default_gateway(), dns_servers()
    rows, apipa = [], False
    apipa_up, good_up = [], []
    if psutil:
        try:
            stats = psutil.net_if_stats()
            for name, addrs in psutil.net_if_addrs().items():
                if name == "lo" or name.startswith(("veth", "docker", "br-", "virbr", "lo0", "utun", "awdl",
                                                    "llw", "anpi", "gif", "stf", "ap1")):
                    continue
                v4 = [a.address for a in addrs if a.family == socket.AF_INET]
                mac = [a.address for a in addrs if a.family == getattr(psutil, "AF_LINK", -1)]
                st = stats.get(name)
                up = bool(st and st.isup)
                if not up and not v4:
                    continue
                if up and any(a.startswith("169.254.") for a in v4):
                    apipa_up.append(name)
                elif up and v4 and not any(a.startswith("127.") for a in v4):
                    good_up.append(name)
                rows.append([name, "UP" if up else "down",
                             f"{st.speed} Mb/s" if st and st.speed else "-",
                             ", ".join(v4) or "-", mac[0] if mac else "-"])
        except Exception:
            pass
    if rows:
        tables.append(table("Interfaces", ["Interface", "État", "Lien", "IPv4", "MAC"], rows))
    else:
        if IS_WIN:
            pre = run(["ipconfig", "/all"], timeout=15)
        elif IS_LINUX:
            pre = run(["ip", "-br", "addr"], timeout=10)
        else:
            pre = run(["ifconfig"], timeout=10)
        if "169.254." in pre:
            apipa = True
    tables.append(table("Configuration IP", ["Élément", "Valeur"],
                        [["Passerelle par défaut", gw or "aucune"],
                         ["Serveurs DNS", ", ".join(dns) or "aucun"]]))
    if apipa_up and not good_up:
        F.append(f(CRIT, "Adresse APIPA (169.254.x.x) détectée : aucune interface avec une IP valide",
                   f"Interface(s) : {', '.join(apipa_up)}. Pas de bail DHCP : vérifier câble/port, serveur DHCP, VLAN."))
    elif apipa_up:
        F.append(f(INFO, "Interface en APIPA (169.254.x.x) alors qu'une autre a une IP valide",
                   f"{', '.join(apipa_up)} : souvent un adaptateur virtuel (VM, VPN) ou un second lien sans DHCP."))
    elif apipa:
        F.append(f(WARN, "Adresse APIPA (169.254.x.x) détectée",
                   "Une interface n'obtient pas de bail DHCP : vérifier câble/port, serveur DHCP, VLAN."))
    if not dns:
        F.append(f(WARN, "Aucun serveur DNS configuré"))
    if not gw:
        F.append(f(CRIT, "Aucune route par défaut", "Pas de passerelle configurée : pas de sortie hors LAN."))

    if not args.no_net_tests:
        results = []
        with cf.ThreadPoolExecutor(max_workers=8) as ex:
            fut = {}
            if gw:
                fut["gw"] = ex.submit(ping, gw)
            fut["p1"] = ex.submit(ping, "1.1.1.1")
            fut["p2"] = ex.submit(ping, "8.8.8.8")
            fut["res1"] = ex.submit(resolve, "www.google.com")
            fut["res2"] = ex.submit(resolve, "www.microsoft.com")
            fut["tcp"] = ex.submit(tcp_connect, "1.1.1.1", 443)
            fut["cap"] = ex.submit(http_get, "http://connectivitycheck.gstatic.com/generate_204")
            for i, s in enumerate(dns[:4]):
                fut[f"dns{i}"] = ex.submit(dns_query, s)
            res = {k: v.result() for k, v in fut.items()}

        def pr(label, r, lan=False):
            if r is None:
                results.append([label, "n/a", "commande ping indisponible"])
                return None
            txt = f"perte {r['loss']:.0f} %"
            if r["avg"] is not None:
                txt += f", moy. {r['avg']:.0f} ms"
            if r["jitter"] is not None:
                txt += f", gigue {r['jitter']:.1f} ms"
            results.append([label, "OK" if r["loss"] == 0 else ("ÉCHEC" if r["loss"] >= 100 else "DÉGRADÉ"), txt])
            return r

        gw_r = pr(f"Ping passerelle ({gw})", res["gw"], True) if gw else None
        p1 = pr("Ping 1.1.1.1", res["p1"])
        p2 = pr("Ping 8.8.8.8", res["p2"])
        inet_up = any(r and r["loss"] < 100 for r in (p1, p2))
        for lbl, r in (("1.1.1.1", p1), ("8.8.8.8", p2)):
            if r and 0 < r["loss"] < 100:
                F.append(f(CRIT if r["loss"] >= 50 else WARN, f"Perte de paquets vers {lbl} : {r['loss']:.0f} %",
                           "Tester en filaire, changer de câble/port, vérifier le lien FAI ou la saturation Wi-Fi."))
            if r and r["avg"] and r["avg"] > 100:
                F.append(f(WARN, f"Latence élevée vers {lbl} : {r['avg']:.0f} ms"))
        if gw_r:
            if gw_r["loss"] >= 100:
                F.append(f(INFO if inet_up else CRIT,
                           "La passerelle ne répond pas au ping" + (" (ICMP filtré ?)" if inet_up else " et Internet est injoignable"),
                           "" if inet_up else "Vérifier câble, Wi-Fi, box/routeur."))
            elif gw_r["loss"] > 0:
                F.append(f(WARN, f"Perte vers la passerelle : {gw_r['loss']:.0f} %", "Problème LAN/Wi-Fi local."))
            if gw_r["avg"] and gw_r["avg"] > 20:
                F.append(f(WARN, f"Latence LAN élevée vers la passerelle : {gw_r['avg']:.0f} ms",
                           "Wi-Fi saturé/faible signal ou équipement surchargé."))
        if not inet_up and gw:
            F.append(f(CRIT, "Internet injoignable par IP (1.1.1.1 / 8.8.8.8)"))

        ok1, t1 = res["res1"]
        ok2, t2 = res["res2"]
        for lbl, ok, t in (("www.google.com", ok1, t1), ("www.microsoft.com", ok2, t2)):
            results.append([f"Résolution DNS {lbl}", "OK" if ok else "ÉCHEC", f"{t:.0f} ms" if t else "-"])
        if inet_up and not (ok1 or ok2):
            F.append(f(CRIT, "Résolution DNS en échec alors qu'Internet répond par IP",
                       "Vérifier les serveurs DNS configurés (DHCP/box/pare-feu/filtrage)."))
        elif ok1 and t1 and t1 > 500:
            F.append(f(WARN, f"Résolution DNS lente ({t1:.0f} ms)"))
        for i, s in enumerate(dns[:4]):
            ok, t = res[f"dns{i}"]
            results.append([f"Requête directe au DNS {s}", "OK" if ok else "ÉCHEC", f"{t:.0f} ms" if t else "-"])
            if not ok and len(dns) > 1:
                F.append(f(WARN, f"Le serveur DNS {s} ne répond pas", "Retirer ou corriger s'il est obsolète."))
        okt, tt = res["tcp"]
        results.append(["Connexion TCP 1.1.1.1:443", "OK" if okt else "ÉCHEC", f"{tt:.0f} ms" if tt else "-"])
        if inet_up and not okt:
            F.append(f(WARN, "ICMP passe mais pas le TCP 443", "Proxy, pare-feu ou filtrage sortant ?"))
        code, _ = res["cap"]
        results.append(["Détection portail captif", "OK" if code == 204 else ("ÉCHEC" if code is None else "SUSPECT"),
                        f"HTTP {code}" if code else "pas de réponse"])
        if code not in (204, None):
            F.append(f(WARN, f"Réponse HTTP inattendue ({code}) au test de connectivité",
                       "Portail captif ou proxy transparent possible."))
        tables.append(table("Tests de connectivité", ["Test", "Résultat", "Détail"], results))
        if args.public_ip:
            st, body = http_get("https://api.ipify.org")
            tables.append(table(None, ["Élément", "Valeur"], [["IP publique", body.strip() if st == 200 else "indisponible"]]))

    wtxt, sig = wifi_info()
    if wtxt:
        tables.append(table("Wi-Fi", ["Connexion active"], [[l] for l in wtxt.splitlines() if l.strip()]))
        if sig is not None:
            if sig < 30:
                F.append(f(CRIT, f"Signal Wi-Fi très faible ({sig} %)"))
            elif sig < 50:
                F.append(f(WARN, f"Signal Wi-Fi moyen/faible ({sig} %)", "Rapprocher le poste ou revoir l'emplacement des bornes."))
    if not any(x["level"] in (WARN, CRIT) for x in F):
        F.insert(0, f(OK, "Configuration et connectivité réseau correctes"))
    return section("network", "Réseau", F, tables, pre)


# --------------------------------------------------------------------------- #
# Section : Sécurité
# --------------------------------------------------------------------------- #
RISKY_WARN = {21: "FTP", 23: "Telnet", 5900: "VNC", 1433: "MSSQL", 3306: "MySQL", 5432: "PostgreSQL",
              27017: "MongoDB", 6379: "Redis", 9200: "Elasticsearch", 2375: "API Docker non chiffrée"}
RISKY_INFO = {445: "SMB", 3389: "RDP", 135: "RPC", 22: "SSH", 5985: "WinRM"}


def listening_ports():
    res = []
    try:
        if IS_LINUX and which("ss"):
            for line in run(["ss", "-tulnH"], timeout=10).splitlines():
                p = line.split()
                if len(p) >= 5:
                    addr, _, port = p[4].rpartition(":")
                    if port.isdigit():
                        res.append((p[0], addr.strip("[]"), int(port), ""))
        elif IS_MAC:
            for line in run(["lsof", "-iTCP", "-sTCP:LISTEN", "-P", "-n"], timeout=15).splitlines()[1:]:
                p = line.split()
                if len(p) >= 9:
                    addr, _, port = p[8].rpartition(":")
                    if port.isdigit():
                        res.append(("tcp", addr.strip("[]"), int(port), p[0]))
        elif IS_WIN:
            j = ps_json(r"Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue|ForEach-Object{[pscustomobject]@{a=$_.LocalAddress;p=$_.LocalPort;n=(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}}|ConvertTo-Json", timeout=40)
            for d in as_list(j):
                res.append(("tcp", d.get("a", ""), int(d.get("p", 0)), d.get("n") or ""))
    except Exception:
        pass
    return res


def sec_security(args):
    F, rows = [], []
    adm = is_admin()
    if IS_WIN:
        j = ps_json(r"""$r=@{};
try{$r.av=@(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction Stop|ForEach-Object{$_.displayName})}catch{$r.av=@()}
try{$d=Get-MpComputerStatus -ErrorAction Stop;$r.def=[pscustomobject]@{rt=$d.RealTimeProtectionEnabled;av=$d.AntivirusEnabled;age=$d.AntivirusSignatureAge}}catch{$r.def=$null}
try{$r.fw=@(Get-NetFirewallProfile -ErrorAction Stop|ForEach-Object{[pscustomobject]@{n=[string]$_.Name;on=[bool]$_.Enabled}})}catch{$r.fw=@()}
try{$r.bl=@(Get-BitLockerVolume -ErrorAction Stop|ForEach-Object{[pscustomobject]@{mp=$_.MountPoint;pr=[string]$_.ProtectionStatus}})}catch{$r.bl=@()}
try{$r.sb=[bool](Confirm-SecureBootUEFI -ErrorAction Stop)}catch{$r.sb=$null}
try{$r.smb1=[bool](Get-SmbServerConfiguration -ErrorAction Stop).EnableSMB1Protocol}catch{$r.smb1=$null}
try{$r.rdp=((Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -ErrorAction Stop).fDenyTSConnections -eq 0)}catch{$r.rdp=$null}
[pscustomobject]$r|ConvertTo-Json -Depth 4""", timeout=60) or {}
        av = as_list(j.get("av"))
        d = j.get("def")
        rows.append(["Antivirus (Security Center)", ", ".join(av) or "non détecté"])
        if not av and not d:
            F.append(f(WARN, "Aucun antivirus détecté"))
        if d:
            rows.append(["Microsoft Defender",
                         f"temps réel {'ON' if d.get('rt') else 'OFF'} ; signatures âgées de {d.get('age')} j"])
            age = d.get("age")
            if isinstance(age, int) and age > 14:
                F.append(f(CRIT, f"Signatures Defender très anciennes ({age} j)"))
            elif isinstance(age, int) and age > 7:
                F.append(f(WARN, f"Signatures Defender anciennes ({age} j)"))
            if av and all("defender" in a.lower() for a in av) and not d.get("rt"):
                F.append(f(CRIT, "Protection en temps réel Defender désactivée"))
        fw = as_list(j.get("fw"))
        for p in fw:
            rows.append([f"Pare-feu profil {p.get('n')}", "activé" if p.get("on") else "DÉSACTIVÉ"])
            if not p.get("on"):
                F.append(f(WARN, f"Pare-feu Windows désactivé (profil {p.get('n')})"))
        bl = as_list(j.get("bl"))
        if bl:
            for v in bl:
                on = str(v.get("pr")).lower() in ("on", "1")
                rows.append([f"BitLocker {v.get('mp')}", "protégé" if on else "non protégé"])
                if not on and str(v.get("mp", "")).upper().startswith("C"):
                    F.append(f(WARN, "Disque système non chiffré (BitLocker)", "Risque en cas de perte/vol du portable."))
        else:
            rows.append(["BitLocker", "non lisible (droits administrateur requis ?)"])
        if j.get("sb") is False:
            F.append(f(WARN, "Secure Boot désactivé"))
        elif j.get("sb") is True:
            rows.append(["Secure Boot", "activé"])
        if j.get("smb1") is True:
            F.append(f(CRIT, "SMBv1 activé sur le serveur", "Protocole obsolète et exploité (WannaCry). À désactiver."))
        if j.get("rdp") is True:
            F.append(f(INFO, "Bureau à distance (RDP) activé", "S'assurer qu'il n'est pas exposé sur Internet et que NLA est actif."))
    elif IS_MAC:
        fv = run(["fdesetup", "status"])
        fwr = run(["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"])
        gk = run(["spctl", "--status"], merge=True)
        sip = run(["csrutil", "status"])
        rows += [["FileVault", fv or "n/a"], ["Pare-feu applicatif", fwr or "n/a"],
                 ["Gatekeeper", gk or "n/a"], ["SIP", sip or "n/a"]]
        if fv and "Off" in fv:
            F.append(f(WARN, "FileVault désactivé", "Disque non chiffré."))
        if fwr and "disabled" in fwr.lower():
            F.append(f(WARN, "Pare-feu macOS désactivé"))
        if gk and "disabled" in gk.lower():
            F.append(f(WARN, "Gatekeeper désactivé"))
        if sip and "disabled" in sip.lower():
            F.append(f(WARN, "SIP désactivé"))
    else:
        active = []
        for svc in ("ufw", "firewalld", "nftables", "iptables", "fail2ban", "crowdsec"):
            if which("systemctl") and run(["systemctl", "is-active", svc]).strip() == "active":
                active.append(svc)
        rows.append(["Services de filtrage/protection actifs", ", ".join(active) or "aucun détecté"])
        if not any(a in active for a in ("ufw", "firewalld", "nftables", "iptables")):
            F.append(f(WARN, "Aucun pare-feu système actif détecté", "Vérifier nftables/iptables si géré autrement."))
        if which("getenforce"):
            rows.append(["SELinux", run(["getenforce"]) or "n/a"])
        if which("aa-status"):
            rows.append(["AppArmor", "actif" if run(["aa-status", "--enabled"], merge=True) == "" else "inactif/indéterminé"])
        lb = run(["lsblk", "-rno", "TYPE"], timeout=10)
        rows.append(["Chiffrement disque (LUKS)", "présent" if "crypt" in lb else "aucun volume chiffré détecté"])
        if "crypt" not in lb:
            F.append(f(INFO, "Aucun volume chiffré détecté", "Pertinent surtout pour un portable."))
    tables = [table(None, ["Contrôle", "État"], rows)]

    ports = listening_ports()
    if ports:
        prow, seen = [], set()
        for proto, addr, port, proc in sorted(ports, key=lambda x: x[2]):
            key = (addr, port)
            if key in seen:
                continue
            seen.add(key)
            exposed = addr in ("0.0.0.0", "::", "*", "[::]", "")
            prow.append([proto, addr or "*", port, proc, "toutes interfaces" if exposed else "local"])
            if exposed and port in RISKY_WARN:
                F.append(f(WARN, f"Service {RISKY_WARN[port]} (port {port}) à l'écoute sur toutes les interfaces",
                           "Vérifier la nécessité, l'authentification et l'exposition réseau."))
            elif exposed and port in RISKY_INFO and not IS_WIN:
                F.append(f(INFO, f"{RISKY_INFO[port]} (port {port}) à l'écoute sur toutes les interfaces"))
        tables.append(table(f"Ports TCP/UDP en écoute ({len(prow)})", ["Proto", "Adresse", "Port", "Processus", "Portée"], prow))
    if not adm:
        F.append(f(INFO, "Contrôles de sécurité partiels (droits non élevés)",
                   "Relancer en administrateur/root pour BitLocker, pare-feu, processus des ports, etc."))
    if not any(x["level"] in (WARN, CRIT) for x in F):
        F.insert(0, f(OK, "Aucun problème de sécurité évident sur les contrôles effectués"))
    return section("security", "Sécurité", F, tables)


# --------------------------------------------------------------------------- #
# Section : Mises à jour
# --------------------------------------------------------------------------- #
def sec_updates(args):
    F, rows = [], []
    try:
        if IS_WIN:
            last = ps(r"Get-HotFix -ErrorAction SilentlyContinue|Where-Object InstalledOn|Sort-Object InstalledOn -Descending|Select-Object -First 1|ForEach-Object{$_.InstalledOn.ToString('yyyy-MM-dd')}", timeout=60).strip()
            if re.match(r"\d{4}-\d{2}-\d{2}", last):
                d = dt.datetime.strptime(last[:10], "%Y-%m-%d")
                age = (dt.datetime.now() - d).days
                rows.append(["Dernier correctif installé", f"{d.strftime('%d/%m/%Y')} (il y a {age} j)"])
                if age > 120:
                    F.append(f(CRIT, f"Aucun correctif depuis {age} jours"))
                elif age > 60:
                    F.append(f(WARN, f"Dernier correctif ancien ({age} jours)"))
            j = ps_json(r"""$s=New-Object -ComObject Microsoft.Update.Session;$r=$s.CreateUpdateSearcher().Search("IsInstalled=0 and IsHidden=0 and Type='Software'");[pscustomobject]@{count=$r.Updates.Count;titles=@($r.Updates|ForEach-Object{$_.Title})}|ConvertTo-Json""", timeout=120)
            if j is not None:
                cnt = int(j.get("count", 0))
                rows.append(["Mises à jour en attente", str(cnt)])
                for t in as_list(j.get("titles"))[:15]:
                    rows.append(["", t])
                if cnt > 0:
                    F.append(f(WARN if cnt >= 5 else INFO, f"{cnt} mise(s) à jour Windows en attente"))
            else:
                rows.append(["Mises à jour en attente", "non déterminé (service Windows Update / réseau)"])
        elif IS_LINUX:
            if which("apt-get"):
                out = run(["apt-get", "-s", "upgrade"], timeout=60, merge=True)
                inst = [l for l in out.splitlines() if l.startswith("Inst ")]
                sec = [l for l in inst if "security" in l.lower()]
                rows.append(["Paquets à mettre à jour (apt)", f"{len(inst)} dont {len(sec)} de sécurité"])
                if sec:
                    F.append(f(WARN, f"{len(sec)} mise(s) à jour de sécurité en attente"))
                elif len(inst) > 30:
                    F.append(f(WARN, f"{len(inst)} paquets en attente"))
                elif inst:
                    F.append(f(INFO, f"{len(inst)} paquets en attente"))
                rows += [["", l[5:90]] for l in sec[:10]]
            elif which("dnf") or which("yum"):
                tool = "dnf" if which("dnf") else "yum"
                out = run([tool, "-q", "check-update"], timeout=90)
                lines = [l for l in out.splitlines() if l and not l.startswith(("Obsoleting", "Security:")) and len(l.split()) >= 3]
                rows.append([f"Paquets à mettre à jour ({tool})", str(len(lines))])
                if len(lines) > 30:
                    F.append(f(WARN, f"{len(lines)} paquets en attente"))
                elif lines:
                    F.append(f(INFO, f"{len(lines)} paquets en attente"))
            elif which("checkupdates"):
                n = len(run(["checkupdates"], timeout=60).splitlines())
                rows.append(["Paquets à mettre à jour (pacman)", str(n)])
                if n:
                    F.append(f(INFO, f"{n} paquets en attente"))
            else:
                rows.append(["Gestionnaire de paquets", "non reconnu"])
        elif IS_MAC:
            out = run(["softwareupdate", "-l"], timeout=120, merge=True)
            if "No new software available" in out:
                rows.append(["Mises à jour macOS", "aucune"])
            else:
                items = [l.strip("* ").strip() for l in out.splitlines() if l.strip().startswith("*")]
                rows.append(["Mises à jour macOS en attente", str(len(items))])
                rows += [["", i] for i in items[:10]]
                if items:
                    F.append(f(WARN, f"{len(items)} mise(s) à jour macOS en attente"))
    except Exception as e:
        F.append(f(INFO, "Vérification des mises à jour incomplète", str(e)))
    if not any(x["level"] in (WARN, CRIT) for x in F):
        F.insert(0, f(OK, "Système à jour (dans la limite des contrôles effectués)"))
    return section("updates", "Mises à jour", F, [table(None, ["Élément", "Valeur"], rows)])


# --------------------------------------------------------------------------- #
# Section : Événements & journaux
# --------------------------------------------------------------------------- #
HW_PROVIDERS = {"disk", "ntfs", "stornvme", "storahci", "volmgr", "microsoft-windows-whea-logger",
                "iastora", "nvme", "partmgr", "microsoft-windows-ntfs", "storport"}
LINUX_PATTERNS = [
    (r"I/O error|Buffer I/O error|blk_update_request", "Erreurs d'E/S disque"),
    (r"EXT4-fs error|XFS.*[Cc]orruption|BTRFS.*error", "Erreurs de système de fichiers"),
    (r"ata\d+.*(failed|error|exception)|nvme.*(timeout|reset|I/O)", "Erreurs contrôleur de stockage"),
    (r"Out of memory|oom-kill|Killed process", "Saturation mémoire (OOM killer)"),
    (r"Machine Check|mce:|Hardware Error|EDAC", "Erreurs matérielles (MCE / ECC)"),
    (r"thermal|temperature above threshold|throttl", "Surchauffe / bridage thermique"),
]


def sec_events(args):
    F, tables = [], []
    try:
        if IS_WIN:
            j = ps_json(r"""$e=Get-WinEvent -FilterHashtable @{LogName='System','Application';Level=1,2;StartTime=(Get-Date).AddDays(-3)} -MaxEvents 600 -ErrorAction SilentlyContinue
if(-not $e){'[]';exit}
$e|Group-Object {$_.ProviderName+'|'+$_.Id}|Sort-Object Count -Descending|Select-Object -First 15|ForEach-Object{$g=$_.Group[0];[pscustomobject]@{count=$_.Count;provider=$g.ProviderName;id=$g.Id;log=$g.LogName;last=$g.TimeCreated.ToString('dd/MM HH:mm');msg=(([string]$g.Message -split "\r?\n")[0])}}|ConvertTo-Json -Depth 3""", timeout=90)
            k = ps_json(r"""$k=Get-WinEvent -FilterHashtable @{LogName='System';Id=41,1001,6008;StartTime=(Get-Date).AddDays(-30)} -ErrorAction SilentlyContinue
[pscustomobject]@{kp=@($k|Where-Object{$_.Id -eq 41}).Count;bc=@($k|Where-Object{$_.Id -eq 1001 -and $_.ProviderName -match 'WER-SystemErrorReporting'}).Count;ud=@($k|Where-Object{$_.Id -eq 6008}).Count}|ConvertTo-Json""", timeout=60) or {}
            if k.get("bc"):
                F.append(f(CRIT, f"{k['bc']} écran(s) bleu(s) (BugCheck) sur 30 jours",
                           "Analyser les minidumps (WinDbg/BlueScreenView), pilotes, RAM, disque."))
            if k.get("kp") or k.get("ud"):
                F.append(f(WARN, f"Arrêts brutaux sur 30 jours : Kernel-Power 41 x{k.get('kp', 0)}, événement 6008 x{k.get('ud', 0)}",
                           "Alimentation, surchauffe, batterie, pilotes ou coupures de courant."))
            rows = []
            for d in as_list(j):
                rows.append([d.get("count"), d.get("provider"), d.get("id"), d.get("log"), d.get("last"), (d.get("msg") or "")[:140]])
                if str(d.get("provider", "")).lower() in HW_PROVIDERS:
                    F.append(f(WARN, f"Erreurs stockage/matériel : {d.get('provider')} (ID {d.get('id')}) x{d.get('count')}",
                               "Vérifier SMART, câbles, contrôleur, chkdsk."))
            tables.append(table("Erreurs/critiques groupées (3 derniers jours)",
                                ["Nb", "Source", "ID", "Journal", "Dernier", "Message"], rows))
            if not rows:
                F.append(f(OK, "Aucune erreur critique dans les journaux Système/Application (3 j)"))
        elif IS_LINUX:
            out = run(["journalctl", "-p", "err", "-b", "--no-pager", "-q", "-n", "400"], timeout=30, merge=True) if which("journalctl") else ""
            if not which("journalctl"):
                F.append(f(INFO, "journalctl indisponible"))
            elif "insufficient permissions" in out.lower() or "not seeing messages" in out.lower():
                F.append(f(INFO, "Journaux illisibles : droits insuffisants", "Lancer avec sudo ou ajouter l'utilisateur aux groupes adm/systemd-journal."))
            else:
                cnt = {}
                for line in out.splitlines():
                    m = re.match(r"^\w{3}\s+\d+\s+[\d:]+\s+\S+\s+([^\s\[:]+)", line)
                    if m:
                        cnt[m.group(1)] = cnt.get(m.group(1), 0) + 1
                rows = [[v, k] for k, v in sorted(cnt.items(), key=lambda x: -x[1])[:12]]
                tables.append(table("Sources d'erreurs (boot courant)", ["Nb", "Source"], rows))
                kern = run(["journalctl", "-k", "-b", "-p", "warning", "--no-pager", "-q", "-n", "2000"], timeout=30, merge=True)
                for pat, label in LINUX_PATTERNS:
                    hits = [l for l in kern.splitlines() if re.search(pat, l, re.I)]
                    if hits:
                        F.append(f(CRIT if "disque" in label or "stockage" in label or "fichiers" in label or "matérielles" in label else WARN,
                                   f"{label} : {len(hits)} occurrence(s) dans le journal noyau", hits[-1][:200]))
                if not rows:
                    F.append(f(OK, "Aucune erreur dans le journal du boot courant"))
        elif IS_MAC:
            recent = []
            for pat in ("/Library/Logs/DiagnosticReports/*anic*", "/Library/Logs/DiagnosticReports/Kernel*"):
                for p in glob.glob(pat):
                    try:
                        if time.time() - os.path.getmtime(p) < 30 * 86400:
                            recent.append(p)
                    except Exception:
                        pass
            if recent:
                F.append(f(WARN, f"{len(recent)} kernel panic récent(s) (30 j)", ", ".join(os.path.basename(p) for p in recent[:5])))
            else:
                F.append(f(OK, "Aucun kernel panic sur 30 jours"))
            crashes = glob.glob(os.path.expanduser("~/Library/Logs/DiagnosticReports/*"))
            recent_c = [c for c in crashes if time.time() - os.path.getmtime(c) < 7 * 86400]
            if len(recent_c) > 10:
                F.append(f(INFO, f"{len(recent_c)} rapports de plantage d'applications sur 7 jours"))
    except Exception as e:
        F.append(f(INFO, "Lecture des journaux incomplète", str(e)))
    return section("events", "Événements & journaux", F, tables)


# --------------------------------------------------------------------------- #
# Section : Processus
# --------------------------------------------------------------------------- #
def sec_processes(args):
    tables, pre = [], ""
    if psutil:
        procs = list(psutil.process_iter(["pid", "name"]))
        for p in procs:
            try:
                p.cpu_percent(None)
            except Exception:
                pass
        time.sleep(1.0)
        data = []
        ncpu = os.cpu_count() or 1
        for p in procs:
            try:
                data.append((p.info["name"] or "?", p.pid, p.cpu_percent(None) / ncpu, p.memory_info().rss))
            except Exception:
                continue
        top_cpu = sorted(data, key=lambda x: -x[2])[:8]
        top_mem = sorted(data, key=lambda x: -x[3])[:8]
        tables.append(table("Top CPU", ["Processus", "PID", "CPU %"], [[n, pid, f"{c:.1f}"] for n, pid, c, _ in top_cpu]))
        tables.append(table("Top mémoire", ["Processus", "PID", "RAM"], [[n, pid, hsize(m)] for n, pid, _, m in top_mem]))
    else:
        if IS_WIN:
            pre = ps(r"Get-Process|Sort-Object WS -Descending|Select-Object -First 8 Name,Id,@{n='RAM_MB';e={[int]($_.WS/1MB)}}|Format-Table -AutoSize|Out-String")
        elif IS_MAC:
            pre = "\n".join(run(["ps", "-Ao", "pid,comm,%cpu,%mem,rss", "-m"]).splitlines()[:9])
        else:
            pre = "\n".join(run(["ps", "-eo", "pid,comm,%cpu,%mem,rss", "--sort=-%mem"]).splitlines()[:9])
    return section("processes", "Processus les plus gourmands", [f(INFO, "Instantané des processus")], tables, pre)


# --------------------------------------------------------------------------- #
# Section : Démarrage & services
# --------------------------------------------------------------------------- #
def sec_startup(args):
    F, tables = [], []
    try:
        if IS_WIN:
            j = ps_json(r"Get-CimInstance Win32_StartupCommand -ErrorAction SilentlyContinue|ForEach-Object{[pscustomobject]@{n=$_.Name;c=[string]$_.Command;l=$_.Location;u=$_.User}}|ConvertTo-Json", timeout=40)
            items = as_list(j)
            tables.append(table(f"Programmes au démarrage ({len(items)})", ["Nom", "Commande", "Emplacement", "Utilisateur"],
                                [[d.get("n"), (d.get("c") or "")[:90], d.get("l"), d.get("u")] for d in items]))
            if len(items) > 25:
                F.append(f(WARN, f"{len(items)} programmes au démarrage", "Alourdit le démarrage ; faire le tri."))
            s = ps_json(r"Get-Service -ErrorAction SilentlyContinue|Where-Object{$_.StartType -eq 'Automatic' -and $_.Status -ne 'Running'}|ForEach-Object{[pscustomobject]@{n=$_.Name;d=$_.DisplayName}}|ConvertTo-Json", timeout=40)
            sv = as_list(s)
            if sv:
                tables.append(table(f"Services automatiques arrêtés ({len(sv)}) - souvent normal (démarrage différé/déclenché)",
                                    ["Service", "Nom affiché"], [[d.get("n"), d.get("d")] for d in sv[:25]]))
        elif IS_LINUX and which("systemctl"):
            failed = run(["systemctl", "--failed", "--no-legend", "--plain"], timeout=15)
            fl = [l.split()[0] for l in failed.splitlines() if l.strip()]
            for u in fl:
                F.append(f(WARN, f"Unité systemd en échec : {u}", "systemctl status " + u))
            en = run(["systemctl", "list-unit-files", "--state=enabled", "--type=service", "--no-legend"], timeout=15)
            tables.append(table(None, ["Élément", "Valeur"], [["Services activés au démarrage", str(len(en.splitlines()))],
                                                             ["Unités en échec", str(len(fl))]]))
        elif IS_MAC:
            rows = []
            for d in (os.path.expanduser("~/Library/LaunchAgents"), "/Library/LaunchAgents", "/Library/LaunchDaemons"):
                for p in sorted(glob.glob(d + "/*.plist")):
                    b = os.path.basename(p)
                    if not b.startswith("com.apple."):
                        rows.append([b, d])
            tables.append(table(f"Agents/daemons tiers ({len(rows)})", ["Fichier", "Dossier"], rows))
    except Exception as e:
        F.append(f(INFO, "Lecture incomplète", str(e)))
    if not F:
        F.append(f(OK, "Rien d'anormal au démarrage"))
    return section("startup", "Démarrage & services", F, tables)


# --------------------------------------------------------------------------- #
# Section : Logiciels installés (option)
# --------------------------------------------------------------------------- #
REMOTE_TOOLS = re.compile(r"anydesk|teamviewer|ultraviewer|rustdesk|screenconnect|connectwise|splashtop|logmein|"
                          r"ammyy|supremo|vnc|radmin|dwservice|meshagent|atera|ninja ?rmm|n-able", re.I)


def sec_software(args):
    items = []
    try:
        if IS_WIN:
            import winreg  # type: ignore
            paths = [(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
                     (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
                     (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall")]
            seen = set()
            for root, path in paths:
                try:
                    k = winreg.OpenKey(root, path)
                except OSError:
                    continue
                for i in range(winreg.QueryInfoKey(k)[0]):
                    try:
                        sk = winreg.OpenKey(k, winreg.EnumKey(k, i))

                        def g(n):
                            try:
                                return str(winreg.QueryValueEx(sk, n)[0])
                            except OSError:
                                return ""
                        name = g("DisplayName")
                        if not name or g("SystemComponent") == "1":
                            continue
                        key = (name, g("DisplayVersion"))
                        if key in seen:
                            continue
                        seen.add(key)
                        items.append([name, g("DisplayVersion"), g("Publisher")])
                    except OSError:
                        continue
        elif IS_MAC:
            for app in sorted(glob.glob("/Applications/*.app") + glob.glob("/Applications/*/*.app")):
                ver = ""
                try:
                    with open(app + "/Contents/Info.plist", "rb") as fh:
                        ver = plistlib.load(fh).get("CFBundleShortVersionString", "")
                except Exception:
                    pass
                items.append([os.path.basename(app)[:-4], ver, ""])
        else:
            if which("dpkg-query"):
                out = run(["dpkg-query", "-W", "-f=${Package}\t${Version}\n"], timeout=30)
            elif which("rpm"):
                out = run(["rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\n"], timeout=30)
            elif which("pacman"):
                out = run(["pacman", "-Q"], timeout=30).replace(" ", "\t")
            else:
                out = ""
            for line in out.splitlines():
                p = line.split("\t")
                if p and p[0]:
                    items.append([p[0], p[1] if len(p) > 1 else "", ""])
    except Exception:
        pass
    items.sort(key=lambda x: x[0].lower())
    F = []
    rem = [i[0] for i in items if REMOTE_TOOLS.search(i[0])]
    if rem:
        F.append(f(INFO, "Outils de prise en main à distance présents", ", ".join(rem)))
    F.append(f(INFO, f"{len(items)} logiciels/paquets inventoriés"))
    return section("software", "Logiciels installés", F,
                   [table(None, ["Nom", "Version", "Éditeur"], items)], collapse=True)


# --------------------------------------------------------------------------- #
# Rendu HTML
# --------------------------------------------------------------------------- #
LABEL = {OK: "OK", WARN: "Attention", CRIT: "Critique", INFO: "Info"}
CSS = """
:root{--ok:#1a7f37;--warn:#b35900;--crit:#c62828;--info:#475569;--bg:#f4f6f8;--card:#fff;--bd:#e2e5ea;--tx:#1f2933;--mut:#64748b;--brand:#f59c1a;--navy:#20252a;--navy2:#2d353c}
*{box-sizing:border-box}body{font:14px/1.5 "Open Sans",system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;margin:0;background:var(--bg);color:var(--tx)}
.wrap{max-width:1020px;margin:0 auto;padding:24px 16px 48px}
h1{margin:0;font-size:22px;font-weight:600;color:#fff}h2{margin:0 0 10px;font-size:17px;font-weight:600;padding-left:10px;border-left:4px solid var(--brand)}
.hdr{display:flex;align-items:center;gap:16px;background:linear-gradient(135deg,var(--navy),var(--navy2));border-bottom:4px solid var(--brand);border-radius:10px;padding:16px 22px;margin-bottom:10px}
.hdr .logo{width:56px;height:56px;flex:none}.hdr .brand{color:var(--brand);font-weight:700;font-size:13px;letter-spacing:.08em;text-transform:uppercase}
th{border-top:2px solid var(--brand)}
.meta{color:var(--mut);font-size:13px}.meta b{color:var(--tx)}
.card{background:var(--card);border:1px solid var(--bd);border-radius:10px;padding:16px 18px;margin:16px 0}
.verdict{border-left:8px solid var(--info)}.verdict.crit{border-color:var(--crit)}.verdict.warn{border-color:var(--warn)}.verdict.ok{border-color:var(--ok)}
.verdict .big{font-size:20px;font-weight:700}.chips span{display:inline-block;margin:6px 8px 0 0}
.badge{display:inline-block;min-width:76px;text-align:center;padding:1px 9px;border-radius:10px;font-size:12px;font-weight:600;color:#fff;margin-right:8px;vertical-align:1px}
.b-ok{background:var(--ok)}.b-warn{background:var(--warn)}.b-crit{background:var(--crit)}.b-info{background:var(--info)}
ul.f{list-style:none;margin:0 0 8px;padding:0}ul.f li{padding:5px 0;border-bottom:1px dashed var(--bd)}ul.f li:last-child{border:0}
.d{display:block;margin:2px 0 0 86px;color:var(--mut);font-size:13px}
table{border-collapse:collapse;width:100%;font-size:13px;margin:8px 0 4px}th,td{border-bottom:1px solid var(--bd);padding:5px 8px;text-align:left;vertical-align:top;word-break:break-word}
th{background:#eef1f5;font-weight:600}caption{text-align:left;font-weight:600;padding:8px 0 2px;color:var(--mut)}
pre{background:#0f172a;color:#e2e8f0;padding:10px;border-radius:6px;overflow:auto;font-size:12px;white-space:pre-wrap}
details summary{cursor:pointer;font-weight:600;margin:6px 0}
footer{color:var(--mut);font-size:12px;text-align:center;margin-top:24px}
@media print{body{background:#fff}.card{break-inside:avoid;box-shadow:none}details{display:block}}
"""


LOGO_SVG = ('<svg class="logo" viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg"><rect width="100" height="100" rx="22" fill="#f59c1a"/>'
            '<rect x="17" y="21" width="66" height="45" rx="6" fill="none" stroke="#fff" stroke-width="5"/>'
            '<rect x="44" y="68" width="12" height="9" fill="#fff"/><rect x="32" y="76" width="36" height="6" rx="3" fill="#fff"/>'
            '<polyline points="22,44 38,44 44,34 52,57 60,29 66,44 78,44" fill="none" stroke="#20252a" stroke-width="5" '
            'stroke-linecap="round" stroke-linejoin="round"/></svg>')


def esc(x):
    return html.escape("" if x is None else str(x), quote=True)


def render_findings(findings):
    out = ['<ul class="f">']
    for x in findings:
        out.append(f'<li><span class="badge b-{x["level"]}">{LABEL[x["level"]]}</span><b>{esc(x["title"])}</b>')
        if x["detail"]:
            out.append(f'<span class="d">{esc(x["detail"])}</span>')
        out.append("</li>")
    out.append("</ul>")
    return "".join(out)


def render_table(t):
    h = ["<table>"]
    if t.get("caption"):
        h.append(f"<caption>{esc(t['caption'])}</caption>")
    h.append("<tr>" + "".join(f"<th>{esc(c)}</th>" for c in t["headers"]) + "</tr>")
    for r in t["rows"]:
        h.append("<tr>" + "".join(f"<td>{esc(c)}</td>" for c in r) + "</tr>")
    h.append("</table>")
    return "".join(h)


def render_html(meta, sections, summary, actions=None):
    p = [f'<!doctype html><html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
         f'<title>{APP_NAME} - {esc(meta["hostname"])}</title><style>{CSS}</style></head><body><div class="wrap">']
    p.append(f'<div class="hdr">{LOGO_SVG}<div><div class="brand">{APP_NAME}</div>'
             f'<h1>Rapport de diagnostic - {esc(meta["hostname"])}</h1></div></div>')
    bits = [f"<b>Date :</b> {esc(meta['date'])}"]
    if meta.get("client"):
        bits.append(f"<b>Client :</b> {esc(meta['client'])}")
    if meta.get("tech"):
        bits.append(f"<b>Technicien :</b> {esc(meta['tech'])}")
    bits.append(f"<b>Droits admin :</b> {'oui' if meta['admin'] else 'non'}")
    p.append('<div class="meta">' + " &nbsp;|&nbsp; ".join(bits) + "</div>")

    cls = {"CRITIQUE": "crit", "À SURVEILLER": "warn", "BON": "ok"}[summary["verdict"]]
    p.append(f'<div class="card verdict {cls}"><div class="big">État global : {esc(summary["verdict"])}</div>'
             f'<div class="chips"><span class="badge b-crit">{summary["crit"]} critique(s)</span>'
             f'<span class="badge b-warn">{summary["warn"]} attention</span>'
             f'<span class="badge b-ok">{summary["ok"]} OK</span></div>')
    if summary["top"]:
        p.append("<h2 style='margin-top:14px'>Points d'attention</h2><ul class='f'>")
        for lvl, sec, title, detail in summary["top"]:
            p.append(f'<li><span class="badge b-{lvl}">{LABEL[lvl]}</span><b>{esc(title)}</b> <span class="meta">({esc(sec)})</span>')
            if detail:
                p.append(f'<span class="d">{esc(detail)}</span>')
            p.append("</li>")
        p.append("</ul>")
    p.append("</div>")

    for s in sections:
        body = render_findings(s["findings"]) + "".join(render_table(t) for t in s["tables"])
        if s["pre"]:
            body += f"<pre>{esc(s['pre'])}</pre>"
        if s.get("collapse"):
            head = render_findings(s["findings"])
            inner = "".join(render_table(t) for t in s["tables"])
            body = head + f"<details><summary>Afficher la liste complète</summary>{inner}</details>"
        p.append(f'<div class="card"><h2>{esc(s["title"])}</h2>{body}</div>')
    if actions:
        stl = {"ok": ("ok", "Terminé"), "warn": ("warn", "Avertissement"), "err": ("crit", "Échec"), "stopped": ("info", "Arrêtée")}
        rows = []
        for a in actions:
            lv, lb = stl.get(a["status"], ("info", a["status"]))
            log = "\n".join(t for t, _ in a["log"])
            rows.append(f'<li><span class="badge b-{lv}">{lb}</span><b>{esc(a["title"])}</b> '
                        f'<span class="meta">({esc(a["time"])}, {a["dur"]:.0f} s)</span>'
                        f'<details><summary>Journal</summary><pre>{esc(log)}</pre></details></li>')
        p.append('<div class="card"><h2>Actions de dépannage effectuées</h2><ul class="f">' + "".join(rows) + "</ul></div>")
    p.append(f'<footer>Généré par {APP_NAME} v{VERSION} en {meta["duration"]:.0f} s. '
             f'Ce rapport contient des informations sensibles (noms, adresses IP/MAC, n° de série) : à diffuser avec précaution.</footer>')
    p.append("</div></body></html>")
    return "".join(p)


# --------------------------------------------------------------------------- #
# Orchestration (commune à la fenêtre et au mode console)
# --------------------------------------------------------------------------- #
def plan_tasks(args):
    tasks = [("system", "Système", sec_system), ("resources", "Ressources", sec_resources),
             ("disks", "Disques / SMART", sec_disks), ("network", "Réseau", sec_network),
             ("security", "Sécurité", sec_security)]
    if not args.quick:
        tasks.append(("updates", "Mises à jour", sec_updates))
    tasks += [("events", "Événements", sec_events), ("processes", "Processus", sec_processes),
              ("startup", "Démarrage", sec_startup)]
    if args.software and not args.quick:
        tasks.append(("software", "Logiciels", sec_software))
    return tasks


def new_meta(args):
    now = dt.datetime.now()
    return {"app": APP_NAME, "hostname": socket.gethostname(), "date": now.strftime("%d/%m/%Y %H:%M"),
            "stamp": now.strftime("%Y%m%d-%H%M"), "client": args.client, "tech": args.tech,
            "admin": is_admin(), "duration": 0, "version": VERSION, "os": platform.platform()}


def run_scan(args, tasks, on_section=None):
    results = {}
    with cf.ThreadPoolExecutor(max_workers=5) as ex:
        futs = {ex.submit(fn, args): (key, title) for key, title, fn in tasks}
        for fut in cf.as_completed(futs):
            key, title = futs[fut]
            try:
                res = fut.result()
            except Exception as e:
                res = section(key, title, [f(INFO, f"Module « {title} » en erreur", f"{type(e).__name__}: {e}")])
            results[key] = res
            if on_section:
                try:
                    on_section(res)
                except Exception:
                    pass
    return [results[k] for k, _, _ in tasks]


def summarize(sections):
    cnt = {OK: 0, WARN: 0, CRIT: 0}
    top = []
    for s in sections:
        for x in s["findings"]:
            if x["level"] in cnt:
                cnt[x["level"]] += 1
            if x["level"] in (WARN, CRIT):
                top.append([x["level"], s["title"], x["title"], x["detail"]])
    top.sort(key=lambda t: 0 if t[0] == CRIT else 1)
    verdict = "CRITIQUE" if cnt[CRIT] else ("À SURVEILLER" if cnt[WARN] else "BON")
    return {"verdict": verdict, "crit": cnt[CRIT], "warn": cnt[WARN], "ok": cnt[OK], "top": top}


# --------------------------------------------------------------------------- #
# Actions de dépannage (Windows)
# --------------------------------------------------------------------------- #
PS_PRE = ("[Console]::OutputEncoding=[Text.Encoding]::UTF8;$ProgressPreference='SilentlyContinue';"
          "$ErrorActionPreference='Continue';")


def _cmd(*cmd):
    return {"show": " ".join(cmd), "kind": "cmd", "run": list(cmd)}


def _ps(show, script):
    return {"show": "PowerShell : " + show, "kind": "ps", "run": script}


ACTIONS = [
    {"id": "restore_point", "cat": "Avant intervention", "title": "Créer un point de restauration",
     "desc": "Sauvegarde l'état du système avant toute modification. Active la protection système du disque "
             "système si elle est coupée. Windows n'autorise par défaut qu'un point toutes les 24 h.",
     "risk": "low", "dur": "~1 min", "reboot": False, "warn": "",
     "steps": [_ps("Enable-ComputerRestore ; Checkpoint-Computer", r"""
$d = $env:SystemDrive + '\'
try { Enable-ComputerRestore -Drive $d -ErrorAction Stop; "Protection système active sur $d" } catch { 'Protection système : ' + $_.Exception.Message }
$last = Get-ComputerRestorePoint -ErrorAction SilentlyContinue | Select-Object -Last 1
Checkpoint-Computer -Description 'E-A2 Scan - avant intervention' -RestorePointType MODIFY_SETTINGS -ErrorAction Stop 3>$null
$new = Get-ComputerRestorePoint -ErrorAction SilentlyContinue | Select-Object -Last 1
if ($new -and (-not $last -or $new.SequenceNumber -ne $last.SequenceNumber)) { "Point de restauration créé (n° $($new.SequenceNumber))." }
else {
  'Aucun nouveau point créé : un point existe déjà depuis moins de 24 h.'
  if ($new) { 'Dernier point : ' + [Management.ManagementDateTimeConverter]::ToDateTime($new.CreationTime).ToString('dd/MM/yyyy HH:mm') + ' - ' + $new.Description }
}""")]},

    {"id": "flush_dns", "cat": "Réseau", "title": "Vider le cache DNS",
     "desc": "Efface les résolutions DNS mémorisées. Utile quand un site ne s'ouvre plus ou pointe vers une ancienne adresse.",
     "risk": "low", "dur": "~2 s", "reboot": False, "warn": "", "steps": [_cmd("ipconfig", "/flushdns")]},

    {"id": "renew_ip", "cat": "Réseau", "title": "Renouveler l'adresse IP",
     "desc": "Libère puis redemande un bail DHCP sur toutes les cartes. Corrige une adresse 169.254.x.x ou un mauvais bail.",
     "risk": "med", "dur": "~15 s", "reboot": False,
     "warn": "La connexion réseau est coupée quelques secondes : une prise en main à distance peut décrocher.",
     "steps": [_cmd("ipconfig", "/release"), _cmd("ipconfig", "/renew")]},

    {"id": "reset_network", "cat": "Réseau", "title": "Réinitialiser la pile réseau",
     "desc": "Réinitialise Winsock et TCP/IP puis vide le cache DNS. Corrige les problèmes réseau persistants "
             "(logiciels VPN ou antivirus mal désinstallés, pile corrompue).",
     "risk": "high", "dur": "~10 s", "reboot": True,
     "warn": "Les réglages IP manuels (IP fixe, DNS fixes) peuvent être perdus : note-les avant. Redémarrage requis.",
     "steps": [_cmd("netsh", "winsock", "reset"), _cmd("netsh", "int", "ip", "reset"), _cmd("ipconfig", "/flushdns")]},

    {"id": "sync_time", "cat": "Réseau", "title": "Resynchroniser l'heure",
     "desc": "Démarre le service Temps Windows si besoin et force la synchronisation. Une heure fausse casse les "
             "certificats HTTPS, l'authentification et les mises à jour.",
     "risk": "low", "dur": "~5 s", "reboot": False, "warn": "",
     "steps": [_ps("Start-Service w32time", r"""
$s = Get-Service w32time
if ($s.StartType -eq 'Disabled') { 'Le service Temps Windows est désactivé.'; exit 1 }
if ($s.Status -ne 'Running') { Start-Service w32time; 'Service Temps Windows démarré.' } else { 'Service Temps Windows actif.' }"""),
               _cmd("w32tm", "/resync", "/force"), _cmd("w32tm", "/query", "/source")]},

    {"id": "sfc", "cat": "Réparation système", "title": "Vérifier les fichiers système (SFC)",
     "desc": "Contrôle l'intégrité des fichiers protégés de Windows et remplace ceux qui sont corrompus.",
     "risk": "low", "dur": "10 à 20 min", "reboot": False, "warn": "", "steps": [_cmd("sfc", "/scannow")]},

    {"id": "dism", "cat": "Réparation système", "title": "Réparer l'image Windows (DISM)",
     "desc": "Répare le magasin de composants depuis Windows Update. À lancer avant SFC si celui-ci n'arrive pas à réparer.",
     "risk": "low", "dur": "10 à 30 min", "reboot": False, "warn": "Connexion Internet nécessaire.",
     "steps": [_cmd("DISM", "/Online", "/Cleanup-Image", "/RestoreHealth")]},

    {"id": "disk_scan", "cat": "Réparation système", "title": "Analyser le disque système",
     "desc": "Analyse en ligne du système de fichiers du disque système, sans redémarrage. Indique si une réparation est nécessaire.",
     "risk": "low", "dur": "~1 min", "reboot": False, "warn": "",
     "steps": [_ps("Repair-Volume -Scan", r"""
$l = $env:SystemDrive.TrimEnd(':')
$r = Repair-Volume -DriveLetter $l -Scan -ErrorAction Stop
"Résultat pour le volume ${l}: : $r"
switch ("$r") {
  'NoErrorsFound'    { 'Aucune erreur détectée.' }
  'SpotFixNeeded'    { 'Erreurs trouvées : correction rapide nécessaire (Repair-Volume -SpotFix, bref redémarrage).' }
  'FullRepairNeeded' { 'Réparation complète nécessaire : planifier chkdsk /f au redémarrage.' }
}
if ("$r" -ne 'NoErrorsFound') { exit 2 }""")]},

    {"id": "clear_temp", "cat": "Nettoyage", "title": "Nettoyer les fichiers temporaires",
     "desc": "Supprime les fichiers temporaires de Windows et de tous les profils utilisateurs, de plus de 24 h. "
             "Les fichiers en cours d'utilisation sont ignorés.",
     "risk": "med", "dur": "~1 min", "reboot": False, "warn": "Suppression définitive des fichiers temporaires.",
     "steps": [_ps("Remove-Item (Windows\\Temp + Users\\*\\AppData\\Local\\Temp)", r"""
$drv = $env:SystemDrive.TrimEnd(':')
$before = (Get-PSDrive $drv).Free
$limit = (Get-Date).AddDays(-1)
$dirs = @("$env:SystemRoot\Temp") + @(Get-ChildItem "$env:SystemDrive\Users" -Directory -Force -ErrorAction SilentlyContinue | ForEach-Object { Join-Path $_.FullName 'AppData\Local\Temp' })
foreach ($d in $dirs) {
  if (-not (Test-Path $d)) { continue }
  $n = 0; $e = 0
  Get-ChildItem $d -Force -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -lt $limit } | ForEach-Object {
    try { Remove-Item $_.FullName -Recurse -Force -ErrorAction Stop; $n++ } catch { $e++ } }
  "$d : $n élément(s) supprimé(s)" + $(if ($e) { ", $e en cours d'utilisation" } else { '' })
}
$after = (Get-PSDrive $drv).Free
'Espace libéré : {0:N0} Mo' -f [math]::Max(0, ($after - $before) / 1MB)""")]},

    {"id": "component_cleanup", "cat": "Nettoyage", "title": "Nettoyer les composants Windows",
     "desc": "Supprime les anciennes versions des composants remplacées par les mises à jour (dossier WinSxS). "
             "Libère souvent plusieurs Go.",
     "risk": "med", "dur": "5 à 15 min", "reboot": False,
     "warn": "Les mises à jour déjà installées ne pourront plus être désinstallées.",
     "steps": [_cmd("DISM", "/Online", "/Cleanup-Image", "/StartComponentCleanup")]},

    {"id": "wu_scan", "cat": "Windows Update", "title": "Rechercher les mises à jour",
     "desc": "Déclenche une recherche Windows Update en arrière-plan.",
     "risk": "low", "dur": "~5 s", "reboot": False, "warn": "",
     "steps": [_ps("UsoClient StartScan", r"""
Start-Process -FilePath "$env:SystemRoot\System32\UsoClient.exe" -ArgumentList StartScan -WindowStyle Hidden -Wait
'Recherche lancée en arrière-plan.'
'Suivre la progression dans Paramètres > Windows Update.'""")]},

    {"id": "repair_wu", "cat": "Windows Update", "title": "Réparer Windows Update",
     "desc": "Arrête les services de mise à jour, renomme les caches SoftwareDistribution et catroot2 (conservés "
             "en .old), puis redémarre les services. Corrige les mises à jour bloquées ou en échec.",
     "risk": "med", "dur": "~2 min", "reboot": True,
     "warn": "L'historique des mises à jour affiché dans Windows Update sera vidé. Redémarrage conseillé ensuite.",
     "steps": [_ps("Stop-Service ; Rename-Item SoftwareDistribution, catroot2 ; Start-Service", r"""
$svc = 'wuauserv', 'bits', 'cryptsvc', 'msiserver'
foreach ($s in $svc) { Stop-Service $s -Force -ErrorAction SilentlyContinue; "Service arrêté : $s" }
$ts = Get-Date -Format yyyyMMdd-HHmmss
foreach ($d in "$env:SystemRoot\SoftwareDistribution", "$env:SystemRoot\System32\catroot2") {
  if (Test-Path $d) {
    try { Rename-Item $d ((Split-Path $d -Leaf) + ".old-$ts") -ErrorAction Stop; "Renommé : $d" }
    catch { "Impossible de renommer $d : " + $_.Exception.Message }
  }
}
foreach ($s in $svc) { Start-Service $s -ErrorAction SilentlyContinue; "Service démarré : $s" }
'Terminé : redémarrer le poste puis relancer Windows Update.'""")]},

    {"id": "spooler", "cat": "Impression", "title": "Débloquer la file d'impression",
     "desc": "Arrête le spouleur, supprime les travaux d'impression bloqués et le redémarre.",
     "risk": "med", "dur": "~10 s", "reboot": False, "warn": "Tous les documents en attente d'impression seront annulés.",
     "steps": [_ps("Stop-Service Spooler ; vider spool\\PRINTERS ; Start-Service Spooler", r"""
Stop-Service Spooler -Force -ErrorAction Stop
$f = @(Get-ChildItem "$env:SystemRoot\System32\spool\PRINTERS" -File -ErrorAction SilentlyContinue)
$f | Remove-Item -Force -ErrorAction SilentlyContinue
"$($f.Count) fichier(s) de travaux d'impression supprimé(s)."
Start-Service Spooler -ErrorAction Stop
'Spouleur : ' + (Get-Service Spooler).Status""")]},

    {"id": "defender_update", "cat": "Sécurité", "title": "Mettre à jour Microsoft Defender",
     "desc": "Télécharge les dernières signatures antivirus de Defender.",
     "risk": "low", "dur": "~1 min", "reboot": False, "warn": "",
     "steps": [_ps("Update-MpSignature", r"""
try { Update-MpSignature -ErrorAction Stop } catch { 'Mise à jour impossible : ' + $_.Exception.Message + ' (antivirus tiers actif ?)'; exit 1 }
$s = Get-MpComputerStatus
'Signatures à jour : version ' + $s.AntivirusSignatureVersion + ' du ' + $s.AntivirusSignatureLastUpdated.ToString('dd/MM/yyyy HH:mm')""")]},

    {"id": "defender_quick", "cat": "Sécurité", "title": "Analyse antivirus rapide",
     "desc": "Lance une analyse rapide Microsoft Defender (zones les plus exposées) et liste les menaces connues.",
     "risk": "low", "dur": "2 à 10 min", "reboot": False, "warn": "",
     "steps": [_ps("Start-MpScan -ScanType QuickScan", r"""
'Analyse rapide en cours, patienter...'
try { Start-MpScan -ScanType QuickScan -ErrorAction Stop } catch { 'Analyse impossible : ' + $_.Exception.Message + ' (antivirus tiers actif ?)'; exit 1 }
$t = @(Get-MpThreat -ErrorAction SilentlyContinue)
if ($t.Count) { "$($t.Count) menace(s) connue(s) :"; $t | ForEach-Object { ' - ' + $_.ThreatName }; exit 2 }
'Analyse terminée : aucune menace active détectée.'""")]},
]
ACTION_BY_ID = {a["id"]: a for a in ACTIONS}


def recommend(sections):
    """Associe les constats du diagnostic aux actions de dépannage pertinentes."""
    rec = {}

    def add(aid, why):
        rec.setdefault(aid, why)
    for s in sections:
        k = s["key"]
        for x in s["findings"]:
            if x["level"] not in (WARN, CRIT):
                continue
            t, low = x["title"], x["title"].lower()
            if k == "network":
                if "dns" in low:
                    add("flush_dns", t)
                if "apipa" in low:
                    add("renew_ip", t)
                if "injoignable" in low or "perte de paquets" in low or "tcp 443" in low:
                    add("reset_network", t)
            elif k == "disks":
                if "espace" in low or "plein" in low:
                    add("clear_temp", t)
                    add("component_cleanup", t)
                if "smart" in low or "secteurs" in low or "santé" in low:
                    add("disk_scan", t)
            elif k == "updates":
                if "correctif" in low:
                    add("repair_wu", t)
                if "en attente" in low:
                    add("wu_scan", t)
            elif k == "security":
                if "signatures" in low:
                    add("defender_update", t)
                if "aucun antivirus" in low or "temps réel" in low:
                    add("defender_quick", t)
            elif k == "events":
                if "écran" in low:
                    add("sfc", t)
                    add("dism", t)
                if "stockage" in low:
                    add("disk_scan", t)
    if rec:
        rec = {"restore_point": "Conseillé avant d'appliquer les actions recommandées", **rec}
    return rec


def _decode_out(b):
    try:
        return b.decode("utf-8")
    except UnicodeDecodeError:
        for enc in ("oem", "cp850"):
            try:
                return b.decode(enc, "replace")
            except LookupError:
                continue
        return b.decode("latin-1", "replace")


# --------------------------------------------------------------------------- #
# Interface fenêtre (style E-Media Services)
# --------------------------------------------------------------------------- #
FONTS_B64 = {'400': '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', '600': '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', '700': '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'}  # Open Sans (SIL OFL 1.1), sous-ensemble latin

_BIN_SVG = ("<svg xmlns='http://www.w3.org/2000/svg' width='460' height='260'>"
            "<g fill='rgba(255,255,255,0.045)' font-family='Consolas,monospace' font-size='13'>"
            "<text x='12' y='28'>10100111001011010</text><text x='250' y='58'>0110100111</text>"
            "<text x='60' y='96'>0101100</text><text x='300' y='126'>1001011101100</text>"
            "<text x='20' y='168'>111010010110</text><text x='240' y='206'>01011</text>"
            "<text x='90' y='242'>1001110100101101</text></g></svg>")
BIN_BG = "data:image/svg+xml;base64," + __import__("base64").b64encode(_BIN_SVG.encode()).decode()

UI_HTML = r"""<!doctype html><html lang="fr"><head><meta charset="utf-8">
<style>
%%FONTS%%
:root{--bg:#0b141d;--panel:rgba(16,26,37,.93);--panel2:rgba(255,255,255,.035);--line:rgba(255,255,255,.08);
--tx:#e9eef3;--mut:#93a1b0;--or:#f59c1a;--or2:#ffb547;--ok:#00acac;--okt:#3fd6d6;--warn:#ffd900;--crit:#ff5b57;--info:#49b6d6}
*{box-sizing:border-box}html,body{height:100%;margin:0}
body{font:14px/1.55 'Open Sans','Segoe UI',sans-serif;color:var(--tx);overflow:hidden;background-color:var(--bg);
background-image:url("%%BINBG%%"),radial-gradient(circle at 50% 40%,transparent 0,transparent 18%,rgba(11,20,29,.92) 62%),
repeating-radial-gradient(circle at 50% 40%,transparent 0 62px,rgba(255,255,255,.04) 62px 63px),
radial-gradient(ellipse at 50% 30%,rgba(30,98,163,.22),transparent 65%)}
.app{display:flex;flex-direction:column;height:100vh}
.top{height:64px;flex:none;display:flex;align-items:center;gap:14px;padding:0 30px;background:rgba(6,11,17,.78);
border-bottom:1px solid rgba(255,255,255,.13);border-top:3px solid #1e62a3}
.top .logo{width:40px;height:40px;flex:none}
.brand{font-weight:700;font-size:19px;color:var(--or);line-height:1.1}
.brand small{display:block;font-size:10.5px;font-weight:600;color:var(--mut);letter-spacing:.16em;text-transform:uppercase;margin-top:3px}
.nav{margin-left:auto;display:flex;gap:28px;align-items:center}
.host{color:var(--mut);font-size:12.5px}
.nav button{background:none;border:0;border-bottom:2px solid transparent;color:#c3ccd5;font:600 12.5px 'Open Sans',sans-serif;
letter-spacing:.07em;text-transform:uppercase;cursor:pointer;padding:6px 0}
.nav button:hover:not(:disabled){color:var(--or);border-bottom-color:var(--or)}
.nav button:disabled{opacity:.3;cursor:default}
.scroll{flex:1;overflow:auto;scroll-behavior:smooth}
.scroll::-webkit-scrollbar{width:10px}.scroll::-webkit-scrollbar-thumb{background:rgba(255,255,255,.15);border-radius:5px}
/* écran d'analyse */
.hero{min-height:100%;display:flex;flex-direction:column;align-items:center;justify-content:center;text-align:center;padding:30px 20px}
.hero .logo{width:88px;height:88px;animation:beat 1.6s ease-in-out infinite;filter:drop-shadow(0 0 22px rgba(245,156,26,.35))}
@keyframes beat{0%,100%{transform:scale(1)}50%{transform:scale(1.07)}}
.hero h1{font-size:46px;font-weight:600;margin:26px 0 0;color:#fff;line-height:1.18}
.hero h1 .o{display:block;color:var(--or)}
.hero .sub{font-weight:700;font-size:18px;margin-top:20px}
.hero .sub2{color:#c9d2db;font-size:14px;margin-top:8px;min-height:22px}
.hero .sub2.err{color:var(--crit)}
.bar{width:min(540px,80vw);height:6px;background:rgba(255,255,255,.1);border-radius:3px;margin:30px auto 20px;overflow:hidden}
.bar i{display:block;height:100%;width:0;background:linear-gradient(90deg,var(--or),var(--or2));transition:width .45s}
.steps{display:flex;flex-wrap:wrap;gap:8px;justify-content:center;max-width:760px}
.step{font-size:12px;font-weight:600;padding:5px 13px;border:1px solid var(--line);border-radius:20px;color:var(--mut);background:rgba(0,0,0,.25)}
.step.done{color:#fff;border-color:rgba(245,156,26,.65)}.step.done::before{content:'\2713  ';color:var(--or)}
/* résultats */
.res{display:grid;grid-template-columns:220px minmax(0,1fr);gap:28px;max-width:1260px;margin:0 auto;padding:28px 30px 60px}
.side{position:sticky;top:0;align-self:start;padding-top:4px}
.side .t{font-size:11px;font-weight:700;letter-spacing:.14em;text-transform:uppercase;color:var(--or);margin:0 0 8px 14px}
.side a{display:flex;align-items:center;gap:10px;padding:8px 12px;color:#b9c4cf;font-size:13px;font-weight:600;
border-left:2px solid rgba(255,255,255,.08);cursor:pointer;text-decoration:none}
.side a:hover{color:#fff;border-left-color:var(--or);background:rgba(255,255,255,.03)}
.dot{width:8px;height:8px;border-radius:50%;flex:none}
.d-ok{background:var(--ok)}.d-warn{background:var(--warn)}.d-crit{background:var(--crit)}
.card{background:var(--panel);border:1px solid var(--line);border-radius:6px;padding:22px 24px;margin-bottom:20px;scroll-margin-top:16px}
.card h2{margin:0 0 14px;font-size:17px;font-weight:600;color:#fff;display:flex;align-items:center;gap:11px}
.card h2::before{content:'';width:4px;height:19px;background:var(--or);border-radius:2px}
.card h3{font-size:12px;font-weight:700;letter-spacing:.12em;text-transform:uppercase;color:var(--or);margin:22px 0 4px}
.sum{border-top:3px solid var(--or)}
.sumrow{display:flex;align-items:center;justify-content:space-between;gap:24px;flex-wrap:wrap}
.lbl{font-size:12px;color:var(--mut);text-transform:uppercase;letter-spacing:.14em;font-weight:600}
.big{font-size:40px;font-weight:700;line-height:1.15;margin:2px 0 4px}
.v-ok{color:var(--okt)}.v-warn{color:var(--warn)}.v-crit{color:var(--crit)}
.meta{color:var(--mut);font-size:13px}.meta b{color:#dfe6ec;font-weight:600}.meta span{margin-right:18px;white-space:nowrap}
.counts{display:flex;gap:12px}
.cnt{min-width:96px;text-align:center;padding:12px 10px;border-radius:6px;background:var(--panel2);border:1px solid var(--line)}
.cnt b{display:block;font-size:28px;line-height:1.1}.cnt span{font-size:11px;letter-spacing:.1em;text-transform:uppercase;color:var(--mut);font-weight:600}
.c-crit b{color:var(--crit)}.c-warn b{color:var(--warn)}.c-ok b{color:var(--okt)}
.note{margin-top:16px;padding:10px 14px;border-left:3px solid var(--info);background:rgba(73,182,214,.08);color:#cfe9f2;font-size:13px}
ul.f{list-style:none;margin:0;padding:0}
ul.f li{display:flex;gap:14px;align-items:flex-start;padding:10px 0;border-bottom:1px dashed var(--line)}
ul.f li:last-child{border-bottom:0}
ul.f b{font-weight:600;color:#fff}ul.f .sec{color:var(--mut);font-size:12.5px;margin-left:6px}
ul.f p{margin:3px 0 0;color:var(--mut);font-size:13px}
.badge{flex:none;font-size:10.5px;font-weight:700;letter-spacing:.06em;text-transform:uppercase;padding:3px 0;width:84px;
text-align:center;border-radius:3px;margin-top:1px;border:1px solid}
.b-ok{color:var(--okt);border-color:rgba(0,172,172,.55);background:rgba(0,172,172,.12)}
.b-warn{color:var(--warn);border-color:rgba(255,217,0,.5);background:rgba(255,217,0,.09)}
.b-crit{color:#ff8a87;border-color:rgba(255,91,87,.6);background:rgba(255,91,87,.13)}
.b-info{color:#8fd4e8;border-color:rgba(73,182,214,.5);background:rgba(73,182,214,.1)}
table{width:100%;border-collapse:collapse;font-size:13px;margin-top:8px}
caption{caption-side:top;text-align:left;color:var(--or);font-weight:600;font-size:12.5px;padding:16px 0 4px}
th{text-align:left;font-size:10.5px;letter-spacing:.1em;text-transform:uppercase;color:var(--mut);font-weight:700;
padding:8px 10px;border-bottom:1px solid rgba(245,156,26,.5)}
td{padding:7px 10px;border-bottom:1px solid var(--line);color:#dbe3ea;vertical-align:top;word-break:break-word}
tr:hover td{background:rgba(255,255,255,.025)}
pre{background:rgba(0,0,0,.35);border:1px solid var(--line);color:#dbe3ea;padding:12px;border-radius:4px;overflow:auto;font-size:12px;white-space:pre-wrap}
details{margin-top:10px}details summary{cursor:pointer;color:var(--or);font-weight:600;font-size:13px}
.foot{text-align:center;color:var(--mut);font-size:12px;margin-top:8px}
.toast{position:fixed;right:24px;bottom:24px;max-width:520px;background:#16222f;border:1px solid rgba(245,156,26,.6);
color:#fff;padding:12px 16px;border-radius:6px;font-size:13px;opacity:0;transform:translateY(10px);transition:.3s;pointer-events:none}
.toast.show{opacity:1;transform:none}
/* onglets */
.tabs{display:flex;align-self:stretch;margin-left:40px}
.tab{background:none;border:0;border-bottom:3px solid transparent;color:#b9c4cf;font:700 12.5px 'Open Sans',sans-serif;
letter-spacing:.1em;text-transform:uppercase;padding:0 18px;cursor:pointer}
.tab:hover{color:#fff}.tab.on{color:var(--or);border-bottom-color:var(--or)}
.tab .n{display:inline-block;min-width:18px;padding:0 5px;margin-left:7px;border-radius:9px;background:var(--or);color:#111;font-size:10.5px;line-height:18px;letter-spacing:0}
/* dépannage */
.dep{display:grid;grid-template-columns:minmax(0,1fr) 410px;gap:24px;max-width:1300px;margin:0 auto;padding:28px 30px 40px}
.grp{font-size:12px;font-weight:700;letter-spacing:.14em;text-transform:uppercase;color:var(--or);margin:4px 0 12px;display:flex;align-items:center;gap:10px}
.grp::after{content:'';flex:1;height:1px;background:var(--line)}
.agrid{display:grid;grid-template-columns:repeat(auto-fill,minmax(290px,1fr));gap:16px;margin-bottom:26px}
.act{background:var(--panel);border:1px solid var(--line);border-radius:6px;padding:16px 18px;display:flex;flex-direction:column;gap:9px}
.act.rec{border-color:rgba(245,156,26,.6);box-shadow:inset 0 0 0 1px rgba(245,156,26,.15)}
.ah{display:flex;justify-content:space-between;align-items:flex-start;gap:8px}.ah b{font-weight:600;color:#fff;font-size:14.5px}
.rb{font-size:10px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:#111;background:var(--or);padding:2px 8px;border-radius:3px;white-space:nowrap}
.act p{margin:0;color:var(--mut);font-size:13px;flex:1}
.why{font-size:12.5px;color:#ffd38a}.why span{color:var(--or);font-weight:700}
.chips{display:flex;flex-wrap:wrap;gap:6px}
.chip{font-size:11px;font-weight:600;padding:2px 9px;border-radius:10px;background:rgba(255,255,255,.06);color:#c3ccd5}
.r-low{color:var(--okt);background:rgba(0,172,172,.12)}.r-med{color:var(--warn);background:rgba(255,217,0,.1)}
.r-high{color:#ff8a87;background:rgba(255,91,87,.13)}.r-boot{color:#8fd4e8;background:rgba(73,182,214,.12)}
.af{display:flex;align-items:center;justify-content:space-between;gap:10px;margin-top:2px}
.st{font-size:12.5px;font-weight:600;color:var(--mut)}.st.ok{color:var(--okt)}.st.warn{color:var(--warn)}.st.err{color:var(--crit)}.st.run{color:var(--or)}
.btn{background:var(--or);color:#121212;border:0;font:700 12px 'Open Sans',sans-serif;letter-spacing:.07em;text-transform:uppercase;padding:8px 18px;border-radius:3px;cursor:pointer}
.btn:hover:not(:disabled){background:var(--or2)}.btn:disabled{opacity:.3;cursor:default}
.btn2{background:none;border:1px solid rgba(255,255,255,.25);color:#c3ccd5;font:600 12px 'Open Sans',sans-serif;letter-spacing:.07em;text-transform:uppercase;padding:8px 16px;border-radius:3px;cursor:pointer}
.btn2:hover{border-color:#fff;color:#fff}
.spin{display:inline-block;width:12px;height:12px;border:2px solid rgba(245,156,26,.3);border-top-color:var(--or);border-radius:50%;animation:rot .8s linear infinite;vertical-align:-2px;margin-right:7px}
@keyframes rot{to{transform:rotate(360deg)}}
.jr{position:sticky;top:0;align-self:start;height:calc(100vh - 120px);display:flex;flex-direction:column;background:rgba(4,9,14,.94);
border:1px solid var(--line);border-top:3px solid var(--or);border-radius:6px;overflow:hidden}
.jh{display:flex;align-items:center;gap:8px;padding:10px 14px;border-bottom:1px solid var(--line);font-size:12px}
.jh .jt{font-weight:700;letter-spacing:.12em;text-transform:uppercase;color:var(--or)}
.jcur{flex:1;color:var(--mut);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.jh button{background:none;border:1px solid rgba(255,255,255,.18);color:#c3ccd5;font:600 10.5px 'Open Sans',sans-serif;text-transform:uppercase;letter-spacing:.06em;padding:4px 9px;border-radius:3px;cursor:pointer}
.jh button:hover:not(:disabled){border-color:var(--or);color:var(--or)}.jh button:disabled{opacity:.3;cursor:default}
.jb{flex:1;overflow:auto;padding:10px 14px 16px;font:12px/1.55 Consolas,'Cascadia Mono',monospace;color:#cfd8e0}
.jb::-webkit-scrollbar{width:8px}.jb::-webkit-scrollbar-thumb{background:rgba(255,255,255,.15);border-radius:4px}
.jl{white-space:pre-wrap;word-break:break-word}.k-cmd{color:var(--or)}.k-err{color:#ff8a87}.k-warn{color:var(--warn)}.k-ok{color:var(--okt)}
.k-prog{color:#9fb0c0}.k-mut{color:var(--mut);font-family:'Open Sans',sans-serif}
.k-hd{color:#fff;font-weight:700;margin-top:12px;padding-top:9px;border-top:1px dashed rgba(255,255,255,.14)}.jb .k-hd:first-child{margin-top:0;border:0;padding-top:0}
.ov{position:fixed;inset:0;background:rgba(3,7,11,.75);display:none;align-items:center;justify-content:center;z-index:50}.ov.show{display:flex}
.md{width:min(580px,92vw);background:#121d29;border:1px solid var(--line);border-top:3px solid var(--or);border-radius:6px;padding:22px 24px;box-shadow:0 20px 60px rgba(0,0,0,.5)}
.md h3{margin:0 0 8px;font-size:19px;font-weight:600;color:#fff}.md p{margin:0 0 14px;color:#c9d2db;font-size:13.5px}
.mw{display:none;border-left:3px solid var(--warn);background:rgba(255,217,0,.07);color:#ffe98a;padding:9px 12px;font-size:13px;margin-bottom:14px}.mw.show{display:block}
.ml{font-size:11px;font-weight:700;letter-spacing:.12em;text-transform:uppercase;color:var(--mut);margin-bottom:5px}
.md pre{margin:0 0 20px;max-height:170px;font-family:Consolas,monospace}.mb{display:flex;justify-content:flex-end;gap:10px}
.dnote{margin:0 0 18px}
</style></head><body>
<div class="app">
 <header class="top">%%LOGO%%
  <div class="brand">E-A2 Scan<small>Diagnostic de poste</small></div>
  <div class="tabs"><button class="tab on" id="tDiag" onclick="tab('diag')">Diagnostic</button>
   <button class="tab" id="tDep" onclick="tab('dep')">Dépannage<span class="n" id="nReco" style="display:none"></span></button></div>
  <div class="nav"><span class="host" id="host"></span>
   <button id="bScan" disabled onclick="rescan()">Relancer l'analyse</button>
   <button id="bExp" disabled onclick="exportRep()">Exporter</button></div>
 </header>
 <main class="scroll" id="scroll">
  <section class="hero" id="load">%%LOGO%%
   <h1>Analyse en cours<span class="o" id="hname">&hellip;</span></h1>
   <div class="sub">Diagnostic complet du poste</div>
   <div class="sub2" id="stat">Préparation&hellip;</div>
   <div class="bar"><i id="bar"></i></div>
   <div class="steps" id="steps"></div>
  </section>
  <section class="res" id="res" style="display:none"><nav class="side" id="side"></nav><div id="content"></div></section>
  <section class="dep" id="dep" style="display:none"><div id="acts"></div>
   <aside class="jr"><div class="jh"><span class="jt">Journal</span><span class="jcur" id="jcur">Aucune action en cours</span>
    <button id="jStop" disabled onclick="stopAct()">Arrêter</button><button onclick="copyLog()">Copier</button></div>
    <div class="jb" id="jb"><div class="jl k-mut">Le résultat des actions s'affiche ici en direct.</div></div></aside>
  </section>
 </main>
</div>
<div class="ov" id="ov"><div class="md"><h3 id="mT"></h3><p id="mD"></p><div class="mw" id="mW"></div>
 <div class="ml">Commandes exécutées</div><pre id="mC"></pre>
 <div class="mb"><button class="btn2" onclick="closeM()">Annuler</button><button class="btn" id="mGo">Lancer l'action</button></div></div></div>
<div class="toast" id="toast"></div>
<script>
window.__errs=[];window.addEventListener('error',e=>window.__errs.push(String(e.message)+' @'+(e.lineno||'')));
window.addEventListener('unhandledrejection',e=>window.__errs.push('promesse : '+String(e.reason&&e.reason.message||e.reason)));
const $=s=>document.querySelector(s);
function el(t,c,x){const e=document.createElement(t);if(c)e.className=c;if(x!=null)e.textContent=x;return e}
const LBL={ok:'OK',warn:'Attention',crit:'Critique',info:'Info'}, LV={ok:0,info:1,warn:2,crit:3};
let plan=[],secs={},nDone=0,meta={};
function worst(s){let w='ok';for(const x of s.findings)if(x.level!=='info'&&LV[x.level]>LV[w])w=x.level;return w}
function busy(b){$('#bScan').disabled=b;$('#bExp').disabled=b}
function toast(m){const t=$('#toast');t.textContent=m;t.classList.add('show');clearTimeout(t._h);t._h=setTimeout(()=>t.classList.remove('show'),4500)}
function finding(x,sec){const li=el('li');li.append(el('span','badge b-'+x.level,LBL[x.level]));const d=el('div');
 d.append(el('b',null,x.title));if(sec)d.append(el('span','sec',sec));if(x.detail)d.append(el('p',null,x.detail));li.append(d);return li}
function table(t){const tb=el('table');if(t.caption)tb.append(el('caption',null,t.caption));const h=el('tr');
 for(const c of t.headers)h.append(el('th',null,c));tb.append(h);
 for(const r of t.rows){const tr=el('tr');for(const c of r)tr.append(el('td',null,c==null?'':String(c)));tb.append(tr)}return tb}
window.E={
 start(d){meta=d.meta;plan=d.plan;secs={};nDone=0;busy(true);
  $('#host').textContent=meta.hostname+'  ·  '+meta.date;$('#hname').textContent=meta.hostname;
  $('#stat').className='sub2';$('#stat').textContent='0 / '+plan.length+' modules analysés';$('#bar').style.width='3%';
  const st=$('#steps');st.innerHTML='';for(const p of plan){const s=el('span','step',p.title);s.id='st-'+p.key;st.append(s)}
  diagState='load';showView();$('#scroll').scrollTop=0},
 section(s){secs[s.key]=s;nDone++;const e=document.getElementById('st-'+s.key);if(e)e.classList.add('done');
  $('#stat').textContent=nDone+' / '+plan.length+' modules analysés';$('#bar').style.width=Math.max(3,100*nDone/plan.length)+'%'},
 done(d){meta=d.meta;RECO=d.reco||{};render(d.summary);renderActs();diagState='res';showView();busy(false);if(view!=='diag')toast('Analyse terminée.')},
 fail(m){$('#stat').className='sub2 err';$('#stat').textContent='Erreur : '+m;$('#bScan').disabled=false}
};
function render(sm){
 const c=$('#content'),side=$('#side');c.innerHTML='';side.innerHTML='';side.append(el('div','t','Modules'));
 const k=sm.crit?'crit':(sm.warn?'warn':'ok');
 const card=el('div','card sum');card.id='sec-sum';const row=el('div','sumrow');const l=el('div');
 l.append(el('div','lbl','État du poste'),el('div','big v-'+k,sm.verdict));
 const m=el('div','meta');m.innerHTML='';const add=(a,b)=>{const s=el('span');s.append(el('b',null,a+' : '),document.createTextNode(b));m.append(s)};
 add('Poste',meta.hostname);add('Date',meta.date);add('Durée',Math.round(meta.duration)+' s');l.append(m);
 const cs=el('div','counts');for(const [n,cl,t] of [[sm.crit,'c-crit','Critique'],[sm.warn,'c-warn','Attention'],[sm.ok,'c-ok','OK']]){
  const b=el('div','cnt '+cl);b.append(el('b',null,n),el('span',null,t));cs.append(b)}
 row.append(l,cs);card.append(row);
 if(!meta.admin)card.append(el('div','note','Lancé sans droits administrateur : certains contrôles (BitLocker, SMART, journaux) sont partiels.'));
 const nr=Object.keys(RECO).length;if(nr){const r=el('div','note');r.style.cssText='border-left-color:var(--or);background:rgba(245,156,26,.08);color:#ffe0b0;display:flex;align-items:center;justify-content:space-between;gap:12px';
  r.append(el('span',null,nr+' action(s) de dépannage recommandée(s) pour ce poste.'));const b=el('button','btn','Voir le dépannage');b.onclick=()=>tab('dep');r.append(b);card.append(r)}
 card.append(el('h3',null,sm.top.length?"Points d'attention":'Aucun point d\'attention'));
 const ul=el('ul','f');for(const t of sm.top)ul.append(finding({level:t[0],title:t[2],detail:t[3]},t[1]));card.append(ul);c.append(card);
 const a0=el('a');a0.append(el('span','dot d-'+k),document.createTextNode('Synthèse'));a0.onclick=()=>card.scrollIntoView();side.append(a0);
 for(const p of plan){const s=secs[p.key];if(!s)continue;const cd=el('div','card');cd.id='sec-'+s.key;cd.append(el('h2',null,s.title));
  const u=el('ul','f');for(const x of s.findings)u.append(finding(x));cd.append(u);
  for(const t of s.tables){const tb=table(t);if(s.collapse||t.rows.length>40){const dd=el('details');
   dd.append(el('summary',null,'Afficher la liste ('+t.rows.length+' lignes)'),tb);cd.append(dd)}else cd.append(tb)}
  if(s.pre)cd.append(el('pre',null,s.pre));c.append(cd);
  const a=el('a');a.append(el('span','dot d-'+worst(s)),document.createTextNode(s.title));a.onclick=()=>cd.scrollIntoView();side.append(a)}
 c.append(el('div','foot',meta.app+' v'+meta.version+'  ·  E-Media Services / A2MI'));
 if(view==='diag')$('#scroll').scrollTop=0}
let view='diag',diagState='load',ACTS=[],RECO={},ST={},running=null;
const RISK={low:'Sans risque',med:'Modéré',high:'Impactant'};
function showView(){const d=view==='diag';$('#tDiag').classList.toggle('on',d);$('#tDep').classList.toggle('on',!d);
 $('#load').style.display=d&&diagState==='load'?'flex':'none';$('#res').style.display=d&&diagState==='res'?'grid':'none';
 $('#dep').style.display=d?'none':'grid'}
function tab(t){if(view===t)return;view=t;showView();$('#scroll').scrollTop=0}
function setSt(id,cls,html){ST[id]={cls,html};const e=document.getElementById('s-'+id);if(e){e.className='st '+cls;e.innerHTML=html}}
function actCard(a){const r=RECO[a.id];const c=el('div','act'+(r?' rec':''));c.id='a-'+a.id;
 const h=el('div','ah');h.append(el('b',null,a.title));if(r)h.append(el('span','rb','Recommandé'));c.append(h);
 c.append(el('p',null,a.desc));
 if(r){const w=el('div','why');w.append(el('span',null,'Constat : '),document.createTextNode(r));c.append(w)}
 const ch=el('div','chips');ch.append(el('span','chip','⏱ '+a.dur),el('span','chip r-'+a.risk,RISK[a.risk]));
 if(a.reboot)ch.append(el('span','chip r-boot','Redémarrage requis'));c.append(ch);
 const f=el('div','af');const st=el('span','st');st.id='s-'+a.id;if(ST[a.id]){st.className='st '+ST[a.id].cls;st.innerHTML=ST[a.id].html}
 const b=el('button','btn go','Lancer');b.id='b-'+a.id;b.disabled=!!running;b.onclick=()=>ask(a);f.append(st,b);c.append(f);return c}
function renderActs(){const box=$('#acts');box.innerHTML='';
 if(!ACTS.length){const c=el('div','card');c.append(el('h2',null,'Dépannage'),el('p',null,'Les actions de dépannage sont disponibles sous Windows uniquement.'));box.append(c);return}
 if(meta&&meta.hostname&&meta.admin===false)box.append(el('div','note dnote','Logiciel lancé sans droits administrateur : la plupart des actions échoueront. Relance E-A2 Scan en administrateur.'));
 const rec=ACTS.filter(a=>RECO[a.id]);const n=$('#nReco');n.style.display=rec.length?'inline-block':'none';n.textContent=rec.length;
 const group=(title,list)=>{if(!list.length)return;box.append(el('div','grp',title));const g=el('div','agrid');for(const a of list)g.append(actCard(a));box.append(g)};
 group('Recommandé pour ce poste',rec);
 const cats=[];for(const a of ACTS)if(!cats.includes(a.cat))cats.push(a.cat);
 for(const c of cats)group(c,ACTS.filter(a=>a.cat===c&&!RECO[a.id]))}
function ask(a){if(running)return;if(a.risk==='low')return go(a);
 $('#mT').textContent=a.title;$('#mD').textContent=a.desc;const w=$('#mW');w.textContent=a.warn||'';w.classList.toggle('show',!!a.warn);
 $('#mC').textContent=a.cmds.join('\n');$('#mGo').onclick=()=>{closeM();go(a)};$('#ov').classList.add('show')}
function closeM(){$('#ov').classList.remove('show')}
function go(a){if(!window.pywebview)return;pywebview.api.run_action(a.id).then(ok=>{if(!ok)toast('Une action est déjà en cours.')})}
function stopAct(){if(window.pywebview)pywebview.api.cancel_action()}
function jline(t,k){const jb=$('#jb');const near=jb.scrollHeight-jb.scrollTop-jb.clientHeight<60;
 const last=jb.lastElementChild;if(k==='prog'&&last&&last.dataset.k==='prog'){last.textContent=t}
 else{const d=el('div','jl k-'+k,t);d.dataset.k=k;jb.append(d);while(jb.childElementCount>4000)jb.firstElementChild.remove()}
 if(near)jb.scrollTop=jb.scrollHeight}
const STEND={ok:['ok','✓ Terminé'],warn:['warn','Terminé avec avertissements'],err:['err','✗ Échec'],stopped:['','Arrêtée']};
Object.assign(window.E,{
 actStart(d){running=d.id;document.querySelectorAll('.go').forEach(b=>b.disabled=true);
  setSt(d.id,'run','<span class="spin"></span>En cours…');$('#jcur').textContent=d.title;$('#jStop').disabled=false;
  const jb=$('#jb');if(jb.firstElementChild&&jb.firstElementChild.classList.contains('k-mut'))jb.innerHTML='';
  jline(d.time+'  ·  '+d.title,'hd')},
 actLog(d){for(const l of d.lines)jline(l.t,l.k)},
 actEnd(d){running=null;const [c,t]=STEND[d.status]||['',d.status];setSt(d.id,c,t+' ('+d.dur+' s)');
  jline(t+' en '+d.dur+' s',d.status==='ok'?'ok':(d.status==='warn'?'warn':'err'));
  if(d.reboot&&(d.status==='ok'||d.status==='warn'))jline('Redémarrage du poste nécessaire pour finaliser.','warn');
  document.querySelectorAll('.go').forEach(b=>b.disabled=false);$('#jcur').textContent='Aucune action en cours';$('#jStop').disabled=true;
  toast(t+' : relance l\'analyse pour vérifier le résultat.')}
});
function copyLog(){const ta=el('textarea');ta.value=$('#jb').innerText;document.body.append(ta);ta.select();
 try{document.execCommand('copy');toast('Journal copié dans le presse-papiers.')}catch(e){}ta.remove()}
function rescan(){if(window.pywebview){view='diag';pywebview.api.start_scan()}}
function exportRep(){if(!window.pywebview)return;pywebview.api.export_report().then(p=>{if(p)toast('Rapport enregistré : '+p)})}
window.addEventListener('pywebviewready',()=>{pywebview.api.list_actions().then(a=>{ACTS=a||[];renderActs()});pywebview.api.start_scan();pywebview.api.ready()});
</script></body></html>"""


def build_ui_html():
    fonts = "".join("@font-face{font-family:'Open Sans';font-style:normal;font-weight:%s;"
                    "src:url(data:font/woff2;base64,%s) format('woff2')}" % (w, b) for w, b in FONTS_B64.items())
    return (UI_HTML.replace("%%FONTS%%", fonts).replace("%%LOGO%%", LOGO_SVG).replace("%%BINBG%%", BIN_BG))


class _Bridge:
    """Pont JS <-> Python exposé à la page (seules les méthodes publiques sont visibles)."""

    def __init__(self, args):
        self._args = args
        self._window = None
        self._busy = False
        self._last = None
        self._lock = threading.Lock()
        self._act = None          # action en cours
        self._proc = None
        self._cancel = False
        self._history = []        # actions effectuées (pour l'export)
        self._out = []
        self._pend = []
        self._plock = threading.Lock()

    # ---- actions de dépannage ------------------------------------------- #
    def list_actions(self):
        if not IS_WIN:
            return []
        return [{**{k: v for k, v in a.items() if k != "steps"}, "cmds": [s["show"] for s in a["steps"]]}
                for a in ACTIONS]

    def run_action(self, aid):
        a = ACTION_BY_ID.get(aid)
        if not a or not IS_WIN:
            return False
        with self._lock:
            if self._act:
                return False
            self._act = aid
            self._cancel = False
        threading.Thread(target=self._run_action, args=(a,), daemon=True).start()
        return True

    def cancel_action(self):
        self._cancel = True
        p = self._proc
        if p and p.poll() is None:
            subprocess.run(["taskkill", "/PID", str(p.pid), "/T", "/F"], stdin=subprocess.DEVNULL,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=0x08000000)
        return True

    def _run_action(self, a):
        t0, start = time.time(), dt.datetime.now()
        self._out, self._pend = [], []
        status = "ok"
        self._js("actStart", {"id": a["id"], "title": a["title"], "time": start.strftime("%H:%M:%S")})
        stop = threading.Event()
        threading.Thread(target=self._flusher, args=(stop,), daemon=True).start()
        try:
            for st in a["steps"]:
                if self._cancel:
                    break
                self._line("> " + st["show"], "cmd")
                if st["kind"] == "ps":
                    cmd = ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                           "-Command", PS_PRE + st["run"]]
                else:
                    cmd = st["run"]
                i0 = len(self._out)
                code = self._stream(cmd)
                if self._cancel:
                    break
                if code not in (0, None):
                    txt = " ".join(t for t, _ in self._out[i0:]).lower()
                    if re.search(r"élévation|elevation|access denied|accès refusé|acces refuse|requires elevation", txt):
                        self._line("Échec : droits administrateur requis. Relance E-A2 Scan en administrateur.", "err")
                        status = "err"
                        break
                    self._line(f"Code de retour : {code}", "warn")
                    status = "warn"
            if self._cancel:
                status = "stopped"
                self._line("Action arrêtée.", "err")
        except FileNotFoundError as e:
            status = "err"
            self._line(f"Commande introuvable : {e}", "err")
        except Exception as e:
            status = "err"
            self._line(f"Erreur : {type(e).__name__}: {e}", "err")
        finally:
            stop.set()
            self._flush()
            dur = time.time() - t0
            self._history.append({"time": start.strftime("%d/%m/%Y %H:%M"), "title": a["title"], "status": status,
                                  "dur": dur, "log": self._out[-80:]})
            self._proc = None
            self._act = None
            self._js("actEnd", {"id": a["id"], "status": status, "dur": round(dur), "reboot": a["reboot"]})

    def _stream(self, cmd):
        p = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                             creationflags=0x08000000 if IS_WIN else 0)
        self._proc = p
        self._in_prog = False
        buf, mode, part = b"", None, ""
        while True:
            chunk = p.stdout.read1(4096)
            if not chunk:
                break
            buf += chunk
            if mode is None:
                if len(buf) < 2:
                    continue
                mode = "u16" if buf[1:2] == b"\x00" or buf.count(b"\x00") * 3 > len(buf) else "b"
            if mode == "u16":
                n = len(buf) // 2 * 2
                text, buf = buf[:n].decode("utf-16-le", "replace"), buf[n:]
            else:
                i = max(buf.rfind(b"\n"), buf.rfind(b"\r"))
                if i < 0:
                    continue
                text, buf = _decode_out(buf[:i + 1]), buf[i + 1:]
            part = self._feed(part + text)
        if buf:
            part = self._feed(part + (buf.decode("utf-16-le", "replace") if mode == "u16" else _decode_out(buf)))
        if part.strip():
            self._line(part.strip(), "out")
        p.wait()
        return p.returncode

    def _feed(self, text):
        lines = text.replace("\x00", "").split("\n")
        part = lines.pop()
        for ln in lines:
            segs = [s for s in ln.split("\r") if s.strip()]
            if segs:
                self._line(segs[-1].rstrip(), "prog" if (len(segs) > 1 or self._in_prog) else "out")
            self._in_prog = False
        if "\r" in part:
            segs = part.split("\r")
            part = segs[-1]
            done = [s for s in segs[:-1] if s.strip()]
            if done:
                self._line(done[-1].rstrip(), "prog")
                self._in_prog = True
        return part

    def _line(self, text, kind):
        with self._plock:
            if kind == "prog" and self._out and self._out[-1][1] == "prog":
                self._out[-1] = (text, kind)
            else:
                self._out.append((text, kind))
            if kind == "prog" and self._pend and self._pend[-1]["k"] == "prog":
                self._pend[-1] = {"t": text, "k": kind}
            else:
                self._pend.append({"t": text, "k": kind})

    def _flush(self):
        with self._plock:
            lines, self._pend = self._pend, []
        if lines:
            self._js("actLog", {"lines": lines})

    def _flusher(self, stop):
        while not stop.wait(0.2):
            self._flush()

    def ready(self):
        if getattr(self._args, "fulltest", ""):
            import ea2_scan_tests
            threading.Thread(target=ea2_scan_tests.run_full, args=(self,), daemon=True).start()
        return True

    def start_scan(self):
        with self._lock:
            if self._busy:
                return False
            self._busy = True
        threading.Thread(target=self._scan, daemon=True).start()
        return True

    def export_report(self):
        if not self._last:
            return ""
        import webview
        meta, sections, summary = self._last
        mode = getattr(getattr(webview, "FileDialog", None), "SAVE", None)
        if mode is None:
            mode = webview.SAVE_DIALOG
        name = f"E-A2Scan_{re.sub(r'[^A-Za-z0-9._-]', '_', meta['hostname'])}_{meta['stamp']}.html"
        desk = Path.home() / "Desktop"
        res = self._window.create_file_dialog(mode, directory=str(desk) if desk.is_dir() else "",
                                              save_filename=name, file_types=("Page HTML (*.html)",))
        if not res:
            return ""
        path = res if isinstance(res, str) else res[0]
        if not path.lower().endswith(".html"):
            path += ".html"
        Path(path).write_text(render_html(meta, sections, summary, self._history), encoding="utf-8")
        return path

    def _js(self, fn, data):
        try:
            self._window.evaluate_js(f"window.E && E.{fn}({json.dumps(data, ensure_ascii=False)})")
        except Exception:
            pass

    def _scan(self):
        try:
            t0 = time.time()
            tasks = plan_tasks(self._args)
            meta = new_meta(self._args)
            self._js("start", {"meta": meta, "plan": [{"key": k, "title": t} for k, t, _ in tasks]})
            sections = run_scan(self._args, tasks, lambda s: self._js("section", s))
            summary = summarize(sections)
            meta["duration"] = time.time() - t0
            self._last = (meta, sections, summary)
            reco = recommend(sections) if IS_WIN else {}
            self._js("done", {"meta": meta, "summary": summary, "reco": reco})
            if self._args.selftest:
                self._selftest(f"verdict={summary['verdict']} reco={list(reco)}")
        except Exception as e:
            self._js("fail", f"{type(e).__name__}: {e}")
            if self._args.selftest:
                self._selftest(f"FAIL {type(e).__name__}: {e}")
        finally:
            self._busy = False

    def _selftest(self, info):
        time.sleep(1.5)
        try:
            n = self._window.evaluate_js("document.querySelectorAll('#res .card').length")
            disp = self._window.evaluate_js("getComputedStyle(document.getElementById('res')).display")
            font = self._window.evaluate_js("document.fonts.check(\"600 16px 'Open Sans'\")")
            nact = self._window.evaluate_js("document.querySelectorAll('.act').length")
            msg = f"cards={n} res_display={disp} openSans={font} actions_ui={nact} {info}"
            if IS_WIN:  # deux actions sans impact : cmd (sortie OEM) et PowerShell (UTF-8)
                for aid in ("flush_dns", "disk_scan"):
                    self.run_action(aid)
                    t = time.time()
                    while (self._act or not self._history or self._history[-1]["title"] != ACTION_BY_ID[aid]["title"]) \
                            and time.time() - t < 60:
                        time.sleep(0.3)
                    h = self._history[-1]
                    msg += f"\n[{aid}] status={h['status']} lines={len(h['log'])} last={h['log'][-1][0] if h['log'] else ''}"
                time.sleep(0.8)
                jb = self._window.evaluate_js("document.getElementById('jb').innerText")
                st = self._window.evaluate_js("document.getElementById('s-flush_dns').innerText")
                msg += f"\njournal_ui={len(jb or '')} chars ; statut_carte={st}\n---\n{(jb or '')[-700:]}"
        except Exception as e:
            msg = f"FAIL js {e} {info}"
        try:
            Path(self._args.selftest).write_text(msg, encoding="utf-8")
        finally:
            self._window.destroy()


def webview2_available():
    if not IS_WIN:
        return True
    try:
        import winreg  # type: ignore
        key = r"SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}"
        for root, k in ((winreg.HKEY_LOCAL_MACHINE, key), (winreg.HKEY_CURRENT_USER, key.replace("WOW6432Node\\", "")),
                        (winreg.HKEY_LOCAL_MACHINE, key.replace("WOW6432Node\\", ""))):
            try:
                with winreg.OpenKey(root, k) as h:
                    v = winreg.QueryValueEx(h, "pv")[0]
                    if v and v != "0.0.0.0":
                        return True
            except OSError:
                pass
    except Exception:
        pass
    return False


def gui_main(args):
    import webview
    bridge = _Bridge(args)
    win = webview.create_window(f"{APP_NAME} - Diagnostic de poste", html=build_ui_html(), js_api=bridge,
                                width=1280, height=840, min_size=(980, 640), background_color="#0b141d")
    bridge._window = win
    webview.start(gui="edgechromium" if IS_WIN else None, debug=False)
    return 0


def gui_fallback(args, reason=""):
    """Fenêtre simplifiée (tkinter) si le composant WebView2 est absent du poste."""
    import tkinter as tk
    from tkinter import scrolledtext
    BG, PANEL, OR = "#0b141d", "#111c27", "#f59c1a"
    root = tk.Tk()
    root.title(f"{APP_NAME} - Diagnostic de poste")
    root.geometry("1000x720")
    root.configure(bg=BG)
    top = tk.Frame(root, bg="#060b11", height=60)
    top.pack(fill="x")
    tk.Label(top, text=APP_NAME, fg=OR, bg="#060b11", font=("Segoe UI", 16, "bold")).pack(side="left", padx=20, pady=12)
    stat = tk.Label(top, text="Analyse en cours…", fg="#c3ccd5", bg="#060b11", font=("Segoe UI", 10))
    stat.pack(side="right", padx=20)
    txt = scrolledtext.ScrolledText(root, bg=PANEL, fg="#e9eef3", font=("Segoe UI", 10), relief="flat",
                                    borderwidth=0, padx=18, pady=14, wrap="word")
    txt.pack(fill="both", expand=True, padx=16, pady=16)
    for tag, col in (("crit", "#ff5b57"), ("warn", "#ffd900"), ("ok", "#3fd6d6"), ("info", "#8fd4e8"),
                     ("h", OR), ("mut", "#93a1b0")):
        txt.tag_config(tag, foreground=col)
    txt.tag_config("big", font=("Segoe UI", 20, "bold"))
    txt.tag_config("h", font=("Segoe UI", 12, "bold"))

    def show(sections, summary):
        txt.delete("1.0", "end")
        k = "crit" if summary["crit"] else ("warn" if summary["warn"] else "ok")
        txt.insert("end", "État du poste : ", "big")
        txt.insert("end", summary["verdict"] + "\n", ("big", k))
        txt.insert("end", f"{summary['crit']} critique(s), {summary['warn']} attention, {summary['ok']} OK\n\n", "mut")
        for s in sections:
            txt.insert("end", s["title"].upper() + "\n", "h")
            for x in s["findings"]:
                txt.insert("end", f"  [{x['level'].upper():>4}] ", x["level"])
                txt.insert("end", x["title"] + "\n")
                if x["detail"]:
                    txt.insert("end", "         " + x["detail"] + "\n", "mut")
            for t in s["tables"]:
                if s.get("collapse"):
                    continue
                if t.get("caption"):
                    txt.insert("end", "  " + t["caption"] + "\n", "mut")
                for r in t["rows"][:40]:
                    txt.insert("end", "    " + "  |  ".join(str(c) for c in r) + "\n")
            txt.insert("end", "\n")
        txt.insert("end", "Affichage simplifié : le composant Microsoft WebView2 est absent de ce poste.\n", "mut")
        stat.config(text=f"Terminé - {socket.gethostname()}")

    def work():
        tasks = plan_tasks(args)
        n = [0]

        def cb(s):
            n[0] += 1
            root.after(0, lambda: stat.config(text=f"Analyse : {n[0]} / {len(tasks)} modules"))
        sections = run_scan(args, tasks, cb)
        summary = summarize(sections)
        root.after(0, lambda: show(sections, summary))

    threading.Thread(target=work, daemon=True).start()
    root.mainloop()
    return 0


def cli_main(args):
    """Mode console (scripts, Linux/macOS sans interface) : écrit HTML + JSON dans --out."""
    t0 = time.time()
    tasks = plan_tasks(args)
    meta = new_meta(args)
    print(f"{APP_NAME} v{VERSION} - {platform.system()} - admin={'oui' if meta['admin'] else 'non'}")
    n = [0]

    def cb(s):
        n[0] += 1
        print(f"  [{n[0]}/{len(tasks)}] {s['title']}")
    sections = run_scan(args, tasks, cb)
    summary = summarize(sections)
    meta["duration"] = time.time() - t0
    out_dir = Path(args.out or (base_dir() / "rapports"))
    out_dir.mkdir(parents=True, exist_ok=True)
    stem = f"E-A2Scan_{re.sub(r'[^A-Za-z0-9._-]', '_', meta['hostname'])}_{meta['stamp']}"
    (out_dir / f"{stem}.html").write_text(render_html(meta, sections, summary), encoding="utf-8")
    (out_dir / f"{stem}.json").write_text(json.dumps({"meta": meta, "summary": summary, "sections": sections},
                                                     ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\nÉtat global : {summary['verdict']}  ->  {out_dir / stem}.html")
    return 2 if summary["crit"] else (1 if summary["warn"] else 0)


def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore
    except Exception:
        pass
    ap = argparse.ArgumentParser(description=f"{APP_NAME} - diagnostic de poste (Windows/macOS/Linux).")
    ap.add_argument("--client", default="", help="Nom du client")
    ap.add_argument("--tech", default="", help="Nom du technicien")
    ap.add_argument("--quick", action="store_true", help="Saute les contrôles lents (mises à jour, logiciels)")
    ap.add_argument("--software", action="store_true", help="Inclut l'inventaire des logiciels installés")
    ap.add_argument("--no-net-tests", action="store_true", help="Pas de test vers Internet (ping, DNS, HTTP)")
    ap.add_argument("--public-ip", action="store_true", help="Relève l'IP publique (api.ipify.org)")
    ap.add_argument("--cli", action="store_true", help="Mode console : écrit un rapport HTML/JSON au lieu d'ouvrir la fenêtre")
    ap.add_argument("--out", default="", help="Dossier de sortie du mode --cli")
    ap.add_argument("--selftest", default="", help=argparse.SUPPRESS)
    ap.add_argument("--fulltest", default="", help=argparse.SUPPRESS)
    args = ap.parse_args()
    if args.cli:
        return cli_main(args)
    if IS_WIN and not webview2_available():
        return gui_fallback(args, "webview2")
    try:
        import webview  # noqa: F401
    except Exception as e:
        return gui_fallback(args, str(e))
    try:
        return gui_main(args)
    except Exception as e:
        return gui_fallback(args, str(e))


if __name__ == "__main__":
    code = main()
    try:
        sys.stdout.flush()
    except Exception:
        pass
    os._exit(code or 0)  # ne pas attendre les analyses encore en cours si la fenêtre est fermée
