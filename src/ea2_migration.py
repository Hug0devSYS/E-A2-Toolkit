# -*- coding: utf-8 -*-
"""E-A2 Migration - transfert de profil utilisateur d'un PC à un autre (sauvegarde puis restauration)."""
from __future__ import annotations

import argparse
import datetime as dt
import getpass
import html
import json
import os
import re
import shutil
import socket
import sqlite3
import tempfile
import threading
import time

from ea2ui import IS_WIN, BridgeBase, LiveRunner, build_page, finish, is_admin, ps_cmd, run, run_window

APP, VERSION = "E-A2 Migration", "1.0.0"
ROOT_DIR = "E-A2_Migration"
SKIP_PROFILES = {"public", "default", "default user", "all users", "defaultapppool", "wdagutilityaccount"}

FOLDERS = [  # clé, libellé, dossier connu, nom dans la sauvegarde, coché par défaut
    ("desktop", "Bureau", "Desktop", "Bureau", True),
    ("documents", "Documents", "MyDocuments", "Documents", True),
    ("pictures", "Images", "MyPictures", "Images", True),
    ("videos", "Vidéos", "MyVideos", "Videos", True),
    ("music", "Musique", "MyMusic", "Musique", True),
    ("downloads", "Téléchargements", "Downloads", "Telechargements", False),
]
EXTRAS = [  # clé, libellé, description, coché par défaut
    ("bookmarks", "Favoris des navigateurs", "Chrome, Edge, Firefox, Brave : convertis en fichier HTML importable partout", True),
    ("signatures", "Signatures Outlook", "Dossier Microsoft\\Signatures", True),
    ("pst", "Fichiers de données Outlook (.pst)", "Archives et comptes POP (les .ost IMAP/Exchange se resynchronisent seuls)", True),
    ("wifi", "Réseaux Wi-Fi enregistrés", "Profils et clés Wi-Fi (clés en clair dans la sauvegarde : à protéger)", True),
    ("printers", "Imprimantes", "Liste, et sauvegarde complète des imprimantes locales (PrintBrm)", True),
    ("netdrives", "Lecteurs réseau", "Lettres de lecteurs mappées (les mots de passe ne sont pas copiés)", True),
    ("wallpaper", "Fond d'écran", "Image de fond d'écran actuelle", True),
    ("software", "Liste des logiciels", "Inventaire + réinstallation automatique avec winget sur le nouveau PC", True),
]
BROWSERS = [("Chrome", r"Google\Chrome\User Data"), ("Edge", r"Microsoft\Edge\User Data"),
            ("Brave", r"BraveSoftware\Brave-Browser\User Data")]


def human(n):
    n = float(n or 0)
    for u in ("o", "Ko", "Mo", "Go", "To"):
        if n < 1024 or u == "To":
            return f"{n:.0f} {u}" if u in ("o", "Ko") else f"{n:.1f} {u}".replace(".", ",")
        n /= 1024
    return str(n)


# --------------------------------------------------------------------------- #
# Lecteurs, profils, dossiers connus
# --------------------------------------------------------------------------- #
def drives():
    res = []
    if not IS_WIN:
        for mp in ("/", "/tmp"):
            u = shutil.disk_usage(mp)
            res.append({"root": mp, "label": mp, "type": "Fixe", "free": u.free, "total": u.total, "removable": False})
        return res
    import ctypes
    k = ctypes.windll.kernel32
    mask = k.GetLogicalDrives()
    for i in range(26):
        if not mask & (1 << i):
            continue
        root = f"{chr(65 + i)}:\\"
        t = k.GetDriveTypeW(root)
        if t not in (2, 3, 4):
            continue
        name = ctypes.create_unicode_buffer(261)
        fs = ctypes.create_unicode_buffer(261)
        k.GetVolumeInformationW(root, name, 261, None, None, None, fs, 261)
        try:
            u = shutil.disk_usage(root)
        except OSError:
            continue
        bus = ""
        res.append({"root": root, "label": name.value or "", "type": {2: "Amovible", 3: "Fixe", 4: "Réseau"}[t],
                    "free": u.free, "total": u.total, "removable": t == 2, "fs": fs.value, "bus": bus})
    # disques USB vus comme « fixes » (disques durs externes)
    try:
        out = run(ps_cmd("Get-Disk | Where-Object BusType -eq 'USB' | Get-Partition | Where-Object DriveLetter | "
                         "ForEach-Object { $_.DriveLetter }"), timeout=20)
        usb = {f"{c.strip()}:\\" for c in out.split() if c.strip()}
        for d in res:
            if d["root"] in usb:
                d["removable"] = True
                d["type"] = "USB"
    except Exception:
        pass
    return res


def profiles():
    base = os.path.join(os.environ.get("SystemDrive", "C:") + "\\", "Users") if IS_WIN else "/home"
    me = getpass.getuser().lower()
    res = []
    try:
        for e in os.scandir(base):
            if e.is_dir() and e.name.lower() not in SKIP_PROFILES and not e.name.startswith((".", "$")):
                if os.path.isdir(os.path.join(e.path, "AppData")) or not IS_WIN:
                    res.append({"name": e.name, "path": e.path, "me": e.name.lower() == me})
    except OSError:
        pass
    res.sort(key=lambda p: (not p["me"], p["name"].lower()))
    return res


def known_folders(profile_path):
    """Chemins réels des dossiers utilisateur (redirections OneDrive comprises)."""
    out = {}
    me = os.path.normcase(os.path.expanduser("~")) == os.path.normcase(profile_path)
    if IS_WIN and me:
        txt = run(ps_cmd(
            "$d=@{};foreach($k in 'Desktop','MyDocuments','MyPictures','MyVideos','MyMusic'){$d[$k]=[Environment]::GetFolderPath($k)};"
            "$d['Downloads']=(Get-ItemProperty 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders' "
            "-Name '{374DE290-123F-4565-9164-39C4925E467B}' -ErrorAction SilentlyContinue).'{374DE290-123F-4565-9164-39C4925E467B}';"
            "$d | ConvertTo-Json -Compress"), timeout=30)
        try:
            d = json.loads(txt[txt.index("{"):])
            for k, v in d.items():
                if v:
                    out[k] = os.path.expandvars(v)
        except Exception:
            pass
    defaults = {"Desktop": ["Desktop", "Bureau"], "MyDocuments": ["Documents"], "MyPictures": ["Pictures", "Images"],
                "MyVideos": ["Videos", "Vidéos"], "MyMusic": ["Music", "Musique"], "Downloads": ["Downloads", "Téléchargements"]}
    od = [e.path for e in os.scandir(profile_path) if e.is_dir() and e.name.lower().startswith("onedrive")] if os.path.isdir(profile_path) else []
    for k, names in defaults.items():
        if out.get(k) and os.path.isdir(out[k]):
            continue
        for root in od + [profile_path]:
            hit = next((os.path.join(root, n) for n in names if os.path.isdir(os.path.join(root, n))), None)
            if hit and (root == profile_path or len(os.listdir(hit)) > 0):
                out[k] = hit
                break
        out.setdefault(k, os.path.join(profile_path, names[0]))
    return out


def dir_size(path, stop=None):
    """(octets, fichiers) en ignorant les fichiers OneDrive « en ligne uniquement » et les jonctions."""
    total = files = 0
    stack = [path]
    while stack:
        if stop and stop():
            break
        p = stack.pop()
        try:
            with os.scandir(p) as it:
                for e in it:
                    try:
                        if e.is_symlink():
                            continue
                        if e.is_dir(follow_symlinks=False):
                            if IS_WIN and e.stat(follow_symlinks=False).st_file_attributes & 0x400:  # point de réanalyse
                                continue
                            stack.append(e.path)
                        else:
                            st = e.stat(follow_symlinks=False)
                            if IS_WIN and st.st_file_attributes & (0x1000 | 0x400000):  # OFFLINE / RECALL_ON_DATA_ACCESS
                                continue
                            total += st.st_size
                            files += 1
                    except OSError:
                        continue
        except OSError:
            continue
    return total, files


# --------------------------------------------------------------------------- #
# Favoris -> HTML (format Netscape, importable dans tous les navigateurs)
# --------------------------------------------------------------------------- #
def _nets(title, tree):
    def walk(nodes, ind):
        o = []
        for n in nodes:
            if n.get("url"):
                o.append(f'{ind}<DT><A HREF="{html.escape(n["url"], True)}">{html.escape(n.get("title") or n["url"])}</A>')
            elif n.get("children") is not None:
                o.append(f'{ind}<DT><H3>{html.escape(n.get("title") or "Dossier")}</H3>')
                o.append(f"{ind}<DL><p>")
                o += walk(n["children"], ind + "    ")
                o.append(f"{ind}</DL><p>")
        return o
    return ("<!DOCTYPE NETSCAPE-Bookmark-file-1>\n<META HTTP-EQUIV=\"Content-Type\" CONTENT=\"text/html; charset=UTF-8\">\n"
            f"<TITLE>{html.escape(title)}</TITLE>\n<H1>{html.escape(title)}</H1>\n<DL><p>\n" + "\n".join(walk(tree, "    ")) + "\n</DL><p>\n")


def chromium_bookmarks(path):
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)

    def conv(n):
        if n.get("type") == "url":
            return {"title": n.get("name"), "url": n.get("url")}
        return {"title": n.get("name"), "children": [conv(c) for c in n.get("children", [])]}
    roots = data.get("roots", {})
    tree, count = [], 0
    for key, label in (("bookmark_bar", "Barre de favoris"), ("other", "Autres favoris"), ("synced", "Favoris mobiles")):
        r = roots.get(key)
        if r and r.get("children"):
            tree.append({"title": label, "children": [conv(c) for c in r["children"]]})
    count = json.dumps(tree).count('"url"')
    return tree, count


def firefox_bookmarks(places):
    tmp = tempfile.mkdtemp(prefix="ea2ff_")
    try:
        dst = os.path.join(tmp, "places.sqlite")
        shutil.copy2(places, dst)
        for ext in ("-wal", "-shm"):
            if os.path.exists(places + ext):
                shutil.copy2(places + ext, dst + ext)
        con = sqlite3.connect(dst)
        rows = con.execute("SELECT b.id, b.type, b.parent, b.position, b.title, p.url, b.guid FROM moz_bookmarks b "
                           "LEFT JOIN moz_places p ON b.fk = p.id ORDER BY b.parent, b.position").fetchall()
        con.close()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    kids = {}
    for r in rows:
        kids.setdefault(r[2], []).append(r)
    labels = {"toolbar_____": "Barre personnelle", "menu________": "Menu des marque-pages", "unfiled_____": "Autres marque-pages",
              "mobile______": "Marque-pages mobiles"}

    def build(pid):
        out = []
        for r in kids.get(pid, []):
            if r[1] == 1 and r[5] and not r[5].startswith("place:"):
                out.append({"title": r[4] or r[5], "url": r[5]})
            elif r[1] == 2:
                out.append({"title": r[4], "children": build(r[0])})
        return out
    tree = []
    for r in kids.get(1, []):
        if r[6] in labels:
            ch = build(r[0])
            if ch:
                tree.append({"title": labels[r[6]], "children": ch})
    return tree, json.dumps(tree).count('"url"')


def find_bookmarks(profile_path):
    local = os.path.join(profile_path, "AppData", "Local")
    roaming = os.path.join(profile_path, "AppData", "Roaming")
    found = []
    for name, rel in BROWSERS:
        base = os.path.join(local, rel)
        if os.path.isdir(base):
            for e in os.scandir(base):
                bm = os.path.join(e.path, "Bookmarks")
                if e.is_dir() and (e.name == "Default" or e.name.startswith("Profile")) and os.path.isfile(bm):
                    found.append({"browser": name, "profile": e.name, "path": bm, "kind": "chromium"})
    ffp = os.path.join(roaming, "Mozilla", "Firefox", "Profiles")
    if os.path.isdir(ffp):
        for e in os.scandir(ffp):
            pl = os.path.join(e.path, "places.sqlite")
            if e.is_dir() and os.path.isfile(pl):
                found.append({"browser": "Firefox", "profile": e.name, "path": pl, "kind": "firefox"})
    return found


def find_pst(profile_path, kf):
    res = []
    for root in (os.path.join(kf.get("MyDocuments", ""), "Fichiers Outlook"), os.path.join(kf.get("MyDocuments", ""), "Outlook Files"),
                 os.path.join(profile_path, "AppData", "Local", "Microsoft", "Outlook")):
        if os.path.isdir(root):
            for e in os.scandir(root):
                if e.is_file() and e.name.lower().endswith(".pst"):
                    res.append(e.path)
    return sorted(set(res))


def safe_name(s):
    return re.sub(r'[<>:"/\\|?*]+', "_", s).strip(" .") or "x"


# --------------------------------------------------------------------------- #
# Pont
# --------------------------------------------------------------------------- #
class MigBridge(BridgeBase):
    def __init__(self, args):
        super().__init__()
        self._args = args
        self._busy = False
        self._cancel = False
        self._runner = None
        self._sizes = {}
        self._size_gen = 0
        self._result = None

    def info(self):
        return {"host": socket.gethostname(), "user": getpass.getuser(), "admin": is_admin(), "win": IS_WIN,
                "profiles": profiles(), "drives": drives(), "extras": [{"key": k, "label": l, "desc": d, "def": df} for k, l, d, df in EXTRAS],
                "folders": [{"key": k, "label": l, "def": df} for k, l, _, _, df in FOLDERS]}

    def ready(self):
        if getattr(self._args, "fulltest", ""):
            threading.Thread(target=self._fulltest, daemon=True).start()
        elif self._args.selftest:
            threading.Thread(target=self._selftest, daemon=True).start()
        return True

    def list_drives(self):
        return drives()

    def pick(self):
        return self.pick_folder()

    # ---- analyse d'un profil -------------------------------------------------- #
    def analyse(self, profile_path, custom=None):
        kf = known_folders(profile_path)
        items = []
        for key, label, known, _, df in FOLDERS:
            p = kf.get(known, "")
            od = "onedrive" in p.lower()
            items.append({"key": key, "label": label, "kind": "folder", "path": p, "exists": os.path.isdir(p), "def": df and not od,
                          "onedrive": od, "detail": p})
        for i, c in enumerate(custom or []):
            items.append({"key": f"custom{i}", "label": os.path.basename(c.rstrip("\\/")) or c, "kind": "folder", "path": c,
                          "exists": os.path.isdir(c), "def": True, "onedrive": "onedrive" in c.lower(), "detail": c, "custom": True})
        bms = find_bookmarks(profile_path)
        sig = os.path.join(profile_path, "AppData", "Roaming", "Microsoft", "Signatures")
        pst = find_pst(profile_path, kf)
        for key, label, desc, df in EXTRAS:
            it = {"key": key, "label": label, "kind": key, "detail": desc, "def": df, "exists": True}
            if key == "bookmarks":
                it["detail"] = ", ".join(sorted({f"{b['browser']}" for b in bms})) or "Aucun navigateur détecté"
                it["exists"] = bool(bms)
            elif key == "signatures":
                it["exists"] = os.path.isdir(sig) and any(os.scandir(sig))
                it["path"] = sig
                if not it["exists"]:
                    it["detail"] = "Aucune signature"
            elif key == "pst":
                it["exists"] = bool(pst)
                it["files"] = pst
                it["detail"] = (f"{len(pst)} fichier(s) : " + ", ".join(os.path.basename(p) for p in pst[:4])) if pst else "Aucun fichier .pst"
            elif key in ("wifi", "printers", "netdrives", "software") and not IS_WIN:
                it["exists"] = False
            it["def"] = it["def"] and it["exists"]
            items.append(it)
        self._size_gen += 1
        gen = self._size_gen
        threading.Thread(target=self._sizes_bg, args=(gen, items), daemon=True).start()
        return {"items": items, "profile": profile_path}

    def _sizes_bg(self, gen, items):
        for it in items:
            if gen != self._size_gen:
                return
            if it["kind"] == "folder" and it["exists"]:
                b, n = dir_size(it["path"], stop=lambda: gen != self._size_gen)
            elif it["kind"] == "pst":
                b, n = sum(os.path.getsize(p) for p in it.get("files", []) if os.path.exists(p)), len(it.get("files", []))
            elif it["kind"] == "signatures" and it["exists"]:
                b, n = dir_size(it["path"])
            else:
                continue
            self._sizes[it["key"]] = b
            self._js("size", {"key": it["key"], "bytes": b, "files": n, "h": human(b)})
        self._js("sizesDone", {})

    def free_space(self, path):
        try:
            p = path
            while p and not os.path.exists(p):
                p = os.path.dirname(p.rstrip("\\/"))
            u = shutil.disk_usage(p or path)
            return {"free": u.free, "h": human(u.free)}
        except Exception as e:
            return {"free": None, "error": str(e)}

    # ---- sauvegarde ------------------------------------------------------------ #
    def backup_start(self, profile_path, items, dest):
        if self._busy:
            return {"error": "Une opération est déjà en cours."}
        if not dest or not os.path.isdir(dest):
            return {"error": "Choisis un dossier de destination existant (clé USB, disque externe, partage réseau)."}
        nd = os.path.normcase(os.path.abspath(dest))
        for it in items:
            if it.get("kind") == "folder" and it.get("path"):
                src = os.path.normcase(os.path.abspath(it["path"]))
                if nd == src or nd.startswith(src + os.sep):
                    return {"error": f"La destination est à l'intérieur du dossier sauvegardé « {it['label']} »."}
        stamp = dt.datetime.now().strftime("%Y-%m-%d_%Hh%M")
        user = os.path.basename(profile_path.rstrip("\\/"))
        root = os.path.join(dest, ROOT_DIR, safe_name(f"{socket.gethostname()}_{user}_{stamp}"))
        self._busy, self._cancel = True, False
        threading.Thread(target=self._backup, args=(profile_path, items, root), daemon=True).start()
        return {"ok": True, "root": root}

    def cancel(self):
        self._cancel = True
        if self._runner:
            self._runner.cancel()
        return True

    def _emit(self, lines):
        self._js("log", {"lines": lines})

    def _robocopy(self, r, src, dst, total, done0, label, restore=False):
        """Copie src -> dst avec suivi des octets. Renvoie (ok, octets copiés, erreurs)."""
        os.makedirs(dst, exist_ok=True)
        cmd = ["robocopy", src, dst, "/E", "/COPY:DAT", "/DCOPY:T", "/R:1", "/W:1", "/XJ", "/MT:8", "/BYTES", "/NDL", "/NJH",
               "/NJS", "/NP", "/FP", "/XF", "desktop.ini", "thumbs.db", "~$*", "*.tmp"]
        cmd += ["/XO"] if restore else ["/XA:O"]
        state = {"bytes": 0, "files": 0, "err": 0, "t": time.time()}
        orig = r.line
        rx = re.compile(r"\t\s*(\d+)\t(.+)$")

        def filt(text, kind="out"):
            if kind == "cmd":
                return orig(text, kind)
            m = rx.search(text)
            if m:
                state["bytes"] += int(m.group(1))
                state["files"] += 1
                if time.time() - state["t"] > 0.4:
                    state["t"] = time.time()
                    self._js("prog", {"label": label, "done": done0 + state["bytes"], "total": total, "files": state["files"]})
                return
            if re.search(r"\b(ERREUR|ERROR)\b", text):
                state["err"] += 1
                if state["err"] <= 40:
                    orig(text.strip(), "err")
                return
            if re.search(r"(?i)(nouveau dossier|new dir|extra|^\s*$)", text):
                return
            if text.strip() and len(text.strip()) < 200 and not re.match(r"^\s*\d+%", text):
                orig(text.strip(), "prog" if kind == "prog" else "out")
        r.line = filt
        try:
            code = r.stream(cmd)
        finally:
            r.line = orig
        self._js("prog", {"label": label, "done": done0 + state["bytes"], "total": total, "files": state["files"]})
        return (code is not None and code < 8), state["bytes"], state["err"], state["files"]

    def _backup(self, profile_path, items, root):
        t0 = time.time()
        r = LiveRunner(self._emit)
        self._runner = r
        r.start_flusher()
        manifest = {"app": APP, "version": VERSION, "date": dt.datetime.now().isoformat(timespec="seconds"),
                    "pc": socket.gethostname(), "user": os.path.basename(profile_path.rstrip("\\/")), "items": {}}
        total = sum(self._sizes.get(it["key"], 0) for it in items)
        done = 0
        status = "ok"
        try:
            os.makedirs(root, exist_ok=True)
            r.line(f"Sauvegarde vers {root}", "hd")
            for it in items:
                if self._cancel:
                    break
                key, kind = it["key"], it["kind"]
                self._js("item", {"key": key, "st": "run"})
                st, msg, rec = "ok", "", {"label": it["label"], "kind": kind}
                try:
                    if kind == "folder":
                        name = "Fichiers/" + (next((f[3] for f in FOLDERS if f[0] == key), None) or safe_name(it["label"]))
                        r.line(f"> {it['label']} : {it['path']}", "cmd")
                        ok, b, err, n = self._robocopy(r, it["path"], os.path.join(root, name), total, done, it["label"])
                        done += b
                        rec.update(dst=name, src=it["path"], bytes=b, files=n, custom=bool(it.get("custom")))
                        msg = f"{n} fichier(s), {human(b)}" + (f", {err} erreur(s)" if err else "")
                        st = "ok" if ok and not err else ("warn" if ok else "err")
                    elif kind == "pst":
                        r.line("> Fichiers Outlook (.pst)", "cmd")
                        dst = os.path.join(root, "Outlook", "PST")
                        os.makedirs(dst, exist_ok=True)
                        n = b = 0
                        for p in it.get("files", []):
                            ok, bb, err, nn = self._robocopy_file(r, p, dst, total, done, it["label"])
                            done += bb
                            b += bb
                            n += 1 if ok else 0
                            if not ok:
                                st = "warn"
                        rec.update(dst="Outlook/PST", files=n, bytes=b, names=[os.path.basename(p) for p in it.get("files", [])])
                        msg = f"{n} fichier(s), {human(b)}" + (" (Outlook ouvert ? fichier verrouillé)" if st == "warn" else "")
                    elif kind == "signatures":
                        r.line("> Signatures Outlook", "cmd")
                        dst = os.path.join(root, "Outlook", "Signatures")
                        shutil.copytree(it["path"], dst, dirs_exist_ok=True)
                        n = sum(len(f) for _, _, f in os.walk(dst))
                        rec.update(dst="Outlook/Signatures", files=n)
                        msg = f"{n} fichier(s)"
                    elif kind == "bookmarks":
                        r.line("> Favoris des navigateurs", "cmd")
                        dst = os.path.join(root, "Navigateurs")
                        os.makedirs(dst, exist_ok=True)
                        out = []
                        for bm in find_bookmarks(profile_path):
                            try:
                                tree, cnt = (chromium_bookmarks(bm["path"]) if bm["kind"] == "chromium" else firefox_bookmarks(bm["path"]))
                                if not cnt:
                                    continue
                                fn = safe_name(f"Favoris_{bm['browser']}_{bm['profile']}.html")
                                with open(os.path.join(dst, fn), "w", encoding="utf-8") as fh:
                                    fh.write(_nets(f"Favoris {bm['browser']} ({manifest['pc']})", tree))
                                if bm["kind"] == "chromium":
                                    shutil.copy2(bm["path"], os.path.join(dst, safe_name(f"{bm['browser']}_{bm['profile']}_Bookmarks.json")))
                                out.append({"file": fn, "browser": bm["browser"], "count": cnt})
                                r.line(f"{bm['browser']} ({bm['profile']}) : {cnt} favori(s)", "out")
                            except Exception as e:
                                r.line(f"{bm['browser']} ({bm['profile']}) : lecture impossible ({e})", "warn")
                                st = "warn"
                        rec.update(dst="Navigateurs", files=out)
                        msg = ", ".join(f"{o['browser']} {o['count']}" for o in out) or "aucun favori"
                    elif kind == "wifi":
                        r.line("> Réseaux Wi-Fi", "cmd")
                        dst = os.path.join(root, "WiFi")
                        os.makedirs(dst, exist_ok=True)
                        cmd = ["netsh", "wlan", "export", "profile", f"folder={dst}"] + (["key=clear"] if is_admin() else [])
                        r.stream(cmd)
                        n = len([f for f in os.listdir(dst) if f.lower().endswith(".xml")])
                        rec.update(dst="WiFi", files=n, keys=is_admin())
                        msg = f"{n} réseau(x)" + ("" if is_admin() else " (sans les clés : droits admin requis)")
                        st = "ok" if n else "warn"
                    elif kind == "printers":
                        r.line("> Imprimantes", "cmd")
                        dst = os.path.join(root, "Imprimantes")
                        os.makedirs(dst, exist_ok=True)
                        txt = run(ps_cmd("Get-Printer | Select-Object Name,DriverName,PortName,Type,Shared,ShareName | ConvertTo-Json -Compress"), timeout=60)
                        try:
                            pl = json.loads(txt[txt.index("["):] if txt.strip().startswith("[") else "[" + txt[txt.index("{"):] + "]")
                        except Exception:
                            pl = []
                        with open(os.path.join(dst, "imprimantes.json"), "w", encoding="utf-8") as fh:
                            json.dump(pl, fh, ensure_ascii=False, indent=1)
                        for p in pl:
                            r.line(f"{p.get('Name')}  [{p.get('DriverName')}]  {p.get('PortName')}", "out")
                        brm = os.path.join(os.environ.get("WINDIR", r"C:\Windows"), "System32", "spool", "tools", "PrintBrm.exe")
                        full = False
                        if is_admin() and os.path.exists(brm):
                            code = r.stream([brm, "-B", "-F", os.path.join(dst, "imprimantes.printerExport"), "-O", "FORCE"])
                            full = code == 0 and os.path.exists(os.path.join(dst, "imprimantes.printerExport"))
                        rec.update(dst="Imprimantes", count=len(pl), full=full)
                        msg = f"{len(pl)} imprimante(s)" + (", pilotes compris" if full else " (liste uniquement)")
                    elif kind == "netdrives":
                        r.line("> Lecteurs réseau", "cmd")
                        txt = run(ps_cmd("Get-ChildItem HKCU:\\Network -ErrorAction SilentlyContinue | ForEach-Object { "
                                         "[pscustomobject]@{Letter=$_.PSChildName; Path=(Get-ItemProperty $_.PSPath).RemotePath} } | ConvertTo-Json -Compress"), timeout=30)
                        try:
                            nd = json.loads(txt) if txt.strip() else []
                            nd = nd if isinstance(nd, list) else [nd]
                        except Exception:
                            nd = []
                        with open(os.path.join(root, "lecteurs_reseau.json"), "w", encoding="utf-8") as fh:
                            json.dump(nd, fh, ensure_ascii=False, indent=1)
                        for d in nd:
                            r.line(f"{d.get('Letter')}: -> {d.get('Path')}", "out")
                        rec.update(dst="lecteurs_reseau.json", count=len(nd))
                        msg = f"{len(nd)} lecteur(s)"
                    elif kind == "wallpaper":
                        r.line("> Fond d'écran", "cmd")
                        cand = os.path.join(profile_path, "AppData", "Roaming", "Microsoft", "Windows", "Themes", "TranscodedWallpaper")
                        if os.path.isfile(cand):
                            shutil.copy2(cand, os.path.join(root, "Fond_ecran.jpg"))
                            rec.update(dst="Fond_ecran.jpg")
                            msg = "copié"
                        else:
                            st, msg = "warn", "aucun fond d'écran personnalisé"
                    elif kind == "software":
                        r.line("> Liste des logiciels", "cmd")
                        dst = os.path.join(root, "Logiciels")
                        os.makedirs(dst, exist_ok=True)
                        lst = run(ps_cmd(
                            "$k='HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*','HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',"
                            "'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*';Get-ItemProperty $k -ErrorAction SilentlyContinue | "
                            "Where-Object { $_.DisplayName -and $_.SystemComponent -ne 1 } | Sort-Object DisplayName -Unique | "
                            "ForEach-Object { $_.DisplayName + ' | ' + $_.DisplayVersion + ' | ' + $_.Publisher }"), timeout=60)
                        names = [l for l in lst.splitlines() if l.strip()]
                        with open(os.path.join(dst, "logiciels_installes.txt"), "w", encoding="utf-8") as fh:
                            fh.write("Logiciels installés sur " + manifest["pc"] + "\n\n" + "\n".join(names))
                        wg = shutil.which("winget") or os.path.join(os.environ.get("LOCALAPPDATA", ""), "Microsoft", "WindowsApps", "winget.exe")
                        nwg = 0
                        if os.path.exists(wg):
                            run([wg, "export", "-o", os.path.join(dst, "winget.json"), "--accept-source-agreements", "--disable-interactivity"], timeout=240)
                            try:
                                with open(os.path.join(dst, "winget.json"), encoding="utf-8-sig") as fh:
                                    nwg = sum(len(s.get("Packages", [])) for s in json.load(fh).get("Sources", []))
                            except Exception:
                                nwg = 0
                        rec.update(dst="Logiciels", count=len(names), winget=nwg)
                        msg = f"{len(names)} logiciel(s), dont {nwg} réinstallable(s) avec winget"
                        r.line(msg, "out")
                except Exception as e:
                    st, msg = "err", f"{type(e).__name__}: {e}"
                    r.line(f"Erreur : {msg}", "err")
                if r.cancelled or self._cancel:
                    st, msg = "stopped", "arrêté"
                rec.update(status=st, msg=msg)
                manifest["items"][key] = rec
                if st in ("err", "warn") and status == "ok":
                    status = "warn"
                self._js("item", {"key": key, "st": st, "msg": msg})
                with open(os.path.join(root, "manifest.json"), "w", encoding="utf-8") as fh:
                    json.dump(manifest, fh, ensure_ascii=False, indent=1)
            if self._cancel:
                status = "stopped"
            self._write_report(root, manifest)
            dur = time.time() - t0
            r.line(f"Sauvegarde terminée en {int(dur // 60)} min {int(dur % 60)} s : {root}", "ok" if status == "ok" else "warn")
        except Exception as e:
            status = "err"
            r.line(f"Erreur : {type(e).__name__}: {e}", "err")
        finally:
            r.stop_flusher()
            self._runner = None
            self._busy = False
            self._result = {"status": status, "root": root, "manifest": manifest}
            self._js("done", {"mode": "backup", "status": status, "root": root})

    def _robocopy_file(self, r, path, dst_dir, total, done0, label):
        return self._robocopy_single(r, os.path.dirname(path), dst_dir, os.path.basename(path), total, done0, label)

    def _robocopy_single(self, r, src_dir, dst_dir, name, total, done0, label):
        cmd = ["robocopy", src_dir, dst_dir, name, "/COPY:DAT", "/R:1", "/W:1", "/BYTES", "/NDL", "/NJH", "/NJS", "/NP", "/FP"]
        before = os.path.getsize(os.path.join(src_dir, name)) if os.path.exists(os.path.join(src_dir, name)) else 0
        code = r.stream(cmd)
        ok = code is not None and code < 8 and os.path.exists(os.path.join(dst_dir, name))
        self._js("prog", {"label": label, "done": done0 + (before if ok else 0), "total": total, "files": 1})
        return ok, before if ok else 0, 0 if ok else 1, 1 if ok else 0

    def _write_report(self, root, m):
        lines = [f"{APP} - sauvegarde du {m['date'].replace('T', ' à ')}", f"Poste : {m['pc']}   Utilisateur : {m['user']}", ""]
        for k, it in m["items"].items():
            lines.append(f"[{ {'ok': 'OK', 'warn': 'ATTENTION', 'err': 'ÉCHEC', 'stopped': 'ARRÊTÉ'}.get(it.get('status'), '?') }] "
                         f"{it['label']} : {it.get('msg', '')}")
        lines += ["", "Restauration : lancer E-A2 Migration sur le nouveau PC, onglet Restaurer, puis choisir ce dossier.",
                  "Les profils Wi-Fi peuvent contenir les clés en clair : effacer cette sauvegarde après la migration."]
        with open(os.path.join(root, "Rapport de sauvegarde.txt"), "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines))

    # ---- restauration ---------------------------------------------------------- #
    def find_backups(self):
        res = []
        for d in drives():
            base = os.path.join(d["root"], ROOT_DIR)
            if os.path.isdir(base):
                for e in os.scandir(base):
                    mf = os.path.join(e.path, "manifest.json")
                    if os.path.isfile(mf):
                        try:
                            with open(mf, encoding="utf-8") as fh:
                                m = json.load(fh)
                            res.append({"path": e.path, "pc": m.get("pc"), "user": m.get("user"), "date": m.get("date"), "drive": d["root"]})
                        except Exception:
                            pass
        res.sort(key=lambda x: x.get("date") or "", reverse=True)
        return res

    def load_backup(self, path):
        mf = os.path.join(path, "manifest.json")
        if not os.path.isfile(mf):
            sub = os.path.join(path, ROOT_DIR)
            return {"error": "Ce dossier n'est pas une sauvegarde E-A2 Migration (manifest.json absent)."
                             + (" Choisir un sous-dossier de " + ROOT_DIR + "." if os.path.isdir(sub) else "")}
        with open(mf, encoding="utf-8") as fh:
            m = json.load(fh)
        kf = known_folders(os.path.expanduser("~"))
        items = []
        for k, it in m.get("items", {}).items():
            if it.get("status") in ("err", "stopped") and it.get("kind") != "folder":
                continue
            tgt = ""
            if it["kind"] == "folder":
                known = next((f[2] for f in FOLDERS if f[0] == k), None)
                tgt = kf.get(known) if known else it.get("src", "")
            items.append({"key": k, "label": it["label"], "kind": it["kind"], "msg": it.get("msg", ""), "target": tgt or "",
                          "bytes": it.get("bytes", 0), "status": it.get("status")})
        return {"path": path, "manifest": {k: m.get(k) for k in ("pc", "user", "date", "version")}, "items": items}

    def restore_start(self, path, keys, alt_root=""):
        if self._busy:
            return {"error": "Une opération est déjà en cours."}
        self._busy, self._cancel = True, False
        threading.Thread(target=self._restore, args=(path, keys, alt_root), daemon=True).start()
        return {"ok": True}

    def _restore(self, path, keys, alt_root):
        t0 = time.time()
        r = LiveRunner(self._emit)
        self._runner = r
        r.start_flusher()
        status = "ok"
        notes = []
        try:
            with open(os.path.join(path, "manifest.json"), encoding="utf-8") as fh:
                m = json.load(fh)
            kf = known_folders(os.path.expanduser("~"))
            desk = alt_root or kf.get("Desktop") or os.path.join(os.path.expanduser("~"), "Desktop")
            total = sum(m["items"][k].get("bytes", 0) for k in keys if k in m["items"])
            done = 0
            r.line(f"Restauration depuis {path}", "hd")
            for k in keys:
                if self._cancel:
                    break
                it = m["items"].get(k)
                if not it:
                    continue
                kind = it["kind"]
                self._js("item", {"key": k, "st": "run"})
                st, msg = "ok", ""
                try:
                    if kind == "folder":
                        src = os.path.join(path, it["dst"])
                        if alt_root:
                            tgt = os.path.join(alt_root, safe_name(it["label"]))
                        else:
                            known = next((f[2] for f in FOLDERS if f[0] == k), None)
                            tgt = kf.get(known) if known else it.get("src")
                        r.line(f"> {it['label']} -> {tgt}", "cmd")
                        ok, b, err, n = self._robocopy(r, src, tgt, total, done, it["label"], restore=True)
                        done += b
                        msg = f"{n} fichier(s) restauré(s), {human(b)}" + (f", {err} erreur(s)" if err else "")
                        st = "ok" if ok and not err else ("warn" if ok else "err")
                    elif kind == "pst":
                        dst = os.path.join(alt_root or kf.get("MyDocuments", os.path.expanduser("~")), "Fichiers Outlook")
                        r.line(f"> Fichiers .pst -> {dst}", "cmd")
                        os.makedirs(dst, exist_ok=True)
                        n = 0
                        for name in it.get("names", []):
                            s = os.path.join(path, "Outlook", "PST", name)
                            if os.path.exists(s) and not os.path.exists(os.path.join(dst, name)):
                                ok, b, _, _ = self._robocopy_single(r, os.path.dirname(s), dst, name, total, done, it["label"])
                                done += b
                                n += 1 if ok else 0
                        msg = f"{n} fichier(s) copié(s) dans {dst}"
                        notes.append("Outlook : Fichier > Ouvrir et exporter > Ouvrir un fichier de données Outlook, puis choisir les .pst du dossier « Fichiers Outlook ».")
                    elif kind == "signatures":
                        dst = os.path.join(alt_root, "Signatures") if alt_root else os.path.join(os.environ.get("APPDATA", ""), "Microsoft", "Signatures")
                        r.line(f"> Signatures -> {dst}", "cmd")
                        shutil.copytree(os.path.join(path, "Outlook", "Signatures"), dst, dirs_exist_ok=True)
                        msg = "copiées (à choisir dans Outlook > Signatures)"
                    elif kind == "bookmarks":
                        dst = os.path.join(desk, "Favoris migrés")
                        os.makedirs(dst, exist_ok=True)
                        n = 0
                        for f in it.get("files", []):
                            s = os.path.join(path, "Navigateurs", f["file"])
                            if os.path.exists(s):
                                shutil.copy2(s, os.path.join(dst, f["file"]))
                                n += 1
                                r.line(f"{f['file']} ({f['count']} favoris)", "out")
                        msg = f"{n} fichier(s) dans « Favoris migrés » sur le Bureau"
                        notes.append("Favoris : dans le navigateur, Paramètres > Importer des favoris > Fichier HTML, puis choisir le fichier "
                                     "du dossier « Favoris migrés » du Bureau.")
                    elif kind == "wifi" and not alt_root:
                        src = os.path.join(path, "WiFi")
                        n = 0
                        for f in sorted(os.listdir(src)):
                            if f.lower().endswith(".xml"):
                                code = r.stream(["netsh", "wlan", "add", "profile", f"filename={os.path.join(src, f)}", "user=all"])
                                n += 1 if code == 0 else 0
                        msg = f"{n} réseau(x) Wi-Fi ajouté(s)"
                        st = "ok" if n else "warn"
                    elif kind == "printers" and not alt_root:
                        exp = os.path.join(path, "Imprimantes", "imprimantes.printerExport")
                        brm = os.path.join(os.environ.get("WINDIR", r"C:\Windows"), "System32", "spool", "tools", "PrintBrm.exe")
                        if os.path.exists(exp) and os.path.exists(brm):
                            code = r.stream([brm, "-R", "-F", exp, "-O", "FORCE"])
                            msg = "imprimantes et pilotes restaurés" if code == 0 else f"PrintBrm code {code}"
                            st = "ok" if code == 0 else "warn"
                        with open(os.path.join(path, "Imprimantes", "imprimantes.json"), encoding="utf-8") as fh:
                            pl = json.load(fh)
                        conns = [p for p in pl if str(p.get("Type")) in ("1", "Connection") and str(p.get("Name", "")).startswith("\\\\")]
                        for p in conns:
                            code = r.stream(ps_cmd(f"Add-Printer -ConnectionName '{p['Name']}' -ErrorAction Stop; 'Connectée : {p['Name']}'"))
                            if code:
                                st = "warn"
                        if not msg:
                            msg = f"{len(conns)} imprimante(s) réseau reconnectée(s) ; imprimantes locales : voir la liste dans la sauvegarde"
                            notes.append("Imprimantes locales : la liste (nom, pilote, port) est dans le dossier Imprimantes de la sauvegarde.")
                    elif kind == "netdrives" and not alt_root:
                        with open(os.path.join(path, "lecteurs_reseau.json"), encoding="utf-8") as fh:
                            nd = json.load(fh)
                        n = 0
                        for d in nd:
                            code = r.stream(["net", "use", f"{d['Letter']}:", d["Path"], "/persistent:yes"])
                            n += 1 if code == 0 else 0
                        msg = f"{n} / {len(nd)} lecteur(s) reconnecté(s)"
                        st = "ok" if n == len(nd) else "warn"
                        if n < len(nd):
                            notes.append("Lecteurs réseau : certains demandent un identifiant ; les reconnecter depuis l'Explorateur (Ce PC > Connecter un lecteur réseau).")
                    elif kind == "wallpaper" and not alt_root:
                        pic = os.path.join(kf.get("MyPictures", os.path.expanduser("~")), "Fond_ecran_migre.jpg")
                        shutil.copy2(os.path.join(path, "Fond_ecran.jpg"), pic)
                        if IS_WIN:
                            import ctypes
                            ctypes.windll.user32.SystemParametersInfoW(20, 0, pic, 3)
                        msg = "appliqué"
                    elif kind == "software" and not alt_root:
                        wj = os.path.join(path, "Logiciels", "winget.json")
                        wg = shutil.which("winget") or os.path.join(os.environ.get("LOCALAPPDATA", ""), "Microsoft", "WindowsApps", "winget.exe")
                        if os.path.exists(wj) and os.path.exists(wg):
                            r.line("> winget import (réinstallation des logiciels)", "cmd")
                            code = r.stream([wg, "import", "-i", wj, "--accept-package-agreements", "--accept-source-agreements",
                                             "--ignore-unavailable", "--ignore-versions", "--disable-interactivity"])
                            msg = "réinstallation terminée" if code == 0 else "terminé avec des erreurs (voir le journal)"
                            st = "ok" if code == 0 else "warn"
                        else:
                            st, msg = "warn", "winget indisponible : voir la liste logiciels_installes.txt"
                    else:
                        st, msg = "skip", "ignoré"
                except Exception as e:
                    st, msg = "err", f"{type(e).__name__}: {e}"
                    r.line(f"Erreur : {msg}", "err")
                if self._cancel:
                    st, msg = "stopped", "arrêté"
                if st in ("err", "warn") and status == "ok":
                    status = "warn"
                self._js("item", {"key": k, "st": st, "msg": msg})
            if self._cancel:
                status = "stopped"
            dur = time.time() - t0
            r.line(f"Restauration terminée en {int(dur // 60)} min {int(dur % 60)} s.", "ok" if status == "ok" else "warn")
        except Exception as e:
            status = "err"
            r.line(f"Erreur : {type(e).__name__}: {e}", "err")
        finally:
            r.stop_flusher()
            self._runner = None
            self._busy = False
            self._result = {"status": status, "notes": notes}
            self._js("done", {"mode": "restore", "status": status, "notes": notes})

    # ---- autotest (sauvegarde + restauration dans des dossiers temporaires) ----- #
    def _fulltest(self):
        import ea2_migration_tests
        ea2_migration_tests.run_full(self)

    def _selftest(self):
        log = []
        tmp = tempfile.mkdtemp(prefix="ea2mig_test_")
        try:
            time.sleep(2)
            src = os.path.join(tmp, "Source Données éèà")
            for i in range(25):
                d = os.path.join(src, f"Dossier {i % 4}", "Sous-dossier")
                os.makedirs(d, exist_ok=True)
                with open(os.path.join(d, f"fichier_{i}_été.txt"), "w", encoding="utf-8") as fh:
                    fh.write(("Ligne de test E-A2 Migration %d\n" % i) * (200 * (i + 1)))
            with open(os.path.join(src, "gros.bin"), "wb") as fh:
                fh.write(os.urandom(6 * 1024 * 1024))
            dest = os.path.join(tmp, "Cle USB")
            os.makedirs(dest)
            info = self.info()
            log.append(f"profils={[p['name'] for p in info['profiles']]} lecteurs={[(d['root'], d['type'], d['label']) for d in info['drives']]}")
            me = next((p for p in info["profiles"] if p["me"]), info["profiles"][0])
            a = self.analyse(me["path"], [src])
            log.append("analyse: " + " | ".join(f"{i['key']}:{'oui' if i['exists'] else 'non'}{' OneDrive' if i.get('onedrive') else ''}" for i in a["items"]))
            log.append("dossiers: " + " | ".join(f"{i['key']}={i.get('path','')}" for i in a["items"] if i["kind"] == "folder"))
            for _ in range(120):
                if "custom0" in self._sizes:
                    break
                time.sleep(0.5)
            self._eval("window.__seen=1")
            time.sleep(3)
            sel = [i for i in a["items"] if i["key"] in ("custom0", "bookmarks", "signatures", "wifi", "printers", "netdrives", "wallpaper", "software") and i["exists"]]
            log.append(f"taille source test={self._sizes.get('custom0')} ; éléments testés={[i['key'] for i in sel]}")
            res = self.backup_start(me["path"], sel, dest)
            log.append(f"backup_start={res}")
            for _ in range(600):
                time.sleep(0.5)
                if not self._busy:
                    break
            bk = self._result
            log.append(f"sauvegarde: statut={bk['status']}")
            for k, it in bk["manifest"]["items"].items():
                log.append(f"   {k}: {it.get('status')} - {it.get('msg')}")
            root = bk["root"]
            tree = []
            for dp, dn, fn in os.walk(root):
                rel = os.path.relpath(dp, root)
                if rel.count(os.sep) < 2:
                    tree.append(f"{rel} ({len(fn)} fichiers)")
            log.append("arborescence: " + " ; ".join(tree[:20]))
            fb = self.find_backups()
            lb = self.load_backup(root)
            log.append(f"load_backup: {lb.get('manifest')} éléments={[i['key'] for i in lb.get('items', [])]}")
            alt = os.path.join(tmp, "Restauration")
            os.makedirs(alt)
            self.restore_start(root, ["custom0", "bookmarks", "signatures"], alt)
            for _ in range(300):
                time.sleep(0.5)
                if not self._busy:
                    break
            log.append(f"restauration: {self._result}")
            restored = os.path.join(alt, safe_name(os.path.basename(src)))
            a1, a2 = dir_size(src), dir_size(restored)
            log.append(f"vérification: source={a1} restauré={a2} identique={a1 == a2}")
            import hashlib

            def h(p):
                return hashlib.md5(open(p, "rb").read()).hexdigest()
            log.append(f"hash gros.bin identique={h(os.path.join(src, 'gros.bin')) == h(os.path.join(restored, 'gros.bin'))}")
            log.append("ui: items_sauvegarde=" + str(self._eval("document.querySelectorAll('#bkL .rowc').length")) +
                       " journal=" + repr((self._eval("document.getElementById('jb').innerText") or "")[:400]))
            log.append("openSans=" + str(self._eval("document.fonts.check(\"600 16px 'Open Sans'\")")))
        except Exception as e:
            import traceback
            log.append("FAIL " + traceback.format_exc())
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
            log.append(f"nettoyage dossier test: {'OK' if not os.path.exists(tmp) else 'reste'}")
        try:
            with open(self._args.selftest, "w", encoding="utf-8") as fh:
                fh.write("\n".join(str(x) for x in log))
        finally:
            self._window.destroy()


# --------------------------------------------------------------------------- #
# Interface
# --------------------------------------------------------------------------- #
CSS = r"""
.split{display:grid;grid-template-columns:minmax(0,1fr) 410px;gap:24px;max-width:1380px;margin:0 auto;padding:26px 30px 40px}
.split .view{padding:0;max-width:none;margin:0}
.side{position:sticky;top:0;align-self:start;display:flex;flex-direction:column;gap:14px}
.jr{height:calc(100vh - 300px);min-height:260px}
.pg{background:var(--panel);border:1px solid var(--line);border-top:3px solid var(--or);border-radius:6px;padding:16px 18px}
.pg .big{font-size:26px;font-weight:700;color:#fff;line-height:1.1}.pg .sub{color:var(--mut);font-size:12.5px;margin-top:4px}
.rowc{display:flex;gap:14px;align-items:flex-start;padding:11px 4px;border-bottom:1px dashed var(--line)}.rowc:last-child{border:0}
.rowc .tx{flex:1;min-width:0}.rowc b{font-weight:600;color:#fff}.rowc small{display:block;color:var(--mut);font-size:12.5px;word-break:break-all}
.rowc.dis{opacity:.45}.rowc input{margin-top:3px}
.right{text-align:right;white-space:nowrap}
.dvs{display:flex;gap:10px;flex-wrap:wrap;margin-top:12px}
.dv{background:var(--panel2);border:1px solid var(--line);border-radius:5px;padding:9px 12px;cursor:pointer;min-width:170px}
.dv:hover,.dv.on{border-color:var(--or)}.dv b{display:block;color:#fff;font-size:13.5px}.dv span{font-size:12px;color:var(--mut)}
.tot{display:flex;gap:16px;align-items:center;flex-wrap:wrap;margin-top:14px}
.bk{display:flex;gap:12px;align-items:center;padding:10px 12px;border:1px solid var(--line);border-radius:5px;margin-bottom:8px;cursor:pointer;background:var(--panel2)}
.bk:hover,.bk.on{border-color:var(--or)}.bk b{color:#fff}
"""

BODY = r"""
<div class="split"><div>
<section class="view" id="v-bk">
 <div class="card"><h2>Sauvegarder l'ancien PC</h2>
  <p class="lead">Copie le profil de l'utilisateur sur une clé USB, un disque externe ou un partage réseau. Rien n'est modifié ni supprimé sur ce PC.</p>
  <div class="row"><span class="lbl">Profil</span><select id="prof" style="min-width:280px" onchange="analyse()"></select>
   <button class="btn2" onclick="addFolder()">Ajouter un dossier…</button></div></div>
 <div class="card"><h2>Éléments à sauvegarder</h2><div id="bkL"><div class="empty">Analyse du profil…</div></div></div>
 <div class="card"><h2>Destination</h2>
  <div class="row"><input type="text" id="dest" style="flex:1;min-width:260px" placeholder="Choisir une clé USB ou un dossier" oninput="destChanged()">
   <button class="btn2" onclick="pickDest()">Parcourir…</button><button class="lnk" onclick="refreshDrives()">Actualiser les lecteurs</button></div>
  <div class="dvs" id="dvs"></div>
  <div class="tot"><span class="host" id="totInfo"></span><span style="margin-left:auto"></span><button class="btn" id="bBk" onclick="backup()">Lancer la sauvegarde</button></div></div>
</section>
<section class="view" id="v-rs">
 <div class="card"><h2>Restaurer sur le nouveau PC</h2>
  <p class="lead">Branche la clé ou le disque contenant la sauvegarde, puis choisis-la. Les fichiers déjà présents et plus récents ne sont jamais écrasés.</p>
  <div class="row"><button class="btn2" onclick="findBk()">Rechercher les sauvegardes</button><button class="btn2" onclick="pickBk()">Choisir un dossier…</button></div>
  <div id="bkFound" style="margin-top:14px"></div></div>
 <div class="card" id="rsCard" style="display:none"><h2>Éléments à restaurer</h2><div id="rsInfo" class="host" style="margin:-6px 0 10px"></div><div id="rsL"></div>
  <div class="tot"><span class="host">Restauré pour le compte : <b id="rsUser" style="color:#fff"></b></span><span style="margin-left:auto"></span>
   <button class="btn" id="bRs" onclick="restore()">Lancer la restauration</button></div></div>
 <div id="notes"></div>
</section>
</div>
<aside class="side">
 <div class="pg"><div class="lbl" id="pgLbl">Progression</div><div class="big" id="pgBig">&mdash;</div><div class="sub" id="pgSub">Aucune opération en cours</div>
  <div class="bar" style="margin-top:12px"><i id="pgBar"></i></div></div>
 <div class="jr"><div class="jh"><span class="jt">Journal</span><span class="jcur" id="jcur"></span>
  <button id="jStop" disabled onclick="api().cancel()">Arrêter</button><button onclick="copyText($('#jb').innerText,'Journal copié.')">Copier</button></div>
  <div class="jb" id="jb"><div class="jl k-mut" data-placeholder="1">Le déroulement de la sauvegarde ou de la restauration s'affiche ici.</div></div></div>
</aside></div>
<div class="ov" id="ov"><div class="md"><h3 id="mT"></h3><p id="mD"></p><div id="mL" style="max-height:240px;overflow:auto;font-size:13px;color:#cfd8e0"></div>
 <div class="mb"><button class="btn2" onclick="$('#ov').classList.remove('show')">Annuler</button><button class="btn" id="mGo">Confirmer</button></div></div></div>
"""

JS = r"""
let INFO=null,ITEMS=[],SIZES={},CUSTOM=[],BUSY=false,T0=0,RSB=null;
const H=n=>{n=+n||0;for(const u of ['o','Ko','Mo','Go','To']){if(n<1024||u==='To')return (u==='o'||u==='Ko'?Math.round(n):n.toFixed(1).replace('.',','))+' '+u;n/=1024}};
window.addEventListener('pywebviewready',async()=>{const a=api();INFO=await a.info();
 $('#host').textContent=INFO.host+'  \u00b7  '+INFO.user+(INFO.admin?'':'  \u00b7  sans droits admin');$('#rsUser').textContent=INFO.user;
 const s=$('#prof');s.innerHTML='';for(const p of INFO.profiles){const o=el('option',null,p.name+(p.me?'  (compte actuel)':''));o.value=p.path;s.append(o)}
 drawDrives();analyse();findBk(true);a.ready()});
function analyse(){const a=api();if(!a)return;SIZES={};$('#bkL').innerHTML='<div class="empty"><span class="spin"></span>Analyse du profil\u2026</div>';
 a.analyse($('#prof').value,CUSTOM).then(r=>{ITEMS=r.items;drawItems()})}
function drawItems(){const box=$('#bkL');box.innerHTML='';
 for(const it of ITEMS){const row=el('label','rowc'+(it.exists?'':' dis'));const cb=el('input');cb.type='checkbox';cb.checked=it.def;cb.disabled=!it.exists;cb.dataset.key=it.key;cb.onchange=total;
  const tx=el('div','tx');const b=el('b',null,it.label);tx.append(b);if(it.onedrive){const c=el('span','chip c-info','OneDrive');c.title='Dossier synchronisé avec OneDrive : déjà sauvegardé dans le cloud';tx.append(' ',c)}
  if(it.custom)tx.append(' ',el('span','chip','dossier ajouté'));tx.append(el('small',null,it.exists?it.detail:(it.kind==='folder'?'Introuvable : '+it.detail:it.detail)));
  const r=el('div','right');const sz=el('span','chip');sz.id='sz-'+it.key;sz.textContent=it.kind==='folder'||it.kind==='pst'||it.kind==='signatures'?(it.exists?'\u2026':'\u2014'):'';
  const st=el('div','st');st.id='st-'+it.key;r.append(sz,st);row.append(cb,tx,r);box.append(row)}
 if(ITEMS.some(i=>i.onedrive))box.prepend(el('div','note','Les dossiers OneDrive sont décochés : ils sont déjà dans le cloud et réapparaîtront en reconnectant OneDrive sur le nouveau PC. Les fichiers « en ligne uniquement » ne sont jamais téléchargés.'));
 total()}
E.size=s=>{SIZES[s.key]=s.bytes;const c=document.getElementById('sz-'+s.key);if(c){c.textContent=s.h+'  \u00b7  '+s.files+' fichier(s)'}total()};
E.sizesDone=()=>total();
function sel(){return $$('#bkL input:checked').map(c=>ITEMS.find(i=>i.key===c.dataset.key))}
let FREE=null;
function total(){const s=sel();const t=s.reduce((a,i)=>a+(SIZES[i.key]||0),0);const pend=s.some(i=>(i.kind==='folder'||i.kind==='pst')&&SIZES[i.key]===undefined);
 let txt=s.length+' élément(s)  \u00b7  '+H(t)+(pend?' (calcul en cours\u2026)':'');
 if(FREE!==null)txt+='  \u00b7  libre sur la destination : '+H(FREE)+(FREE<t*1.05?'  \u26A0 place insuffisante':'');$('#totInfo').textContent=txt}
function drawDrives(){const box=$('#dvs');box.innerHTML='';for(const d of INFO.drives){if(d.root.toUpperCase().startsWith('C:'))continue;
  const b=el('div','dv'+($('#dest').value.startsWith(d.root)?' on':''));b.append(el('b',null,d.root+'  '+(d.label||'')),el('span',null,d.type+'  \u00b7  '+H(d.free)+' libres'));
  b.onclick=()=>{$('#dest').value=d.root;destChanged()};box.append(b)}
 if(!box.childElementCount)box.append(el('span','host','Aucune clé ou disque externe détecté : brancher le support puis « Actualiser les lecteurs ».'))}
function refreshDrives(){api().list_drives().then(d=>{INFO.drives=d;drawDrives()})}
function destChanged(){const v=$('#dest').value.trim();drawDrives();if(!v){FREE=null;total();return}api().free_space(v).then(r=>{FREE=r.free;total()})}
function pickDest(){api().pick().then(p=>{if(p){$('#dest').value=p;destChanged()}})}
function addFolder(){api().pick().then(p=>{if(p&&!CUSTOM.includes(p)){CUSTOM.push(p);analyse()}})}
function confirmBox(t,d,lines,go){$('#mT').textContent=t;$('#mD').textContent=d;const l=$('#mL');l.innerHTML='';for(const x of lines)l.append(el('div',null,'\u2022 '+x));
 $('#mGo').onclick=()=>{$('#ov').classList.remove('show');go()};$('#ov').classList.add('show')}
function backup(){const s=sel();const dest=$('#dest').value.trim();if(!s.length){toast('Rien de sélectionné.');return}if(!dest){toast('Choisis une destination.');return}
 const t=s.reduce((a,i)=>a+(SIZES[i.key]||0),0);if(FREE!==null&&FREE<t){toast('Place insuffisante sur la destination.');return}
 confirmBox('Lancer la sauvegarde','Vers '+dest+'\\'+'E-A2_Migration ('+H(t)+').',s.map(i=>i.label),()=>{
  api().backup_start($('#prof').value,s,dest).then(r=>{if(r.error){toast(r.error);return}start('Sauvegarde',r.root);for(const i of s)itemSt(i.key,'queued')})})}
let MODE='bk';
function start(lbl,where){BUSY=true;MODE=lbl==='Restauration'?'rs':'bk';T0=Date.now();$('#jStop').disabled=false;$('#bBk').disabled=true;$('#bRs').disabled=true;$('#pgLbl').textContent=lbl;
 $('#pgBig').textContent='0 %';$('#pgSub').textContent=where;$('#pgBar').style.width='1%';$('#jcur').textContent=lbl+' en cours'}
const STL={queued:['','En attente'],run:['run','<span class="spin"></span>En cours'],ok:['ok','\u2713 '],warn:['warn','\u26A0 '],err:['err','\u2717 '],stopped:['','Arrêté'],skip:['','Ignoré']};
function itemSt(k,st,msg){const e=document.getElementById((MODE==='rs'?'rst-':'st-')+k);if(!e)return;const [c,h]=STL[st]||['',st];e.className='st '+c;e.innerHTML=h+(msg&&['ok','warn','err'].includes(st)?'':'');if(msg&&['ok','warn','err'].includes(st))e.append(document.createTextNode(msg))}
E.item=i=>itemSt(i.key,i.st,i.msg);
E.log=d=>{for(const l of d.lines)jline($('#jb'),l.t,l.k)};
E.prog=p=>{const pc=p.total?Math.min(100,100*p.done/p.total):0;const sec=(Date.now()-T0)/1000;const sp=sec>1?p.done/sec:0;
 const eta=sp>0&&p.total>p.done?(p.total-p.done)/sp:0;$('#pgBig').textContent=Math.floor(pc)+' %';$('#pgBar').style.width=Math.max(1,pc)+'%';
 $('#pgSub').textContent=p.label+'  \u00b7  '+H(p.done)+' / '+H(p.total)+(sp?'  \u00b7  '+H(sp)+'/s':'')+(eta>3?'  \u00b7  reste ~'+(eta>90?Math.round(eta/60)+' min':Math.round(eta)+' s'):'')};
E.done=d=>{BUSY=false;$('#jStop').disabled=true;$('#bBk').disabled=false;$('#bRs').disabled=false;$('#pgBar').style.width='100%';
 const ok={ok:'Terminé',warn:'Terminé avec avertissements',err:'Échec',stopped:'Arrêté'}[d.status]||d.status;$('#pgBig').textContent=ok;$('#jcur').textContent=ok;
 if(d.mode==='backup'){$('#pgSub').textContent=d.root;toast('Sauvegarde : '+ok.toLowerCase()+'.')}
 else{const n=$('#notes');n.innerHTML='';if(d.notes&&d.notes.length){const c=el('div','card');c.append(el('h2',null,'À faire sur le nouveau PC'));for(const x of d.notes)c.append(el('div','note',x));n.append(c)}toast('Restauration : '+ok.toLowerCase()+'.')}};
/* restauration */
function findBk(silent){api().find_backups().then(l=>{const box=$('#bkFound');box.innerHTML='';
 if(!l.length){if(!silent)box.append(el('div','host','Aucune sauvegarde trouvée sur les lecteurs branchés. Utiliser « Choisir un dossier… ».'));return}
 for(const b of l){const r=el('div','bk');r.append(el('b',null,b.pc+'  \u00b7  '+b.user),el('span','host',(b.date||'').replace('T',' à ')+'  \u00b7  '+b.drive));r.onclick=()=>{$$('.bk').forEach(x=>x.classList.remove('on'));r.classList.add('on');loadBk(b.path)};box.append(r)}})}
function pickBk(){api().pick().then(p=>{if(p)loadBk(p)})}
function loadBk(p){api().load_backup(p).then(r=>{if(r.error){toast(r.error);return}RSB=r;$('#rsCard').style.display='block';
 $('#rsInfo').textContent='Sauvegarde de '+r.manifest.pc+' ('+r.manifest.user+'), '+(r.manifest.date||'').replace('T',' à ')+'  \u00b7  '+r.path;
 const box=$('#rsL');box.innerHTML='';for(const it of r.items){const row=el('label','rowc');const cb=el('input');cb.type='checkbox';cb.checked=it.status!=='err';cb.dataset.key=it.key;
  const tx=el('div','tx');tx.append(el('b',null,it.label),el('small',null,(it.target?'\u2192 '+it.target+'  \u00b7  ':'')+it.msg));const rr=el('div','right');const st=el('div','st');st.id='rst-'+it.key;rr.append(st);
  row.append(cb,tx,rr);box.append(row)}})}
function restore(){if(!RSB)return;const keys=$$('#rsL input:checked').map(c=>c.dataset.key);if(!keys.length){toast('Rien de sélectionné.');return}
 const labels=keys.map(k=>RSB.items.find(i=>i.key===k).label);
 confirmBox('Lancer la restauration','Sur le compte '+INFO.user+'. Les fichiers déjà présents et plus récents sont conservés.',labels,()=>{
  MODE='rs';api().restore_start(RSB.path,keys,'').then(r=>{if(r.error){toast(r.error);return}start('Restauration',RSB.path);for(const k of keys)itemSt(k,'queued')})})}
"""


def main():
    ap = argparse.ArgumentParser(description=f"{APP} - transfert de profil")
    ap.add_argument("--selftest", default="", help=argparse.SUPPRESS)
    ap.add_argument("--fulltest", default="", help=argparse.SUPPRESS)
    args = ap.parse_args()
    html_ = build_page("migration", APP, "Transfert de profil", [("bk", "Sauvegarder"), ("rs", "Restaurer")],
                       BODY, CSS, JS, nav="<span class='host' id='host'></span>")
    return run_window(f"{APP} - Transfert de profil", html_, MigBridge(args))


if __name__ == "__main__":
    finish(main())
