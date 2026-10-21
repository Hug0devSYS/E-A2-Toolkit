# -*- coding: utf-8 -*-
"""Tests complets d'E-A2 Migration (mode --fulltest DOSSIER) - à lancer uniquement dans une VM jetable."""
import hashlib
import json
import os
import shutil
import time

from ea2ui import TestKit, run, ps_cmd
import ea2_migration as M


def sha(p):
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for blk in iter(lambda: fh.read(1 << 20), b""):
            h.update(blk)
    return h.hexdigest()


def run_full(b):
    T = TestKit(b._args.fulltest, "migration", b)
    try:
        b._window.maximize()
    except Exception:
        pass
    js = T.js
    T.wait(lambda: js("typeof INFO!=='undefined' && INFO!==null") is True, 90)
    home = os.path.expanduser("~")
    kf = M.known_folders(home)
    created = {}          # chemin -> sha256
    st = {}

    # ------------------------------------------------------------------ préparation d'un profil réaliste
    A = "Préparation"

    def prep():
        def mk(path, data):
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "wb") as fh:
                fh.write(data)
            created[path] = sha(path)
        desk = kf["Desktop"]
        base = os.path.join(desk, "Test E-A2 Migration")
        for i in range(40):
            mk(os.path.join(base, f"Dossier {i % 5}", "Sous-dossier éàç", f"Facture n°{i} été.txt"), (f"Facture {i}\n" * (300 * (i + 1))).encode("utf-8"))
        mk(os.path.join(base, "Vidéo vacances.bin"), os.urandom(60 * 1024 * 1024))
        deep = os.path.join(base, *["Dossier avec un nom assez long pour depasser la limite"] * 5)
        mk(os.path.join(deep, "fichier au chemin tres long.txt"), b"chemin long" * 100)
        mk(os.path.join(base, "conflit.txt"), "VERSION ANCIENNE".encode())
        os.utime(os.path.join(base, "conflit.txt"), (time.time() - 86400 * 3, time.time() - 86400 * 3))
        mk(os.path.join(kf["MyDocuments"], "Comptabilité 2026", "Bilan.xlsx"), os.urandom(300 * 1024))
        mk(os.path.join(kf["MyPictures"], "Photos famille", "photo_001.jpg"), os.urandom(2 * 1024 * 1024))
        mk(os.path.join(kf["MyMusic"], "Musique test.mp3"), os.urandom(800 * 1024))
        mk(os.path.join(kf["MyVideos"], "Clip test.mp4"), os.urandom(1024 * 1024))
        mk(os.path.join(kf["Downloads"], "Installeur test.exe"), os.urandom(512 * 1024))
        mk(os.path.join(kf["MyDocuments"], "Fichiers Outlook", "Archives 2025.pst"), os.urandom(5 * 1024 * 1024))
        sig = os.path.join(home, "AppData", "Roaming", "Microsoft", "Signatures")
        mk(os.path.join(sig, "Signature E-A2.htm"), "<p>Hugo - E-Media Services</p>".encode())
        mk(os.path.join(sig, "Signature E-A2.txt"), "Hugo - E-Media Services".encode())
        edge = os.path.join(home, "AppData", "Local", "Microsoft", "Edge", "User Data", "Default")
        bm = {"roots": {"bookmark_bar": {"children": [{"type": "url", "name": "E-Media Services", "url": "https://emedia-services.fr/"},
                                                      {"type": "folder", "name": "Clients", "children": [
                                                          {"type": "url", "name": "A2MI", "url": "https://a2mi-info.fr/"}]}]},
                        "other": {"children": [{"type": "url", "name": "Impôts", "url": "https://www.impots.gouv.fr/"}]}, "synced": {"children": []}}}
        os.makedirs(edge, exist_ok=True)
        with open(os.path.join(edge, "Bookmarks"), "w", encoding="utf-8") as fh:
            json.dump(bm, fh)
        run(ps_cmd("New-Item 'HKCU:\\Network\\T' -Force | Out-Null; Set-ItemProperty 'HKCU:\\Network\\T' RemotePath '\\\\127.0.0.1\\C$';"
                   "Set-ItemProperty 'HKCU:\\Network\\T' ConnectionType 1 -Type DWord"), timeout=30)
        img = os.path.join(os.environ.get("WINDIR", r"C:\Windows"), "Web", "Wallpaper", "Windows", "img0.jpg")
        if os.path.exists(img):
            import ctypes
            ctypes.windll.user32.SystemParametersInfoW(20, 0, img, 3)
            time.sleep(2)
        tw = os.path.join(home, "AppData", "Roaming", "Microsoft", "Windows", "Themes", "TranscodedWallpaper")
        T.check(A, "Profil de test créé", len(created) >= 50, f"{len(created)} fichiers, fond d'écran={os.path.exists(tw)}")
        cdir = r"C:\Donnees Client"
        for i in range(10):
            mk(os.path.join(cdir, f"Devis {i}.docx"), os.urandom(50 * 1024))
        st["custom"] = cdir
    T.guard(A, "Préparation", prep)

    # ------------------------------------------------------------------ analyse
    A = "Analyse"

    def analyse():
        b._window.create_file_dialog = lambda *a, **k: st["custom"]
        js("addFolder()")
        ok = T.wait(lambda: js("ITEMS.some(i=>i.custom)") is True, 30)
        T.check(A, "Ajout d'un dossier personnalisé (C:\\Donnees Client)", ok)
        T.wait(lambda: all(js(f"SIZES['{k}']!==undefined") for k in ("desktop", "documents", "pictures", "custom0")), 120)
        items = js("JSON.stringify(ITEMS)")
        items = json.loads(items or "[]")
        keys = {i["key"]: i for i in items}
        for k in ("desktop", "documents", "pictures", "videos", "music", "downloads", "bookmarks", "signatures", "pst",
                  "printers", "netdrives", "wallpaper", "software", "custom0"):
            T.check(A, f"Élément détecté : {keys.get(k, {}).get('label', k)}", keys.get(k, {}).get("exists") is True, keys.get(k, {}).get("detail"))
        T.rec(A, "Wi-Fi", "INFO", f"existe={keys.get('wifi', {}).get('exists')} (pas de carte Wi-Fi dans la VM)")
        desk_sz = js("SIZES['desktop']") or 0
        T.check(A, "Taille du Bureau calculée", desk_sz >= 60 * 1024 * 1024, M.human(desk_sz))
        T.shot("1_analyse")
    T.guard(A, "Analyse", analyse)

    # ------------------------------------------------------------------ garde-fous
    A = "Garde-fous"

    def guards():
        items = json.loads(js("JSON.stringify(ITEMS)"))
        r = b.backup_start(home, [i for i in items if i["key"] == "desktop"], kf["Desktop"])
        T.check(A, "Destination dans un dossier sauvegardé refusée", "intérieur" in (r.get("error") or ""), r)
        r = b.backup_start(home, items[:1], r"C:\Dossier\Inexistant")
        T.check(A, "Destination inexistante refusée", "existant" in (r.get("error") or ""), r)
        fs = b.free_space("C:\\")
        T.check(A, "Espace libre de la destination", (fs.get("free") or 0) > 0, fs)
    T.guard(A, "Garde-fous", guards)

    # ------------------------------------------------------------------ arrêt d'une sauvegarde
    A = "Arrêt"

    def cancel():
        big = r"C:\Gros dossier"
        os.makedirs(big, exist_ok=True)
        with open(os.path.join(big, "gros.bin"), "wb") as fh:
            for _ in range(40):
                fh.write(os.urandom(16 * 1024 * 1024))
        dest = r"C:\Dest annulation"
        os.makedirs(dest, exist_ok=True)
        b._sizes["xbig"] = 640 * 1024 * 1024
        r = b.backup_start(home, [{"key": "xbig", "label": "Gros dossier", "kind": "folder", "path": big}], dest)
        time.sleep(1.5)
        b.cancel()
        T.wait(lambda: not b._busy, 120)
        T.check(A, "Sauvegarde arrêtée par le bouton Arrêter", b._result.get("status") == "stopped", b._result.get("status"))
        shutil.rmtree(big, ignore_errors=True)
        shutil.rmtree(dest, ignore_errors=True)
    T.guard(A, "Arrêt", cancel)

    # ------------------------------------------------------------------ sauvegarde complète via l'interface
    A = "Sauvegarde"

    def backup():
        js("tab('bk');document.querySelectorAll('#bkL input').forEach(c=>{if(!c.disabled)c.checked=true});total()")
        js("document.getElementById('dest').value='C:\\\\';destChanged()")
        time.sleep(2)
        js("backup()")
        T.check(A, "Confirmation affichée", js("document.getElementById('ov').classList.contains('show')") is True, js("document.getElementById('mL').innerText"))
        js("document.getElementById('mGo').click()")
        T.wait(lambda: b._busy, 20)
        time.sleep(4)
        T.shot("2_sauvegarde_en_cours")
        T.wait(lambda: not b._busy, 1800, 1)
        res = b._result or {}
        man = res.get("manifest", {})
        st["root"] = res.get("root")
        T.check(A, "Sauvegarde terminée", res.get("status") in ("ok", "warn"), f"{res.get('status')} - {res.get('root')}")
        for k, it in man.get("items", {}).items():
            exp_warn = k in ("wifi",)
            T.rec(A, f"Élément « {it['label']} »", "PASS" if it.get("status") == "ok" else ("WARN" if exp_warn or it.get("status") == "warn" else "FAIL"),
                  it.get("msg"))
        root = st["root"]
        miss, bad = [], []
        for p, h in created.items():
            rel = None
            for k, known, name in (("desktop", "Desktop", "Bureau"), ("documents", "MyDocuments", "Documents"), ("pictures", "MyPictures", "Images"),
                                   ("videos", "MyVideos", "Videos"), ("music", "MyMusic", "Musique"), ("downloads", "Downloads", "Telechargements")):
                if os.path.normcase(p).startswith(os.path.normcase(kf[known]) + os.sep):
                    rel = os.path.join(root, "Fichiers", name, os.path.relpath(p, kf[known]))
                    break
            if rel is None and p.startswith(st["custom"]):
                rel = os.path.join(root, "Fichiers", "Donnees Client", os.path.relpath(p, st["custom"]))
            if rel is None:
                continue
            q = rel if len(rel) < 250 else "\\\\?\\" + rel
            if not os.path.exists(q):
                miss.append(rel)
            elif sha(q) != h:
                bad.append(rel)
        T.check(A, "Fichiers copiés à l'identique (SHA-256)", not miss and not bad, f"manquants={miss[:3]} différents={bad[:3]}")
        T.check(A, "Chemin de plus de 260 caractères copié", not any("chemin au" in m for m in miss))
        html_ = os.path.join(root, "Navigateurs", "Favoris_Edge_Default.html")
        T.check(A, "Favoris Edge convertis en HTML", os.path.exists(html_) and "a2mi-info.fr" in open(html_, encoding="utf-8").read())
        T.check(A, "Signatures Outlook copiées", os.path.exists(os.path.join(root, "Outlook", "Signatures", "Signature E-A2.htm")))
        T.check(A, "Fichier .pst copié", os.path.exists(os.path.join(root, "Outlook", "PST", "Archives 2025.pst")))
        T.check(A, "Imprimantes : sauvegarde complète PrintBrm", os.path.exists(os.path.join(root, "Imprimantes", "imprimantes.printerExport")),
                man.get("items", {}).get("printers", {}).get("msg"))
        T.check(A, "Lecteurs réseau listés", "T" in open(os.path.join(root, "lecteurs_reseau.json"), encoding="utf-8").read())
        T.check(A, "Fond d'écran copié", os.path.exists(os.path.join(root, "Fond_ecran.jpg")))
        T.check(A, "Liste des logiciels", os.path.exists(os.path.join(root, "Logiciels", "logiciels_installes.txt")))
        T.check(A, "Rapport de sauvegarde écrit", os.path.exists(os.path.join(root, "Rapport de sauvegarde.txt")))
        big = js("document.getElementById('pgBig').textContent")
        T.check(A, "Panneau de progression : terminé", "Terminé" in (big or ""), big)
        T.shot("3_sauvegarde_terminee")
    T.guard(A, "Sauvegarde", backup)

    # ------------------------------------------------------------------ simulation du nouveau PC puis restauration
    A = "Restauration"

    def restore():
        root = st.get("root")
        if not root:
            T.rec(A, "Restauration", "FAIL", "pas de sauvegarde")
            return
        base = os.path.join(kf["Desktop"], "Test E-A2 Migration")
        shutil.rmtree("\\\\?\\" + base, ignore_errors=True)
        for p in list(created):
            if not p.startswith(base) and os.path.exists(p):
                os.remove(p)
        shutil.rmtree(os.path.join(home, "AppData", "Roaming", "Microsoft", "Signatures"), ignore_errors=True)
        run(ps_cmd("Remove-Item 'HKCU:\\Network\\T' -Recurse -Force -ErrorAction SilentlyContinue"), timeout=20)
        os.makedirs(base, exist_ok=True)
        with open(os.path.join(base, "conflit.txt"), "w", encoding="utf-8") as fh:
            fh.write("VERSION RECENTE")
        found = b.find_backups()
        T.check(A, "Sauvegarde retrouvée automatiquement sur les lecteurs", any(os.path.normcase(f["path"]) == os.path.normcase(root) for f in found),
                [f["path"] for f in found])
        js("tab('rs');findBk()")
        T.wait(lambda: js("document.querySelectorAll('.bk').length") >= 1, 20)
        js("document.querySelector('.bk').click()")
        T.wait(lambda: js("document.querySelectorAll('#rsL .rowc').length") >= 5, 20)
        T.check(A, "Éléments de la sauvegarde listés", js("document.querySelectorAll('#rsL .rowc').length") >= 10,
                js("document.getElementById('rsL').innerText"))
        js("document.querySelectorAll('#rsL input').forEach(c=>c.checked=true);restore()")
        js("document.getElementById('mGo').click()")
        T.wait(lambda: b._busy, 20)
        T.wait(lambda: not b._busy, 2400, 1)
        res = b._result or {}
        T.check(A, "Restauration terminée", res.get("status") in ("ok", "warn"), res)
        statuses = js("[...document.querySelectorAll('[id^=rst-]')].map(e=>e.id.slice(4)+'='+e.textContent).join(' | ')")
        T.rec(A, "Statut par élément", "INFO", statuses)
        miss, bad = [], []
        for p, h in created.items():
            if p.startswith(st["custom"]):
                continue
            q = p if len(p) < 250 else "\\\\?\\" + p
            if p.endswith("conflit.txt"):
                continue
            if not os.path.exists(q):
                miss.append(p)
            elif sha(q) != h:
                bad.append(p)
        T.check(A, "Fichiers restaurés à l'identique dans le profil", not miss and not bad, f"manquants={miss[:4]} différents={bad[:4]}")
        T.check(A, "Fichier plus récent sur le nouveau PC non écrasé", open(os.path.join(base, "conflit.txt"), encoding="utf-8").read() == "VERSION RECENTE")
        T.check(A, "Signatures restaurées", os.path.exists(os.path.join(home, "AppData", "Roaming", "Microsoft", "Signatures", "Signature E-A2.htm")))
        T.check(A, "Favoris HTML déposés sur le Bureau", os.path.exists(os.path.join(kf["Desktop"], "Favoris migrés", "Favoris_Edge_Default.html")))
        T.check(A, "Fichier .pst dans Documents\\Fichiers Outlook", os.path.exists(os.path.join(kf["MyDocuments"], "Fichiers Outlook", "Archives 2025.pst")))
        wp = run(ps_cmd("(Get-ItemProperty 'HKCU:\\Control Panel\\Desktop').WallPaper"), timeout=20).strip()
        T.check(A, "Fond d'écran réappliqué", "Fond_ecran_migre" in wp, wp)
        nu = run(["net", "use"], timeout=20)
        T.rec(A, "Lecteur réseau T: reconnecté", "PASS" if "T:" in nu else "WARN", nu[-300:])
        notes = js("document.getElementById('notes').innerText") or ""
        T.check(A, "Consignes « À faire sur le nouveau PC » affichées", "Favoris" in notes, notes[:300])
        T.shot("4_restauration")
        T.js_errors(A)
    T.guard(A, "Restauration", restore)
    T.finish()
