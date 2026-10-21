# -*- coding: utf-8 -*-
"""Tests complets d'E-A2 Install (mode --fulltest DOSSIER) - à lancer uniquement dans une VM jetable."""
import os
import time

from ea2ui import TestKit, run, ps_cmd


def run_full(b):
    T = TestKit(b._args.fulltest, "install", b)
    try:
        b._window.maximize()
    except Exception:
        pass
    js = T.js
    T.wait(lambda: js("window.READY===true") is True, 120)

    def idle(timeout):
        return T.wait(lambda: b._q.empty() and b._cur is None and not b._pending, timeout, 1)

    def last(kind, ref=None):
        for d in reversed(b._done):
            if d["kind"] == kind and (ref is None or d["ref"] == ref):
                return d
        return {}

    def logtxt(d):
        return " / ".join(t for t, _ in d.get("log", [])[-8:])

    # ------------------------------------------------------------------ démarrage
    A = "Démarrage"

    def start():
        info = b.info()
        T.check(A, "Lancé avec les droits administrateur", info["admin"] is True, info["admin"])
        n = sum(len(c["items"]) for c in info["catalog"])
        T.check(A, "Catalogue chargé", n >= 50, f"{n} logiciels")
        T.check(A, "Tuiles affichées", js("document.querySelectorAll('.app-t').length") == n)
        T.check(A, "Réglages affichés", js("document.querySelectorAll('#setL .rowc').length") == len(info["settings"]))
        T.rec(A, "Système", "INFO", f"{info['os']} - constructeur : {info['maker']!r}")
        T.shot("1_logiciels")
    T.guard(A, "Démarrage", start)

    # ------------------------------------------------------------------ winget
    A = "winget"
    state = {"wg": False}

    def winget():
        ws = b.winget_status()
        if not ws["version"]:
            T.rec(A, "winget absent au départ (comme sur certains PC neufs)", "INFO", ws)
            note = js("document.getElementById('wgNote').innerText") or ""
            T.check(A, "Bandeau « Réparer winget » affiché", "Réparer" in note or "absent" in note, note)
            js("document.querySelector('#wgNote .btn').click()")
            time.sleep(2)
            idle(900)
            d = last("winget_fix")
            ws = b.winget_status()
            T.check(A, "Réparer winget : installation réussie", bool(ws["version"]), f"{ws} - job={d.get('st')} {d.get('msg')} - {logtxt(d)}")
        else:
            T.rec(A, "winget présent", "INFO", ws)
        state["wg"] = bool(ws["version"])
        if state["wg"]:
            r = b.installed()
            T.check(A, "Détection des logiciels installés (winget export)", "error" not in r, f"{len(r['ids'])} paquets")
    T.guard(A, "winget", winget)

    # ------------------------------------------------------------------ logiciels
    A = "Logiciels"

    def apps():
        cat = b.info()["catalog"]
        for p, lab in (("P", "Particulier"), ("B", "Bureau / PME"), ("T", "Technicien")):
            exp = sum(1 for c in cat for it in c["items"] if p in it["presets"])
            n = js(f"presetSel('{p}');SEL.size")
            T.check(A, f"Préréglage {lab}", n is not None and 0 < n <= exp + 1, f"{n} coché(s), {exp} prévus")
        T.check(A, "Tout décocher", js("presetSel('none');SEL.size") == 0)
        vis = js("document.getElementById('aFilter').value='zip';appFilter();[...document.querySelectorAll('.app-t')].filter(t=>t.style.display!=='none').map(t=>t.dataset.id).join(',')")
        T.check(A, "Recherche dans le catalogue", "7zip.7zip" in (vis or ""), vis)
        js("document.getElementById('aFilter').value='';appFilter()")
        if not state["wg"]:
            T.rec(A, "Installations", "FAIL", "winget indisponible : tests d'installation impossibles")
            return
        targets = {"7zip.7zip": r"C:\Program Files\7-Zip\7z.exe", "voidtools.Everything": r"C:\Program Files\Everything\Everything.exe",
                   "Notepad++.Notepad++": r"C:\Program Files\Notepad++\notepad++.exe"}
        for i in targets:
            js(f"(()=>{{const t=document.querySelector('.app-t[data-id=\"{i}\"]');const c=t.querySelector('input');if(!c.checked)c.click()}})()")
        T.check(A, "Sélection par les cases", js("SEL.size") == 3, js("[...SEL].join(',')"))
        js("installSel()")
        T.check(A, "Fenêtre de confirmation affichée", js("document.getElementById('ov').classList.contains('show')") is True,
                js("document.getElementById('mL').innerText"))
        js("document.getElementById('mGo').click()")
        time.sleep(3)
        T.shot("2_installation_en_cours")
        idle(1500)
        for i, exe in targets.items():
            d = last("install", "app:" + i)
            T.check(A, f"Installation réelle de {i}", d.get("st") == "ok" and os.path.exists(exe),
                    f"statut={d.get('st')} {d.get('msg')} - présent={os.path.exists(exe)} - {logtxt(d)}")
        time.sleep(15)
        inst = js("[...document.querySelectorAll('.app-t.inst')].map(t=>t.dataset.id).join(',')") or ""
        T.check(A, "Tuiles passées à « Installé » après la file", all(i in inst for i in targets), inst)
        T.shot("3_installations_terminees")
        b.enqueue([{"kind": "install", "id": "7zip.7zip", "ref": "app:7zip.7zip", "title": "Réinstallation 7-Zip"}])
        idle(600)
        d = last("install", "app:7zip.7zip")
        T.check(A, "Logiciel déjà installé : pas d'échec", d.get("st") in ("ok", "warn"), f"{d.get('st')} {d.get('msg')} - {logtxt(d)}")
        b.enqueue([{"kind": "install", "id": "EA2.LogicielInexistant", "ref": "app:x", "title": "Logiciel inexistant"}])
        idle(300)
        d = last("install", "app:x")
        T.check(A, "Logiciel introuvable : échec clair", d.get("st") == "err" and "introuvable" in (d.get("msg") or ""), f"{d.get('st')} {d.get('msg')}")
        b.enqueue([{"kind": "install", "id": "9NKSQGP7F2NH", "ref": "app:wa", "title": "WhatsApp (Store)"}])
        idle(900)
        d = last("install", "app:wa")
        T.rec(A, "Installation depuis le Microsoft Store (WhatsApp)", "PASS" if d.get("st") == "ok" else "WARN",
              f"{d.get('st')} {d.get('msg')} - {logtxt(d)}")
        b.enqueue([{"kind": "install", "id": "VideoLAN.VLC", "ref": "app:VideoLAN.VLC", "title": "VLC"},
                   {"kind": "install", "id": "GIMP.GIMP", "ref": "app:GIMP.GIMP", "title": "GIMP"}])
        time.sleep(6)
        js("stopAll()")
        idle(300)
        d1, d2 = last("install", "app:VideoLAN.VLC"), last("install", "app:GIMP.GIMP")
        T.check(A, "Bouton Arrêter : tâche en cours stoppée", d1.get("st") in ("stopped", "ok"), f"VLC={d1.get('st')} {d1.get('msg')}")
        stopped2 = d2.get("st") == "stopped" or any(d["ref"] == "app:GIMP.GIMP" and d.get("st") == "stopped" for d in b._done) or not d2
        T.check(A, "Bouton Arrêter : file d'attente vidée", stopped2 and not os.path.exists(r"C:\Program Files\GIMP 3"), f"GIMP={d2.get('st') or 'annulé avant démarrage'}")
        b.enqueue([{"kind": "upgrade_all", "ref": "up", "title": "Mise à jour globale"}])
        idle(1500)
        d = last("upgrade_all")
        T.check(A, "Mettre à jour tous les logiciels", d.get("st") in ("ok", "warn"), f"{d.get('st')} {d.get('msg')} - {logtxt(d)}")
        jl = js("document.getElementById('jb').innerText") or ""
        T.check(A, "Journal alimenté en direct", "7zip" in jl or "7-Zip" in jl, jl[-400:])
    T.guard(A, "Logiciels", apps)

    # ------------------------------------------------------------------ nettoyage
    A = "Nettoyage"

    def bloat():
        js("tab('bloat')")
        r = b.bloat_scan()
        found = [x["pat"] for x in r["found"]]
        T.rec(A, "Applications superflues détectées", "INFO", ", ".join(found) or "aucune")
        T.wait(lambda: js("document.querySelectorAll('#bloatL .rowc').length") == len(found) or not found, 30)
        T.check(A, "Liste affichée", js("document.querySelectorAll('#bloatL .rowc').length") == len(found))
        T.shot("4_nettoyage")
        if not found:
            T.rec(A, "Suppression", "INFO", "rien à supprimer dans cette VM")
            return
        tgt = found[:3]
        js("document.querySelectorAll('#bloatL input').forEach(c=>c.checked=false)")
        for p in tgt:
            js(f"document.querySelector('#bloatL input[data-pat=\"{p}\"]').checked=true")
        js("document.getElementById('bAll').checked=true;bloatRun()")
        js("document.getElementById('mGo').click()")
        time.sleep(2)
        idle(600)
        left = [x["pat"] for x in b.bloat_scan()["found"]]
        for p in tgt:
            d = last("bloat", "bl:" + p)
            T.check(A, f"Suppression de {p} (tous les comptes)", d.get("st") == "ok" and p not in left, f"{d.get('st')} - {logtxt(d)}")
        prov = run(ps_cmd("Get-AppxProvisionedPackage -Online | Select-Object -ExpandProperty DisplayName"), timeout=120)
        T.check(A, "Retiré aussi pour les futurs comptes", not any(p.replace("*", "") in prov for p in tgt if "*" not in p), "")
    T.guard(A, "Nettoyage", bloat)

    # ------------------------------------------------------------------ réglages
    A = "Réglages"

    def settings():
        js("tab('set')")
        r0 = b.settings_read()
        T.rec(A, "État initial", "INFO", r0)
        T.check(A, "Lecture de l'état de chaque réglage", r0 and all(v in ("0", "1", "na") for v in r0.values()), r0)
        js("setAll(true);setRun()")
        js("document.getElementById('mGo').click()")
        time.sleep(2)
        idle(600)
        r1 = b.settings_read()
        for s in b.info()["settings"]:
            d = last("setting", "set:" + s["id"])
            T.check(A, f"Appliqué et vérifié : {s['label']}", r1.get(s["id"]) in ("1", "na") and d.get("st") in ("ok", "warn"),
                    f"avant={r0.get(s['id'])} après={r1.get(s['id'])} job={d.get('st')} - {logtxt(d)}")
        d = last("explorer")
        exp = run(ps_cmd("@(Get-Process explorer -ErrorAction SilentlyContinue).Count"), timeout=20).strip()
        T.check(A, "Explorateur redémarré", d.get("st") == "ok" and exp not in ("", "0"), f"{d.get('st')} - processus={exp}")
        cur = js("[...document.querySelectorAll('[id^=cur-]')].map(e=>e.textContent).join(' | ')")
        T.check(A, "États affichés « Déjà appliqué »", "Non appliqué" not in (cur or ""), cur)
        T.shot("5_reglages")
        js("document.getElementById('newName').value='nom invalide!';renamePc()")
        T.check(A, "Nom de poste invalide refusé", js("document.getElementById('ov').classList.contains('show')") is False,
                js("document.getElementById('toast').textContent"))
        js("document.getElementById('newName').value='EA2-TEST-VM';renamePc()")
        js("document.getElementById('mGo').click()")
        time.sleep(2)
        idle(120)
        pend = run(ps_cmd("(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ComputerName').ComputerName"), timeout=20).strip()
        T.check(A, "Renommage du poste (effectif au redémarrage)", pend.upper() == "EA2-TEST-VM", f"nom en attente={pend}")
        T.js_errors(A)
    T.guard(A, "Réglages", settings)
    T.finish()
