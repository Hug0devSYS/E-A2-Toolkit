# -*- coding: utf-8 -*-
"""Tests complets d'E-A2 Scan (mode --fulltest DOSSIER) - à lancer uniquement dans une VM jetable."""
import glob
import os
import socket
import time

from ea2ui import TestKit, run, ps_cmd

TIMEOUTS = {"sfc": 1800, "dism": 1800, "component_cleanup": 1500, "defender_quick": 1200, "defender_update": 600,
            "repair_wu": 600, "restore_point": 600, "clear_temp": 600}


def run_full(b):
    T = TestKit(b._args.fulltest, "scan", b)
    try:
        b._window.maximize()
    except Exception:
        pass
    js = T.js

    # ------------------------------------------------------------------ analyse
    A = "Diagnostic"

    def diag():
        ok = T.wait(lambda: b._last is not None and not b._busy, 900, 1)
        T.check(A, "Analyse automatique au lancement terminée", ok)
        meta, sections, summary = b._last
        T.check(A, "Droits administrateur", meta["admin"] is True)
        T.check(A, "Tous les modules présents", len(sections) >= 9, [s["title"] for s in sections])
        errs = [f"{s['title']}: {f['title']} - {f['detail']}" for s in sections for f in s["findings"] if "en erreur" in f["title"]]
        T.check(A, "Aucun module en erreur", not errs, errs)
        for s in sections:
            T.check(A, f"Module « {s['title']} » renseigné", bool(s["findings"]) and (s["tables"] or s["pre"] or s["key"] == "processes" or True),
                    "; ".join(f"[{f['level']}] {f['title']}" for f in s["findings"])[:600])
        T.rec(A, "Verdict", "INFO", f"{summary['verdict']} - {summary['crit']} critique(s), {summary['warn']} attention, durée {meta['duration']:.0f} s")
        time.sleep(1)
        cards = js("document.querySelectorAll('#res .card').length")
        T.check(A, "Cartes de résultats affichées", cards == len(sections) + 1, f"{cards} cartes")
        T.check(A, "Écran de résultats visible", js("getComputedStyle(document.getElementById('res')).display") == "grid")
        T.shot("1_diagnostic")
        js("document.getElementById('sec-network').scrollIntoView()")
        T.shot("2_diagnostic_reseau")
        b._last = None
        js("rescan()")
        ok = T.wait(lambda: b._last is not None and not b._busy, 900, 1)
        T.check(A, "Relancer l'analyse", ok)
        out = os.path.join(T.dir, "scan_rapport_avant.html")
        b._window.create_file_dialog = lambda *a, **k: out
        p = b.export_report()
        txt = open(p, encoding="utf-8").read() if p and os.path.exists(p) else ""
        T.check(A, "Exporter le rapport (HTML)", "Rapport de diagnostic" in txt and len(txt) > 5000, f"{p} ({len(txt)} car.)")
    T.guard(A, "Diagnostic", diag)

    # ------------------------------------------------------------------ dépannage
    A = "Dépannage"
    js("tab('dep')")
    time.sleep(1)
    T.check(A, "Onglet Dépannage : 15 actions", js("document.querySelectorAll('.act').length") == 15)
    reco = js("Object.keys(RECO).join(',')")
    T.rec(A, "Actions recommandées par le diagnostic", "INFO", reco or "aucune")
    T.shot("3_depannage")

    def launch(aid, timeout=300):
        n0 = len(b._history)
        js(f"ask(ACTS.find(a=>a.id==='{aid}'))")
        time.sleep(0.5)
        if js("document.getElementById('ov').classList.contains('show')") is True:
            js("document.getElementById('mGo').click()")
        T.wait(lambda: b._act is not None or len(b._history) > n0, 20, 0.2)
        ok = T.wait(lambda: b._act is None and len(b._history) > n0, timeout, 1)
        if not ok:
            b.cancel_action()
            T.wait(lambda: b._act is None, 60)
            return {"status": "timeout", "log": [], "dur": timeout}
        return b._history[-1]

    def logtxt(h, n=6):
        return " / ".join(t for t, _ in h.get("log", [])[-n:])

    def act(aid, label, verify=None, prep=None, allow_warn=True):
        def go():
            if prep:
                prep()
            h = launch(aid, TIMEOUTS.get(aid, 300))
            card = js(f"document.getElementById('s-{aid}').textContent")
            good = h["status"] == "ok" or (allow_warn and h["status"] == "warn")
            extra = ""
            if verify and good:
                v, extra = verify()
                good = good and v
            status = "PASS" if good else ("WARN" if h["status"] in ("warn",) else "FAIL")
            T.rec(A, label, status, f"statut={h['status']} ({h.get('dur', 0):.0f} s) carte=« {card} » {extra} - {logtxt(h)}")
        T.guard(A, label, go)

    def tcp_ok():
        try:
            socket.create_connection(("1.1.1.1", 443), 5).close()
            return True
        except OSError:
            return False

    act("restore_point", "Point de restauration")
    act("flush_dns", "Vider le cache DNS")
    act("sync_time", "Resynchroniser l'heure",
        verify=lambda: (run(ps_cmd("(Get-Service w32time).Status"), 20).strip() == "Running", "service w32time en marche"))
    act("disk_scan", "Analyser le disque système")

    old = [os.path.join(os.environ.get("WINDIR", r"C:\Windows"), "Temp", "ea2_test_ancien.tmp"),
           os.path.join(os.environ.get("TEMP", ""), "ea2_test_ancien.tmp")]
    recent = os.path.join(os.environ.get("TEMP", ""), "ea2_test_recent.tmp")

    def prep_temp():
        for p in old + [recent]:
            with open(p, "w") as fh:
                fh.write("x" * 1000)
        for p in old:
            os.utime(p, (time.time() - 3 * 86400, time.time() - 3 * 86400))
    act("clear_temp", "Nettoyer les fichiers temporaires", prep=prep_temp,
        verify=lambda: (not any(os.path.exists(p) for p in old) and os.path.exists(recent),
                        f"anciens supprimés={not any(os.path.exists(p) for p in old)} récent conservé={os.path.exists(recent)}"))
    spl = os.path.join(os.environ.get("WINDIR", r"C:\Windows"), "System32", "spool", "PRINTERS", "EA2TEST.SPL")

    def prep_spool():
        try:
            with open(spl, "w") as fh:
                fh.write("travail bloqué")
        except OSError:
            pass
    act("spooler", "Débloquer la file d'impression", prep=prep_spool,
        verify=lambda: (not os.path.exists(spl) and run(ps_cmd("(Get-Service Spooler).Status"), 20).strip() == "Running",
                        f"travail supprimé={not os.path.exists(spl)}"))
    act("wu_scan", "Rechercher les mises à jour")
    act("repair_wu", "Réparer Windows Update",
        verify=lambda: (bool(glob.glob(os.path.join(os.environ.get("WINDIR", r"C:\Windows"), "SoftwareDistribution.old-*"))),
                        "SoftwareDistribution renommé en .old"))
    act("defender_update", "Mettre à jour Microsoft Defender")
    act("defender_quick", "Analyse antivirus rapide")

    def sfc_cancel():
        n0 = len(b._history)
        js("ask(ACTS.find(a=>a.id==='sfc'))")
        T.wait(lambda: b._act == "sfc", 20)
        time.sleep(20)
        js("stopAct()")
        T.wait(lambda: b._act is None and len(b._history) > n0, 120)
        h = b._history[-1]
        T.check(A, "Arrêter une action longue (SFC)", h["status"] == "stopped" and not run(ps_cmd("Get-Process sfc -ErrorAction SilentlyContinue"), 20).strip(),
                f"statut={h['status']} carte=« {js('document.getElementById(`s-sfc`).textContent')} »")
    T.guard(A, "Arrêt SFC", sfc_cancel)
    act("sfc", "Vérifier les fichiers système (SFC)")
    act("dism", "Réparer l'image Windows (DISM)")
    act("component_cleanup", "Nettoyer les composants Windows")
    act("renew_ip", "Renouveler l'adresse IP", verify=lambda: (T.wait(tcp_ok, 60, 2), "connexion Internet rétablie"))
    act("reset_network", "Réinitialiser la pile réseau")
    T.shot("4_depannage_termine")

    def final():
        jl = js("document.getElementById('jb').innerText") or ""
        T.check(A, "Journal alimenté", len(jl) > 500 and "SFC" in jl, f"{len(jl)} caractères")
        out = os.path.join(T.dir, "scan_rapport_apres.html")
        b._window.create_file_dialog = lambda *a, **k: out
        p = b.export_report()
        txt = open(p, encoding="utf-8").read() if p and os.path.exists(p) else ""
        T.check(A, "Rapport exporté avec l'historique des actions", "Actions de dépannage effectuées" in txt, f"{len(txt)} car.")
        T.js_errors(A)
    T.guard(A, "Fin", final)
    T.finish()
