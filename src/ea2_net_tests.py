# -*- coding: utf-8 -*-
"""Tests complets d'E-A2 Net (mode --fulltest DOSSIER)."""
import os
import re
import time

from ea2ui import TestKit


def run_full(b):
    T = TestKit(b._args.fulltest, "net", b)
    try:
        b._window.maximize()
    except Exception:
        pass
    T.wait(lambda: T.js("typeof INFO!=='undefined' && INFO!==null") is True, 60)
    js = T.js

    # ------------------------------------------------------------------ démarrage
    A = "Démarrage"

    def start():
        info = b.info()
        T.check(A, "Interfaces réseau détectées", len(info["ifs"]) > 0, [(i["name"], i["net"]) for i in info["ifs"]])
        T.check(A, "Passerelle par défaut détectée", bool(info["gw"]), info["gw"])
        T.check(A, "En-tête (poste, IP, passerelle)", info["host"] in (js("document.getElementById('host').textContent") or ""),
                js("document.getElementById('host').textContent"))
        T.check(A, "Plage du scan pré-remplie", bool(js("document.getElementById('cidr').value")), js("document.getElementById('cidr').value"))
    T.guard(A, "Démarrage", start)

    # ------------------------------------------------------------------ réseau local
    A = "Réseau local"

    def lan():
        r = b.lan_start("pas-une-plage")
        T.check(A, "Plage invalide refusée avec message", "invalide" in (r.get("error") or ""), r)
        r = b.lan_start("10.0.0.0/16")
        T.check(A, "Plage trop grande (> /22) refusée", "trop grande" in (r.get("error") or ""), r)
        js("tab('lan')")
        js("lanStart()")
        T.wait(lambda: b._scanning, 10)
        r2 = b.lan_start(js("document.getElementById('cidr').value"))
        T.check(A, "Second scan refusé pendant un scan", "déjà" in (r2.get("error") or ""), r2)
        ok = T.wait(lambda: b._lan_done.is_set() and not b._scanning, 400)
        T.check(A, "Scan terminé", ok, f"{len(b._found)} appareil(s)")
        time.sleep(1.5)
        rows = js("document.querySelectorAll('#lanT tbody tr').length")
        T.check(A, "Au moins un appareil trouvé", len(b._found) >= 1, sorted(b._found))
        T.check(A, "Tableau = appareils trouvés", rows == len(b._found), f"lignes={rows} trouvés={len(b._found)}")
        types = {ip: h["type"] for ip, h in b._found.items()}
        T.check(A, "Ce poste identifié", "Ce poste" in types.values(), types)
        gw = b.info()["gw"]
        if gw in b._found:
            T.check(A, "Passerelle identifiée", types[gw] == "Passerelle / box", types[gw])
            T.check(A, "Adresse MAC de la passerelle (ARP)", bool(b._found[gw]["mac"]), b._found[gw]["mac"])
        else:
            T.rec(A, "Passerelle dans la plage scannée", "WARN", f"passerelle {gw} absente des résultats")
        phase = js("document.getElementById('lanPhase').textContent")
        T.check(A, "Message de fin de scan", "terminé" in (phase or "").lower(), phase)
        details = "; ".join(f"{h['ip']} {h['type']} {h['vendor'][:20]} {h['name'][:20]} ports={h['ports']}" for h in b._found.values())
        T.rec(A, "Détail des appareils", "INFO", details)
        T.shot("1_reseau_local")
        # filtre
        js("document.getElementById('lanFilter').value='Ce poste';lanFilter()")
        vis = js("[...document.querySelectorAll('#lanT tbody tr')].filter(r=>r.style.display!=='none').length")
        T.check(A, "Filtre de recherche", vis == 1, f"lignes visibles={vis}")
        js("document.getElementById('lanFilter').value='';lanFilter()")
        # export CSV (boîte d'enregistrement simulée)
        out = os.path.join(T.dir, "net_export.csv")
        b._window.create_file_dialog = lambda *a, **k: out
        js("lanCsv()")
        T.wait(lambda: os.path.exists(out), 15)
        if os.path.exists(out):
            with open(out, encoding="utf-8-sig") as fh:
                lines = fh.read().splitlines()
            T.check(A, "Export CSV (en-tête + une ligne par appareil)", len(lines) == len(b._found) + 1 and lines[0].startswith("IP;"),
                    f"{len(lines)} lignes : {lines[:2]}")
        else:
            T.check(A, "Export CSV", False, "fichier non créé")
        # arrêt d'un scan
        js("lanStart()")
        time.sleep(2)
        js("lanStop()")
        ok = T.wait(lambda: b._lan_done.is_set() and not b._scanning, 60)
        phase = js("document.getElementById('lanPhase').textContent") or ""
        T.check(A, "Arrêt d'un scan en cours", ok and "arrêté" in phase.lower(), phase)
        js("lanStart()")
        T.wait(lambda: b._lan_done.is_set() and not b._scanning, 400)
    T.guard(A, "Réseau local", lan)

    # ------------------------------------------------------------------ ping
    A = "Ping"

    def ping():
        r = b.ping_start("nom-inexistant-ea2.invalid")
        T.check(A, "Nom introuvable signalé", "résoudre" in (r.get("error") or ""), r)
        js("tab('ping');document.getElementById('pTarget').value=INFO.gw||'1.1.1.1';document.getElementById('pInt').value='500';pingStart()")
        time.sleep(7)
        js("pingStop()")
        n1 = len(b._pings)
        ok = [p for p in b._pings if p["rtt"] is not None]
        T.check(A, "Ping continu vers la passerelle (0,5 s)", n1 >= 10 and len(ok) >= n1 - 1, f"{len(ok)}/{n1} réponses, rtt={[p['rtt'] for p in b._pings[:6]]}")
        time.sleep(2)
        T.check(A, "Arrêt du ping", len(b._pings) <= n1 + 1, f"avant={n1} après={len(b._pings)}")
        st = js("document.getElementById('pStats').innerText") or ""
        T.check(A, "Statistiques affichées", "ENVOY" in st.upper() and "GIGUE" in st.upper(), st.replace("\n", " | "))
        T.check(A, "Graphe dessiné", js("document.getElementById('pc').width>0") is True)
        T.shot("2_ping")
        js("document.getElementById('pTarget').value='192.0.2.1';document.getElementById('pInt').value='500';pingStart()")
        time.sleep(6)
        js("pingStop()")
        T.check(A, "Hôte injoignable : toutes les réponses en échec", b._pings and all(p["rtt"] is None for p in b._pings),
                [(p["seq"], p["err"]) for p in b._pings[:5]])
        st = js("document.getElementById('pStats').innerText") or ""
        T.check(A, "Pertes à 100 % affichées", "100 %" in st, st.replace("\n", " | "))
        js("document.getElementById('pTarget').value='google.fr';pingStart()")
        time.sleep(4)
        js("pingStop()")
        ok = [p for p in b._pings if p["rtt"] is not None]
        T.check(A, "Ping d'un nom de domaine (google.fr)", len(ok) >= 2, f"{len(ok)}/{len(b._pings)}")
    T.guard(A, "Ping", ping)

    # ------------------------------------------------------------------ traceroute
    A = "Traceroute"

    def trace():
        r = b.trace_start("nom-inexistant-ea2.invalid")
        T.check(A, "Nom introuvable signalé", "résoudre" in (r.get("error") or ""), r)
        js("tab('trace');document.getElementById('tTarget').value='1.1.1.1';traceStart()")
        b._trace_done.clear()
        ok = T.wait(lambda: b._trace_done.is_set(), 200)
        hops = list(b._hops)
        T.check(A, "Traceroute terminé", ok, f"{len(hops)} sauts")
        last = hops[-1]["ip"] if hops else ""
        if last == "1.1.1.1":
            T.check(A, "Destination 1.1.1.1 atteinte", True, f"{len(hops)} sauts")
        else:
            T.rec(A, "Destination 1.1.1.1 atteinte", "WARN", f"dernier saut : {last!r} (ICMP filtré par le NAT de la VM ?)")
        T.check(A, "Premier saut = passerelle", bool(hops) and hops[0]["ip"] == b.info()["gw"], hops[0] if hops else None)
        time.sleep(4)
        rows = js("document.querySelectorAll('#trT tbody tr').length")
        T.check(A, "Tableau = sauts", rows == len(hops), f"lignes={rows} sauts={len(hops)}")
        names = js("[...document.querySelectorAll('#trT tbody td:nth-child(3)')].map(e=>e.textContent).join(' | ')") or ""
        T.check(A, "Noms des routeurs résolus (plus de « … »)", "…" not in names, names)
        info = js("document.getElementById('tInfo').textContent")
        T.check(A, "Message de fin", "atteinte" in (info or ""), info)
        T.shot("3_traceroute")
        b._trace_done.clear()
        js("document.getElementById('tTarget').value='192.0.2.1';traceStart()")
        time.sleep(5)
        js("traceStop()")
        ok = T.wait(lambda: b._trace_done.is_set(), 30)
        T.check(A, "Arrêt d'un traceroute en cours", ok and len(b._hops) < 30, f"{len(b._hops)} sauts avant arrêt")
        T.check(A, "Bouton Lancer réactivé après arrêt", js("document.getElementById('bTr').disabled") is False)
    T.guard(A, "Traceroute", trace)

    # ------------------------------------------------------------------ DNS
    A = "DNS"

    def dns():
        r = b.dns_run("", "A")
        T.check(A, "Nom vide refusé", "Saisir" in (r.get("error") or ""), r)
        cases = [("A", "google.com"), ("AAAA", "google.com"), ("MX", "gmail.com"), ("TXT", "google.com"), ("NS", "google.com"),
                 ("SOA", "google.com"), ("CNAME", "www.github.com"), ("SRV", "_imaps._tcp.gmail.com"), ("PTR", "8.8.8.8")]
        for qt, name in cases:
            r = b.dns_run(name, qt)
            good = [x for x in r["rows"] if x["ok"] and any(a["type"] == qt for a in x["answers"])]
            T.check(A, f"Requête {qt} ({name})", len(good) >= 2,
                    "; ".join(f"{x['server']}={x['rcode']} {x['ms']}ms {[a['value'][:40] for a in x['answers']][:2]}" for x in r["rows"]))
        r = b.dns_run("google.com", "A", "1.0.0.1")
        T.check(A, "Serveur personnalisé ajouté", any(x["role"] == "Personnalisé" and x["ok"] for x in r["rows"]), [x["server"] for x in r["rows"]])
        r = b.dns_run("nexistepas-ea2-test.invalid", "A")
        T.check(A, "Domaine inexistant (NXDOMAIN)", any(x["rcode"] == "Nom inexistant" for x in r["rows"]), [(x["server"], x["rcode"]) for x in r["rows"]])
        t = time.time()
        r = b.dns_run("google.com", "A", "192.0.2.53")
        row = next((x for x in r["rows"] if x["server"] == "192.0.2.53"), {})
        T.check(A, "Serveur muet : « Pas de réponse » en moins de 4 s", row.get("rcode") == "Pas de réponse" and time.time() - t < 4.5,
                f"{row.get('rcode')} en {time.time() - t:.1f} s")
        js("tab('dns');document.getElementById('dName').value='emedia-services.fr';document.getElementById('dType').value='MX';"
           "document.getElementById('dCustom').value='';dnsRun()")
        ok = T.wait(lambda: js("document.querySelectorAll('#dT tbody tr').length") >= 3, 20)
        T.check(A, "Résultats affichés dans le tableau", ok, js("document.getElementById('dT').innerText"))
        T.shot("4_dns")
    T.guard(A, "DNS", dns)

    # ------------------------------------------------------------------ calculateur
    A = "Calculateur IP"

    def calc():
        js("tab('calc')")
        cases = [("192.168.1.10/24", ["192.168.1.0/24", "255.255.255.0", "192.168.1.1", "192.168.1.254", "192.168.1.255"], "254"),
                 ("10.20.30.40 255.255.252.0", ["10.20.28.0/22", "10.20.31.255"], "1022"),
                 ("172.16.5.4/30", ["172.16.5.4/30", "172.16.5.5", "172.16.5.6"], "2"),
                 ("100.64.3.1/10", ["CGNAT"], None), ("8.8.8.8/32", ["8.8.8.8/32", "Publique"], "1")]
        for inp, subs, hosts in cases:
            out = js(f"document.getElementById('cIn').value='{inp}';calc();document.getElementById('cOut').innerText") or ""
            ok = all(s in out for s in subs)
            if hosts:
                m = re.search(r"UTILISABLES\s*([\d\s\u202f\u00a0]+)", out.upper())
                ok = ok and m and re.sub(r"\D", "", m.group(1)) == hosts
            T.check(A, f"Calcul {inp}", ok, out.replace("\n", " | ")[:400])
        for bad in ("192.168.1.300/24", "10.0.0.1 255.0.255.0", "abc"):
            err = js(f"document.getElementById('cIn').value='{bad}';calc();document.getElementById('cErr').textContent")
            T.check(A, f"Saisie invalide refusée ({bad})", "non reconnu" in (err or ""), err)
        n = js("document.getElementById('cIn').value='192.168.0.0/24';calc();document.getElementById('cSub').value='26';calcSub();"
               "document.querySelectorAll('#cSubT tbody tr').length")
        T.check(A, "Découpage /24 en /26 = 4 sous-réseaux", n == 4, n)
        T.shot("5_calculateur")
    T.guard(A, "Calculateur", calc)

    # ------------------------------------------------------------------ Wi-Fi
    A = "Wi-Fi"

    def wifi():
        w = b.wifi(True)
        if w["nets"]:
            T.check(A, "Réseaux Wi-Fi listés", True, f"{len(w['nets'])} réseaux")
        else:
            T.rec(A, "Réseaux Wi-Fi listés", "INFO", f"aucun (VM sans carte Wi-Fi) - message : {w['error']!r}")
            T.check(A, "Message clair sans carte Wi-Fi", bool(w["error"]), w["error"])
        js("tab('wifi');WIFI=null;wifiRefresh(false)")
        ok = T.wait(lambda: "point(s)" in (js("document.getElementById('wInfo').textContent") or ""), 30)
        T.check(A, "Onglet Wi-Fi actualisé", ok, js("document.getElementById('wInfo').textContent"))
        T.shot("6_wifi")
    T.guard(A, "Wi-Fi", wifi)

    # ------------------------------------------------------------------ interface
    A = "Interface"

    def ui():
        for t in ("lan", "ping", "trace", "dns", "calc", "wifi"):
            js(f"tab('{t}')")
            T.check(A, f"Onglet « {t} » affiché", js(f"document.getElementById('v-{t}').classList.contains('on')") is True)
        T.check(A, "Lien non web refusé", b.open_url("file:///C:/Windows") is False)
        T.check(A, "Police Open Sans chargée", js("document.fonts.check(\"600 16px 'Open Sans'\")") is True)
        T.js_errors(A)
    T.guard(A, "Interface", ui)
    T.finish()
