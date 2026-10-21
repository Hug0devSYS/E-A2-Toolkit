# -*- coding: utf-8 -*-
"""E-A2 Net - outils réseau du technicien (E-Media Services / A2MI)."""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import ipaddress
import json
import socket
import threading
import time

from ea2ui import IS_WIN, BridgeBase, build_page, run_window, finish
from ea2_net_core import (ICMP_STATUS, IP_TTL_EXPIRED, PORTS, arp, device_type, dns_query, icmp, interfaces,
                          netbios, rdns, resolve_target, system_dns, tcp_ports, vendor, wifi_scan, QTYPES)

APP, VERSION = "E-A2 Net", "1.0.0"


class NetBridge(BridgeBase):
    def __init__(self, args):
        super().__init__()
        self._args = args
        self._scanning = False
        self._scan_stop = False
        self._ping_id = 0
        self._trace_id = 0
        self._dns_sys = None
        self._found = {}
        self._pings = []
        self._hops = []
        self._lan_done = threading.Event()
        self._trace_done = threading.Event()

    # ---- informations ---------------------------------------------------- #
    def info(self):
        ifs, gw = interfaces()
        return {"ifs": ifs, "gw": gw, "host": socket.gethostname(), "win": IS_WIN, "version": VERSION,
                "ports": {str(k): v for k, v in PORTS.items()}, "qtypes": list(QTYPES)}

    def ready(self):
        if getattr(self._args, "fulltest", ""):
            threading.Thread(target=self._fulltest, daemon=True).start()
        elif self._args.selftest:
            threading.Thread(target=self._selftest, daemon=True).start()
        return True

    # ---- scan du réseau local -------------------------------------------- #
    def lan_start(self, cidr, ports=True):
        try:
            net = ipaddress.IPv4Network((cidr or "").strip(), strict=False)
        except ValueError:
            return {"error": "Plage invalide. Exemple : 192.168.1.0/24"}
        if net.num_addresses > 1024:
            return {"error": "Plage trop grande : 1024 adresses maximum (/22)."}
        if self._scanning:
            return {"error": "Un scan est déjà en cours."}
        self._scanning, self._scan_stop = True, False
        self._lan_done.clear()
        threading.Thread(target=self._lan, args=(net, bool(ports)), daemon=True).start()
        return {"ok": True, "total": max(1, net.num_addresses - (2 if net.prefixlen < 31 else 0))}

    def lan_stop(self):
        self._scan_stop = True
        return True

    def _lan(self, net, with_ports):
        t0 = time.time()
        try:
            ifs, gw = interfaces()
            local = {i["ip"]: i for i in ifs}
            hosts = [str(h) for h in (net.hosts() if net.prefixlen < 31 else net)]
            found = {}
            self._found = found

            def disc(ip):
                if self._scan_stop:
                    return None
                if ip in local:
                    return {"ip": ip, "mac": local[ip]["mac"], "rtt": 0.0, "icmp": True}
                mac = arp(ip)
                st, rtt, _ = icmp(ip, 700)
                if not mac and st != 0:
                    return None
                return {"ip": ip, "mac": mac or "", "rtt": rtt if st == 0 else None, "icmp": st == 0}

            done = 0
            with cf.ThreadPoolExecutor(max_workers=96) as ex:
                futs = [ex.submit(disc, ip) for ip in hosts]
                for fut in cf.as_completed(futs):
                    done += 1
                    r = fut.result()
                    if r:
                        r.update(vendor=vendor(r["mac"]), name="", ports=[], group="")
                        r["type"] = device_type(r["ip"], r["mac"], r["vendor"], [], gw, local)
                        found[r["ip"]] = r
                        self._js("lanHost", r)
                    if done % 8 == 0 or done == len(hosts):
                        self._js("lanProg", {"done": done, "total": len(hosts), "phase": "Découverte des appareils",
                                             "n": len(found)})
            if not self._scan_stop and found:
                todo = list(found.values())
                n2 = 0

                def enrich(r):
                    if self._scan_stop:
                        return r
                    if r["ip"] not in local:
                        nb, grp = netbios(r["ip"])
                        r["name"] = nb or rdns(r["ip"])
                        if grp:
                            r["group"] = grp
                    else:
                        r["name"] = socket.gethostname()
                    if with_ports and r["ip"] not in local:
                        r["ports"] = tcp_ports(r["ip"])
                    r["type"] = device_type(r["ip"], r["mac"], r["vendor"], r["ports"], gw, local, r["name"])
                    return r
                with cf.ThreadPoolExecutor(max_workers=16) as ex:
                    for fut in cf.as_completed([ex.submit(enrich, r) for r in todo]):
                        n2 += 1
                        self._js("lanHost", fut.result())
                        self._js("lanProg", {"done": n2, "total": len(todo), "phase": "Identification (noms, ports)",
                                             "n": len(found)})
            self._js("lanDone", {"n": len(found), "dur": round(time.time() - t0), "stopped": self._scan_stop})
        except Exception as e:
            self._js("lanDone", {"n": len(self._found), "dur": round(time.time() - t0), "error": f"{type(e).__name__}: {e}"})
        finally:
            self._scanning = False
            self._lan_done.set()

    # ---- ping continu ----------------------------------------------------- #
    def ping_start(self, target, interval=1000):
        ip = resolve_target(target)
        if not ip:
            return {"error": f"Impossible de résoudre « {target} »."}
        self._ping_id += 1
        pid = self._ping_id
        self._pings = []
        interval = max(200, min(10000, int(interval or 1000)))

        def loop():
            seq = 0
            while self._ping_id == pid:
                seq += 1
                t0 = time.time()
                st, rtt, frm = icmp(ip, 2000)
                pt = {"pid": pid, "seq": seq, "rtt": rtt if st == 0 else None,
                      "err": "" if st == 0 else ICMP_STATUS.get(st, "délai dépassé"), "from": frm or "", "t": time.strftime("%H:%M:%S")}
                self._pings.append(pt)
                if self._ping_id != pid:
                    break
                self._js("pingPt", pt)
                time.sleep(max(0.0, interval / 1000 - (time.time() - t0)))
        threading.Thread(target=loop, daemon=True).start()
        return {"ok": True, "ip": ip, "pid": pid}

    def ping_stop(self):
        self._ping_id += 1
        return True

    # ---- traceroute -------------------------------------------------------- #
    def trace_start(self, target, maxhops=30):
        ip = resolve_target(target)
        if not ip:
            return {"error": f"Impossible de résoudre « {target} »."}
        self._trace_id += 1
        tid = self._trace_id
        self._hops = []
        self._trace_done.clear()

        def loop():
            reached = False
            names = cf.ThreadPoolExecutor(max_workers=4)
            try:
                for ttl in range(1, int(maxhops) + 1):
                    if self._trace_id != tid:
                        break
                    rtts, addr = [], None
                    for _ in range(3):
                        st, rtt, a = icmp(ip, 1500, ttl=ttl)
                        if a:
                            addr = a
                        rtts.append(rtt if st in (0, IP_TTL_EXPIRED) else None)
                        if st == 0:
                            reached = True
                    hop = {"tid": tid, "ttl": ttl, "ip": addr or "", "rtts": rtts}
                    self._hops.append(hop)
                    self._js("hop", hop)
                    if addr:
                        names.submit(lambda t=ttl, a=addr: self._js("hopName", {"tid": tid, "ttl": t, "name": rdns(a)}))
                    if reached or addr == ip:
                        reached = True
                        break
            finally:
                names.shutdown(wait=True)
                self._js("traceDone", {"tid": tid, "reached": reached, "ip": ip})
                self._trace_done.set()
        threading.Thread(target=loop, daemon=True).start()
        return {"ok": True, "ip": ip, "tid": tid}

    def trace_stop(self):
        self._trace_id += 1
        return True

    # ---- DNS --------------------------------------------------------------- #
    def dns_servers(self):
        if self._dns_sys is None:
            self._dns_sys = system_dns()
        return self._dns_sys

    def dns_run(self, name, qtype="A", custom=""):
        name = (name or "").strip()
        if not name:
            return {"error": "Saisir un nom de domaine."}
        if qtype not in QTYPES:
            qtype = "A"
        servers = [(s, "DNS du poste") for s in self.dns_servers()]
        servers += [("1.1.1.1", "Cloudflare"), ("8.8.8.8", "Google"), ("9.9.9.9", "Quad9")]
        for c in (custom or "").replace(";", ",").split(","):
            c = c.strip()
            if c:
                servers.insert(0, (c, "Personnalisé"))
        seen, uniq = set(), []
        for s, r in servers:
            if s not in seen:
                seen.add(s)
                uniq.append((s, r))
        with cf.ThreadPoolExecutor(max_workers=len(uniq)) as ex:
            res = list(ex.map(lambda sr: {"server": sr[0], "role": sr[1], **dns_query(sr[0], name, qtype)}, uniq))
        return {"name": name, "qtype": qtype, "rows": res}

    # ---- Wi-Fi ------------------------------------------------------------- #
    def wifi(self, fresh=True):
        return wifi_scan(bool(fresh))

    # ---- autotest ------------------------------------------------------------ #
    def _fulltest(self):
        import ea2_net_tests
        ea2_net_tests.run_full(self)

    def _selftest(self):
        log = []
        try:
            time.sleep(1.5)
            info = self.info()
            log.append(f"ifs={[(i['name'], i['net']) for i in info['ifs']]} gw={info['gw']}")
            cidr = self._eval("document.getElementById('cidr').value")
            log.append(f"cidr_ui={cidr}")
            self._eval("lanStart()")
            self._lan_done.wait(240)
            time.sleep(1)
            rows = self._eval("document.querySelectorAll('#lanT tbody tr').length")
            log.append(f"lan: trouvés={len(self._found)} lignes_ui={rows}")
            for r in sorted(self._found.values(), key=lambda r: tuple(int(x) for x in r['ip'].split('.')))[:25]:
                log.append(f"  {r['ip']:<15} {r['mac']:<17} {r['type']:<26} {r['vendor'][:24]:<24} {r['name'][:24]:<24} "
                           f"ports={r['ports']} rtt={r['rtt']}")
            self._eval("tab('ping');document.getElementById('pTarget').value=INFO.gw||'1.1.1.1';pingStart()")
            time.sleep(6.5)
            self._eval("pingStop()")
            log.append(f"ping: {[(p['seq'], p['rtt'], p['err']) for p in self._pings]} stats_ui={self._eval('document.getElementById(`pStats`).innerText')!r}")
            self._eval("tab('trace');document.getElementById('tTarget').value='1.1.1.1';traceStart()")
            self._trace_done.wait(120)
            time.sleep(2)
            log.append(f"trace: {[(h['ttl'], h['ip'], h['rtts']) for h in self._hops]}")
            log.append(f"trace_ui_rows={self._eval('document.querySelectorAll(`#trT tbody tr`).length')} "
                       f"noms={self._eval('[...document.querySelectorAll(`#trT tbody td:nth-child(3)`)].map(e=>e.textContent).join(` | `)')!r}")
            d = self.dns_run("google.com", "MX")
            log.append(f"dns: {[(r['server'], r['rcode'], r['ms'], [a['value'] for a in r['answers']][:2]) for r in d['rows']]}")
            w = self.wifi(True)
            log.append(f"wifi: err={w['error']!r} nets={len(w['nets'])} cur={w['cur']}")
            for n in w["nets"][:8]:
                log.append(f"  {n['ssid'][:24]:<24} {n['bssid']} {n['signal']}% ch={n['channel']} {n['band']} {n['auth']} {n['radio']}")
            self._eval("tab('wifi');wifiRefresh(false)")
            time.sleep(4)
            log.append(f"wifi_ui_rows={self._eval('document.querySelectorAll(`#wT tbody tr`).length')} "
                       f"reco={self._eval('document.getElementById(`wReco`).innerText')!r}")
            self._eval("tab('calc');document.getElementById('cIn').value='192.168.10.77/26';calc()")
            calc_js = "document.getElementById('cOut').innerText.replace(/\\n/g,' ; ')"
            log.append("calc=" + repr(self._eval(calc_js)))
            fonts = self._eval("document.fonts.check(\"600 16px 'Open Sans'\")")
            log.append(f"openSans={fonts}")
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
.lanbar{margin-top:14px}.lanmeta{display:flex;justify-content:space-between;margin-top:6px;font-size:12px;color:var(--mut)}
.stats{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:20px}
.t-ce{color:#111;background:var(--or)}.t-gw{color:#8fd4e8;background:rgba(73,182,214,.15)}.t-pc{color:var(--okt);background:rgba(0,172,172,.13)}
.t-pr{color:#e3b6ff;background:rgba(170,110,230,.16)}.t-nas{color:#ffd38a;background:rgba(245,156,26,.15)}.t-cam{color:#ff8a87;background:rgba(255,91,87,.13)}
.t-net{color:#8fd4e8;background:rgba(73,182,214,.13)}.t-mob{color:#c3ccd5;background:rgba(255,255,255,.08)}
canvas.ch{width:100%;display:block;background:rgba(0,0,0,.25);border:1px solid var(--line);border-radius:4px}
.pl{font:12px/1.6 Consolas,monospace;color:#cfd8e0;max-height:220px;overflow:auto}.pl .bad{color:#ff8a87}
.sig{display:inline-block;width:70px;height:7px;background:rgba(255,255,255,.1);border-radius:4px;overflow:hidden;vertical-align:1px;margin-right:8px}
.sig i{display:block;height:100%}
tr.me td{background:rgba(245,156,26,.08)}
.kv{display:grid;grid-template-columns:repeat(auto-fill,minmax(210px,1fr));gap:10px}
.kv div{background:var(--panel2);border:1px solid var(--line);border-radius:5px;padding:10px 12px}
.kv span{display:block;font-size:10.5px;letter-spacing:.1em;text-transform:uppercase;color:var(--mut);font-weight:700}
.kv b{font-weight:600;color:#fff;font-size:14.5px;word-break:break-word}
.qk{cursor:pointer}.qk:hover{background:var(--or);color:#111}
"""

BODY = r"""
<section class="view" id="v-lan">
 <div class="card"><h2>Scanner le réseau local</h2>
  <p class="lead">Liste tous les appareils du réseau, même ceux qui bloquent le ping (détection ARP), avec leur nom, constructeur, type et ports ouverts.</p>
  <div class="row"><select id="ifSel" style="min-width:320px"></select><input type="text" id="cidr" style="width:180px" placeholder="192.168.1.0/24">
   <label class="row" style="gap:7px;font-size:13px"><input type="checkbox" id="optPorts" checked>Ports ouverts</label>
   <button class="btn" id="bLan" onclick="lanStart()">Scanner</button><button class="btn2" id="bLanStop" onclick="lanStop()" disabled>Arrêter</button></div>
  <div class="bar lanbar"><i id="lanBar"></i></div><div class="lanmeta"><span id="lanPhase">Prêt</span><span id="lanCount"></span></div>
 </div>
 <div class="stats" id="lanStats"></div>
 <div class="card"><div class="row" style="justify-content:space-between;margin-bottom:12px"><h2 style="margin:0">Appareils détectés</h2>
   <div class="row"><input type="text" id="lanFilter" placeholder="Filtrer (IP, nom, type, constructeur…)" style="width:280px" oninput="lanFilter()">
   <button class="btn2" onclick="lanCsv()">Exporter CSV</button></div></div>
  <div class="tw"><table class="t" id="lanT"><thead><tr><th>Adresse IP</th><th>Nom</th><th>Type</th><th>Constructeur</th><th>Adresse MAC</th><th>Ports ouverts</th><th>Latence</th></tr></thead>
  <tbody></tbody></table><div class="empty" id="lanEmpty">Lance un scan pour afficher les appareils du réseau.</div></div></div>
</section>
<section class="view" id="v-ping">
 <div class="card"><h2>Ping continu</h2><p class="lead">Mesure la latence et les pertes en continu : idéal pour prouver une coupure intermittente (Wi-Fi, box, lien FAI).</p>
  <div class="row"><input type="text" id="pTarget" style="width:260px" placeholder="IP ou nom (ex. 8.8.8.8)">
   <select id="pInt"><option value="500">toutes les 0,5 s</option><option value="1000" selected>toutes les 1 s</option><option value="2000">toutes les 2 s</option><option value="5000">toutes les 5 s</option></select>
   <button class="btn" id="bPing" onclick="pingStart()">Démarrer</button><button class="btn2" id="bPingStop" onclick="pingStop()" disabled>Arrêter</button>
   <span class="host" id="pIp"></span></div>
  <div class="row" style="margin-top:12px;gap:6px" id="pQuick"></div>
 </div>
 <div class="stats" id="pStats"></div>
 <div class="card"><h2>Latence (ms)</h2><canvas class="ch" id="pc" height="270"></canvas>
  <h3>Dernières réponses</h3><div class="pl" id="pLog"></div></div>
</section>
<section class="view" id="v-trace">
 <div class="card"><h2>Traceroute</h2><p class="lead">Affiche chaque routeur traversé jusqu'à la destination, pour localiser où la latence ou la coupure apparaît.</p>
  <div class="row"><input type="text" id="tTarget" style="width:300px" placeholder="IP ou nom (ex. google.fr)" value="1.1.1.1">
   <button class="btn" id="bTr" onclick="traceStart()">Lancer</button><button class="btn2" id="bTrStop" onclick="traceStop()" disabled>Arrêter</button>
   <span class="host" id="tInfo"></span></div></div>
 <div class="card"><div class="tw"><table class="t" id="trT"><thead><tr><th>Saut</th><th>Adresse IP</th><th>Nom</th><th>Essai 1</th><th>Essai 2</th><th>Essai 3</th><th>Moyenne</th></tr></thead><tbody></tbody></table>
  <div class="empty" id="trEmpty">Saisis une destination puis lance le traceroute.</div></div></div>
</section>
<section class="view" id="v-dns">
 <div class="card"><h2>Test DNS</h2><p class="lead">Interroge en parallèle les DNS du poste et les DNS publics, et compare temps de réponse et résultats.</p>
  <div class="row"><input type="text" id="dName" style="width:280px" placeholder="nom de domaine (ex. emedia-services.fr)" value="emedia-services.fr">
   <select id="dType"></select><input type="text" id="dCustom" style="width:200px" placeholder="Serveur en plus (facultatif)">
   <button class="btn" id="bDns" onclick="dnsRun()">Interroger</button><span class="host" id="dInfo"></span></div></div>
 <div id="dNote"></div>
 <div class="card"><div class="tw"><table class="t" id="dT"><thead><tr><th>Serveur</th><th>Rôle</th><th>Temps</th><th>Statut</th><th>Réponses</th></tr></thead><tbody></tbody></table>
  <div class="empty" id="dEmpty">Les résultats s'affichent ici.</div></div></div>
</section>
<section class="view" id="v-calc">
 <div class="card"><h2>Calculateur IP</h2><p class="lead">Saisis une adresse avec son préfixe (192.168.1.10/24) ou son masque (192.168.1.10 255.255.255.0).</p>
  <div class="row"><input type="text" id="cIn" style="width:320px" value="192.168.1.10/24" oninput="calc()"><span class="host" id="cErr"></span></div></div>
 <div class="card"><h2>Résultat</h2><div class="kv" id="cOut"></div></div>
 <div class="card"><h2>Découper en sous-réseaux</h2>
  <div class="row"><span class="lbl">Nouveau préfixe</span><select id="cSub" onchange="calcSub()"></select><span class="host" id="cSubInfo"></span></div>
  <div class="tw" style="margin-top:12px"><table class="t" id="cSubT"><thead><tr><th>#</th><th>Réseau</th><th>Première IP</th><th>Dernière IP</th><th>Broadcast</th><th>Hôtes</th></tr></thead><tbody></tbody></table></div></div>
</section>
<section class="view" id="v-wifi">
 <div class="card"><div class="row" style="justify-content:space-between"><h2 style="margin:0">Wi-Fi à proximité</h2>
   <div class="row"><span class="host" id="wInfo"></span><button class="btn" id="bWifi" onclick="wifiRefresh(true)">Actualiser</button></div></div>
  <div id="wErr" style="margin-top:14px"></div><div class="kv" id="wCur" style="margin-top:14px"></div></div>
 <div class="card"><h2>Occupation des canaux</h2><div id="wReco" class="note" style="display:none"></div>
  <h3>2,4 GHz</h3><canvas class="ch" id="w24" height="220"></canvas><h3>5 GHz</h3><canvas class="ch" id="w5" height="220"></canvas></div>
 <div class="card"><h2>Réseaux détectés</h2><div class="tw"><table class="t" id="wT"><thead><tr><th>SSID</th><th>BSSID</th><th>Signal</th><th>Canal</th><th>Bande</th><th>Sécurité</th><th>Norme</th></tr></thead><tbody></tbody></table>
  <div class="empty" id="wEmpty">Clique sur Actualiser pour lister les réseaux.</div></div></div>
</section>
"""

JS = r"""
let INFO=null;
const ipn=ip=>ip.split('.').reduce((a,b)=>a*256+(+b),0);
window.addEventListener('pywebviewready',()=>{api().info().then(i=>{INFO=i;initInfo()}).finally(()=>api().ready())});
function initInfo(){const f0=INFO.ifs[0];$('#host').textContent=INFO.host+(f0?'  ·  '+f0.ip:'')+(INFO.gw?'  ·  passerelle '+INFO.gw:'');
 const s=$('#ifSel');s.innerHTML='';
 for(const f of INFO.ifs){const o=el('option',null,f.name+'  —  '+f.ip+'/'+f.prefix+(f.virtual?'  (virtuelle)':'')+(f.gw?'  ★':''));
  o.value=f.prefix<22?f.ip.split('.').slice(0,3).join('.')+'.0/24':f.net;s.append(o)}
 if(!INFO.ifs.length){s.append(el('option',null,'Aucune interface réseau active'))}else $('#cidr').value=s.value;
 s.onchange=()=>{$('#cidr').value=s.value};
 const q=$('#pQuick');q.innerHTML='';q.append(el('span','lbl','Raccourcis'));
 for(const [t,l] of [[INFO.gw,'Passerelle'],['1.1.1.1','Cloudflare'],['8.8.8.8','Google DNS'],['google.fr','google.fr']])if(t){
  const c=el('span','chip qk',l+(l!==t?'  '+t:''));c.onclick=()=>{$('#pTarget').value=t;pingStart()};q.append(c)}
 $('#pTarget').value=INFO.gw||'1.1.1.1';
 const dt=$('#dType');for(const t of INFO.qtypes)dt.append(Object.assign(el('option',null,t),{value:t}));
 if(!INFO.win)$('#lanEmpty').textContent='Le scan réseau utilise les API Windows : disponible sous Windows uniquement.';
 calc();drawPing();lanStats()}
/* ---------- réseau local ---------- */
const LAN={};let lanRun=false;
const TCLS=t=>t==='Ce poste'?'t-ce':t.startsWith('Passerelle')?'t-gw':t.startsWith('Ordinateur')?'t-pc':t==='Imprimante'?'t-pr':t==='NAS'?'t-nas':
 t==='Caméra'?'t-cam':t.startsWith('Équipement')||t.startsWith('Téléphonie')?'t-net':'t-mob';
const WEB={80:'http',443:'https',5000:'http',5001:'https',8080:'http',8443:'https',631:'http'};
function lanStart(){const a=api();if(!a)return;for(const k in LAN)delete LAN[k];$('#lanT tbody').innerHTML='';lanStats();
 a.lan_start($('#cidr').value,$('#optPorts').checked).then(r=>{if(r.error){toast(r.error);return}
  lanRun=true;$('#bLan').disabled=true;$('#bLanStop').disabled=false;$('#lanBar').style.width='1%';
  $('#lanPhase').innerHTML='<span class="spin"></span>Découverte des appareils…';$('#lanEmpty').style.display='none'})}
function lanStop(){const a=api();if(a)a.lan_stop();$('#lanPhase').textContent='Arrêt en cours…'}
function lanRow(h){const tr=el('tr');tr.dataset.ip=h.ip;
 const c1=el('td','mono',h.ip);if(INFO&&h.ip===INFO.gw)c1.append(' ',el('span','chip t-gw','passerelle'));tr.append(c1);
 const nm=el('td',null,h.name||'—');if(h.group)nm.append(el('div','host',h.group));tr.append(nm);
 const ty=el('td');ty.append(el('span','chip '+TCLS(h.type),h.type));tr.append(ty);
 tr.append(el('td',null,h.vendor||'—'),el('td','mono',h.mac||'—'));
 const pc=el('td');for(const p of h.ports){const lab=INFO.ports[p]||p;
  if(WEB[p]){const a=el('a','chip port',lab);a.title='Ouvrir '+WEB[p]+'://'+h.ip+':'+p;a.onclick=()=>api().open_url(WEB[p]+'://'+h.ip+([80,443].includes(p)?'':':'+p));pc.append(a)}
  else pc.append(el('span','chip',lab))}
 if(!h.ports.length)pc.textContent='—';tr.append(pc);
 const lt=el('td');if(h.rtt===null){const c=el('span','chip c-warn','pas de ping');c.title='Répond en ARP mais bloque le ping (pare-feu)';lt.append(c)}else lt.textContent=(h.rtt<1?'<1':Math.round(h.rtt))+' ms';
 tr.append(lt);return tr}
E.lanHost=h=>{LAN[h.ip]=h;const tb=$('#lanT tbody');const old=tb.querySelector('tr[data-ip="'+h.ip+'"]');const row=lanRow(h);
 if(old)old.replaceWith(row);else{const n=ipn(h.ip);const nxt=[...tb.children].find(r=>ipn(r.dataset.ip)>n);tb.insertBefore(row,nxt||null)}
 lanFilter();lanStats()};
E.lanProg=p=>{$('#lanBar').style.width=Math.max(1,100*p.done/p.total)+'%';$('#lanPhase').innerHTML='<span class="spin"></span>'+p.phase+'…';
 $('#lanCount').textContent=p.done+' / '+p.total};
E.lanDone=d=>{lanRun=false;$('#bLan').disabled=false;$('#bLanStop').disabled=true;$('#lanBar').style.width='100%';
 $('#lanPhase').textContent=d.error?('Erreur : '+d.error):(d.stopped?'Scan arrêté':'Scan terminé')+' : '+d.n+' appareil(s) en '+d.dur+' s';
 $('#lanCount').textContent='';if(!d.n)$('#lanEmpty').style.display='block',$('#lanEmpty').textContent='Aucun appareil trouvé.'};
function lanStats(){const v=Object.values(LAN);const cnt=f=>v.filter(f).length;const s=$('#lanStats');s.innerHTML='';
 for(const [n,l] of [[v.length,'Appareils'],[cnt(h=>h.type.startsWith('Ordinateur')||h.type==='Ce poste'),'Ordinateurs'],[cnt(h=>h.type==='Imprimante'),'Imprimantes'],
  [cnt(h=>h.type.startsWith('Passerelle')||h.type.startsWith('Équipement')),'Équipements réseau'],[cnt(h=>h.type==='NAS'),'NAS'],
  [cnt(h=>h.rtt===null),'Bloquent le ping']]){const b=el('div','stat');b.append(el('b',null,n),el('span',null,l));s.append(b)}}
function lanFilter(){const q=$('#lanFilter').value.toLowerCase();for(const tr of $('#lanT tbody').children)tr.style.display=!q||tr.innerText.toLowerCase().includes(q)?'':'none'}
function lanCsv(){const v=Object.values(LAN).sort((a,b)=>ipn(a.ip)-ipn(b.ip));if(!v.length){toast('Aucun appareil à exporter.');return}
 const q=s=>'"'+String(s??'').replace(/"/g,'""')+'"';const lines=['IP;Nom;Groupe;Type;Constructeur;MAC;Ports;Latence ms'];
 for(const h of v)lines.push([h.ip,h.name,h.group,h.type,h.vendor,h.mac,h.ports.map(p=>p+' '+(INFO.ports[p]||'')).join(' / '),h.rtt??'pas de ping'].map(q).join(';'));
 api().save_text('Reseau_'+$('#cidr').value.replace(/[\/.]/g,'-')+'.csv',lines.join('\r\n'),'Fichier CSV').then(p=>{if(p)toast('Exporté : '+p)})}
/* ---------- ping ---------- */
let PP=[],pPid=0;
function pingStart(){const a=api();if(!a)return;const t=$('#pTarget').value.trim();if(!t)return;
 a.ping_start(t,+$('#pInt').value).then(r=>{if(r.error){toast(r.error);return}pPid=r.pid;PP=[];$('#pLog').innerHTML='';
  $('#pIp').textContent=t===r.ip?'':'→ '+r.ip;$('#bPing').textContent='Redémarrer';$('#bPingStop').disabled=false;pingStats();drawPing()})}
function pingStop(){const a=api();if(a)a.ping_stop();pPid=0;$('#bPingStop').disabled=true;$('#bPing').textContent='Démarrer'}
E.pingPt=p=>{if(p.pid!==pPid)return;PP.push(p);if(PP.length>3600)PP.shift();
 const d=el('div',p.rtt===null?'bad':null,p.t+'   seq='+p.seq+'   '+(p.rtt===null?p.err+(p.from?' ('+p.from+')':''):(p.rtt<1?'<1':Math.round(p.rtt))+' ms'));
 const L=$('#pLog');L.prepend(d);while(L.childElementCount>60)L.lastElementChild.remove();pingStats();drawPing()};
function pingStats(){const ok=PP.filter(p=>p.rtt!==null).map(p=>p.rtt);const n=PP.length;const loss=n?100*(n-ok.length)/n:0;
 let jit=0;for(let i=1;i<ok.length;i++)jit+=Math.abs(ok[i]-ok[i-1]);jit=ok.length>1?jit/(ok.length-1):0;
 const f=v=>ok.length?(v<1?'<1':v.toFixed(v<10?1:0))+' ms':'—';const s=$('#pStats');s.innerHTML='';
 for(const [v,l,c] of [[n,'Envoyés'],[ok.length,'Reçus'],[loss.toFixed(loss&&loss<10?1:0)+' %','Pertes',loss?'#ff8a87':null],
  [f(Math.min(...ok)),'Minimum'],[f(ok.reduce((a,b)=>a+b,0)/(ok.length||1)),'Moyenne'],[f(Math.max(...ok)),'Maximum'],[f(jit),'Gigue']]){
  const b=el('div','stat');const bb=el('b',null,v);if(c)bb.style.color=c;b.append(bb,el('span',null,l));s.append(b)}}
function canvasCtx(cv){if(!cv._h)cv._h=+cv.getAttribute('height')||220;const dpr=window.devicePixelRatio||1;const w=Math.max(300,cv.getBoundingClientRect().width);
 cv.width=Math.round(w*dpr);cv.height=Math.round(cv._h*dpr);cv.style.height=cv._h+'px';const g=cv.getContext('2d');g.setTransform(dpr,0,0,dpr,0,0);return [g,w,cv._h]}
function drawPing(){const cv=$('#pc');if(!cv.offsetParent)return;const [g,W,H]=canvasCtx(cv);g.clearRect(0,0,W,H);
 const pts=PP.slice(-150),L=44,R=12,T=14,B=24,w=W-L-R,h=H-T-B;const ok=pts.filter(p=>p.rtt!==null).map(p=>p.rtt);
 let mx=Math.max(10,...ok)*1.2;const st=[1,2,5,10,20,50,100,200,500,1000,2000].find(s=>mx/s<=5)||500;mx=Math.ceil(mx/st)*st;
 g.font='11px Open Sans';g.fillStyle='#93a1b0';g.strokeStyle='rgba(255,255,255,.07)';g.lineWidth=1;
 for(let v=0;v<=mx;v+=st){const y=T+h-h*v/mx;g.beginPath();g.moveTo(L,y);g.lineTo(W-R,y);g.stroke();g.fillText(v,6,y+4)}
 if(!pts.length){g.fillText('En attente de mesures…',L+10,T+h/2);return}
 const x=i=>L+(pts.length<2?w/2:w*i/(150-1));g.strokeStyle='#f59c1a';g.lineWidth=2;g.beginPath();let pen=false;
 pts.forEach((p,i)=>{if(p.rtt===null){pen=false;return}const y=T+h-h*Math.min(p.rtt,mx)/mx;if(!pen){g.moveTo(x(i),y);pen=true}else g.lineTo(x(i),y)});g.stroke();
 g.fillStyle='rgba(245,156,26,.9)';pts.forEach((p,i)=>{if(p.rtt!==null){g.beginPath();g.arc(x(i),T+h-h*Math.min(p.rtt,mx)/mx,2,0,7);g.fill()}});
 g.fillStyle='#ff5b57';pts.forEach((p,i)=>{if(p.rtt===null)g.fillRect(x(i)-1.5,T,3,h)})}
window.addEventListener('resize',()=>{drawPing();if(WIFI)drawWifi()});
window.onTab=v=>{if(v==='ping')setTimeout(drawPing,30);if(v==='wifi'){setTimeout(()=>{if(WIFI)drawWifi()},30);if(!WIFI&&!wBusy)wifiRefresh(false)}};
/* ---------- traceroute ---------- */
let tTid=0;
function traceStart(){const a=api();if(!a)return;$('#trT tbody').innerHTML='';
 a.trace_start($('#tTarget').value).then(r=>{if(r.error){toast(r.error);return}tTid=r.tid;$('#trEmpty').style.display='none';
  $('#tInfo').innerHTML='<span class="spin"></span>Vers '+r.ip+'…';$('#bTr').disabled=true;$('#bTrStop').disabled=false})}
function traceStop(){const a=api();if(a)a.trace_stop()}
const ms=v=>v===null?'*':(v<1?'<1':Math.round(v))+' ms';
E.hop=h=>{if(h.tid!==tTid)return;const tr=el('tr');tr.dataset.ttl=h.ttl;const ok=h.rtts.filter(v=>v!==null);
 tr.append(el('td',null,h.ttl),el('td','mono',h.ip||'*'),el('td',null,h.ip?'…':'(pas de réponse)'));
 for(const v of h.rtts){const c=el('td',null,ms(v));if(v===null)c.style.color='#93a1b0';tr.append(c)}
 const av=ok.length?ok.reduce((a,b)=>a+b,0)/ok.length:null;const c=el('td');c.append(el('span','chip '+(av===null?'':av<30?'c-ok':av<100?'c-warn':'c-crit'),av===null?'—':ms(av)));tr.append(c);
 $('#trT tbody').append(tr)};
E.hopName=n=>{if(n.tid!==tTid)return;const tr=$('#trT tbody tr[data-ttl="'+n.ttl+'"]');if(tr)tr.children[2].textContent=n.name||'—'};
E.traceDone=d=>{if(d.tid!==tTid)return;$('#bTr').disabled=false;$('#bTrStop').disabled=true;
 $('#tInfo').textContent=d.reached?'Destination '+d.ip+' atteinte.':'Destination non atteinte (arrêt ou filtrage ICMP).'};
/* ---------- DNS ---------- */
function dnsRun(){const a=api();if(!a)return;$('#bDns').disabled=true;$('#dInfo').innerHTML='<span class="spin"></span>Interrogation…';
 a.dns_run($('#dName').value,$('#dType').value,$('#dCustom').value).then(r=>{$('#bDns').disabled=false;$('#dInfo').textContent='';
  if(r.error){toast(r.error);return}const tb=$('#dT tbody');tb.innerHTML='';$('#dEmpty').style.display='none';const sets=new Set();
  for(const x of r.rows){const tr=el('tr');tr.append(el('td','mono',x.server),el('td',null,x.role));
   const t=el('td');t.append(el('span','chip '+(x.ms===null?'c-crit':x.ms<50?'c-ok':x.ms<200?'c-warn':'c-crit'),x.ms===null?'—':x.ms+' ms'));tr.append(t);
   const s=el('td');s.append(el('span','chip '+(x.ok?'c-ok':'c-crit'),x.rcode));tr.append(s);
   const an=el('td','mono');if(!x.answers.length)an.textContent=x.ok?'(aucun enregistrement '+r.qtype+')':'—';
   for(const a of x.answers){const d=el('div',null,(a.type!==r.qtype?a.type+'  ':'')+a.value+(a.ttl?'   (TTL '+a.ttl+' s)':''));an.append(d)}
   tr.append(an);tb.append(tr);if(x.ok)sets.add(x.answers.filter(a=>a.type===r.qtype).map(a=>a.value).sort().join('|'))}
  const n=$('#dNote');n.innerHTML='';
  if(r.rows.every(x=>!x.ok&&x.ms===null))n.append(el('div','note w','Aucun serveur DNS ne répond : vérifier la connexion ou un filtrage du port 53.'));
  else if(sets.size>1)n.append(el('div','note','Les serveurs ne renvoient pas tous la même réponse : normal pour les grands sites (CDN), suspect sinon (filtrage DNS, DNS de la box, propagation en cours).'))})}
/* ---------- calculateur IP ---------- */
const ip2n=s=>{const p=s.split('.');if(p.length!==4||p.some(x=>!/^\d{1,3}$/.test(x)||+x>255))return null;return p.reduce((a,b)=>a*256+(+b),0)};
const n2ip=n=>[24,16,8,0].map(s=>Math.floor(n/2**s)%256).join('.');
const bin=n=>[24,16,8,0].map(s=>(Math.floor(n/2**s)%256).toString(2).padStart(8,'0')).join('.');
let CNET=null;
function calc(){const v=$('#cIn').value.trim().replace(/\s+/g,' ');let ip,pre;let m=v.match(/^([\d.]+)\s*\/\s*(\d{1,2})$/);
 if(m){ip=ip2n(m[1]);pre=+m[2]}else if((m=v.match(/^([\d.]+)\s+([\d.]+)$/))){ip=ip2n(m[1]);const mk=ip2n(m[2]);
  if(mk!==null){const b=mk.toString(2).padStart(32,'0');pre=b.indexOf('0')<0?32:b.indexOf('0');if(/01/.test(b))pre=null}}
 else if((m=v.match(/^([\d.]+)$/))){ip=ip2n(m[1]);pre=null;if(ip!==null){const a=Math.floor(ip/2**24);pre=a<128?8:a<192?16:24}}
 const out=$('#cOut');out.innerHTML='';if(ip==null||pre==null||pre>32){$('#cErr').textContent='Format non reconnu';CNET=null;calcSub();return}
 $('#cErr').textContent='';const size=2**(32-pre),net=Math.floor(ip/size)*size,bc=net+size-1,mask=2**32-size;
 const hosts=pre>=31?size:size-2,first=pre>=31?net:net+1,last=pre>=31?bc:bc-1;const a=Math.floor(net/2**24),b=Math.floor(net/2**16)%256;
 const priv=a===10||(a===172&&b>=16&&b<=31)||(a===192&&b===168)?'Privée (RFC 1918)':a===100&&b>=64&&b<=127?'CGNAT (RFC 6598)':a===127?'Boucle locale':a===169&&b===254?'APIPA (lien local)':a>=224&&a<=239?'Multicast':'Publique';
 const cls=a<128?'A':a<192?'B':a<224?'C':a<240?'D':'E';
 for(const [k,val] of [['Adresse',n2ip(ip)],['Réseau',n2ip(net)+'/'+pre],['Masque',n2ip(mask)],['Masque inverse (wildcard)',n2ip(2**32-1-mask)],
  ['Première adresse utilisable',n2ip(first)],['Dernière adresse utilisable',n2ip(last)],['Broadcast',pre>=31?'—':n2ip(bc)],['Hôtes utilisables',hosts.toLocaleString('fr-FR')],
  ['Type',priv],['Classe historique',cls],['Masque (binaire)',bin(mask)],['Adresse (binaire)',bin(ip)]]){const d=el('div');d.append(el('span',null,k),el('b',null,val));out.append(d)}
 CNET={net,pre};const s=$('#cSub');const keep=+s.value;s.innerHTML='';for(let p=pre+1;p<=Math.min(30,pre+10);p++){const o=el('option',null,'/'+p+'  ('+2**(p-pre)+' sous-réseaux de '+(2**(32-p)-2)+' hôtes)');o.value=p;s.append(o)}
 if(keep&&keep>pre&&keep<=Math.min(30,pre+10))s.value=keep;calcSub()}
function calcSub(){const tb=$('#cSubT tbody');tb.innerHTML='';if(!CNET||!$('#cSub').value){$('#cSubInfo').textContent='';return}
 const p=+$('#cSub').value,sz=2**(32-p),n=2**(p-CNET.pre);$('#cSubInfo').textContent=n>256?'256 premiers affichés sur '+n:'';
 for(let i=0;i<Math.min(n,256);i++){const s=CNET.net+i*sz;const tr=el('tr');
  tr.append(el('td',null,i+1),el('td','mono',n2ip(s)+'/'+p),el('td','mono',n2ip(s+1)),el('td','mono',n2ip(s+sz-2)),el('td','mono',n2ip(s+sz-1)),el('td',null,sz-2));tb.append(tr)}}
/* ---------- Wi-Fi ---------- */
let WIFI=null,wBusy=false;
function wifiRefresh(fresh){const a=api();if(!a||wBusy)return;wBusy=true;$('#bWifi').disabled=true;$('#wInfo').innerHTML='<span class="spin"></span>'+(fresh?'Recherche des réseaux (5 s)…':'Lecture…');
 a.wifi(fresh).then(r=>{WIFI=r;wBusy=false;$('#bWifi').disabled=false;$('#wInfo').textContent=r.nets.length+' point(s) d\'accès';renderWifi()})}
const secCls=a=>{a=(a||'').toLowerCase();return /ouvert|open/.test(a)?'c-crit':/wep/.test(a)?'c-crit':/wpa3/.test(a)?'c-ok':/wpa2/.test(a)?'c-ok':'c-warn'};
const sigCol=s=>s>=70?'#3fd6d6':s>=45?'#ffd900':'#ff5b57';
function renderWifi(){const r=WIFI;const e=$('#wErr');e.innerHTML='';if(r.error)e.append(el('div','note w',r.error));
 const c=$('#wCur');c.innerHTML='';if(r.cur){for(const [k,v] of [['Connecté à',r.cur.ssid],['Signal',r.cur.signal],['Canal / bande',r.cur.channel+(r.cur.band?'  ·  '+r.cur.band:'')],
  ['Norme',r.cur.radio],['Débit réception / émission',(r.cur.rx||'?')+' / '+(r.cur.tx||'?')+' Mbit/s'],['Sécurité',r.cur.auth],['BSSID',r.cur.bssid],['Carte',r.cur.iface]])if(v){const d=el('div');d.append(el('span',null,k),el('b',null,v));c.append(d)}}
 const tb=$('#wT tbody');tb.innerHTML='';$('#wEmpty').style.display=r.nets.length?'none':'block';
 for(const n of r.nets){const tr=el('tr');if(r.cur&&n.bssid===r.cur.bssid)tr.className='me';
  tr.append(el('td',null,n.ssid),el('td','mono',n.bssid));const s=el('td');const bar=el('span','sig');const i=el('i');i.style.width=n.signal+'%';i.style.background=sigCol(n.signal);
  bar.append(i);s.append(bar,document.createTextNode(n.signal+' %  ('+n.dbm+' dBm)'));tr.append(s,el('td',null,n.channel),el('td',null,n.band));
  const sc=el('td');sc.append(el('span','chip '+secCls(n.auth),n.auth||'?'));tr.append(sc,el('td',null,n.radio));tb.append(tr)}
 wifiReco();drawWifi()}
function wifiReco(){const r=WIFI,box=$('#wReco');const me=r.cur?r.cur.bssid:'';const n24=r.nets.filter(n=>n.band==='2,4 GHz'&&n.bssid!==me);
 const score=c=>n24.reduce((s,n)=>{const d=Math.abs((+n.channel||0)-c);return s+(d<5?(5-d)/5*Math.max(5,n.signal):0)},0);
 const best=[1,6,11].sort((a,b)=>score(a)-score(b))[0];const n5=r.nets.filter(n=>n.band==='5 GHz'&&n.bssid!==me);
 const cnt5=c=>n5.filter(n=>+n.channel===c).length;const best5=[36,40,44,48,149,153,157,161].sort((a,b)=>cnt5(a)-cnt5(b))[0];
 if(!r.nets.length){box.style.display='none';return}box.style.display='block';
 let t='Canal conseillé en 2,4 GHz : '+best+' (le moins encombré parmi 1, 6 et 11).  En 5 GHz : '+best5+'.';
 if(r.cur&&r.cur.band==='2,4 GHz'&&+r.cur.channel!==best&&score(+r.cur.channel)>score(best)*1.5)t+='  Le réseau actuel (canal '+r.cur.channel+') est sur un canal plus chargé.';
 box.textContent=t}
function drawWifi(){if(!WIFI)return;drawBand($('#w24'),WIFI.nets.filter(n=>n.band==='2,4 GHz'),1,13,2.2,[1,2,3,4,5,6,7,8,9,10,11,12,13]);
 drawBand($('#w5'),WIFI.nets.filter(n=>n.band==='5 GHz'),32,169,2,[36,44,52,60,100,108,116,124,132,140,149,157,165])}
const PAL=['#f59c1a','#3fd6d6','#49b6d6','#ffd900','#ff8a87','#b48cff','#7ee081','#ff9ff3','#ffffff','#f6c177'];
function drawBand(cv,nets,c0,c1,half,ticks){if(!cv.offsetParent)return;const [g,W,H]=canvasCtx(cv);g.clearRect(0,0,W,H);const L=40,R=14,T=12,B=26,w=W-L-R,h=H-T-B;
 const x=c=>L+w*(c-(c0-half))/((c1+half)-(c0-half));const y=s=>T+h-h*s/100;g.font='11px Open Sans';g.strokeStyle='rgba(255,255,255,.07)';g.fillStyle='#93a1b0';
 for(const s of [0,25,50,75,100]){g.beginPath();g.moveTo(L,y(s));g.lineTo(W-R,y(s));g.stroke();g.fillText(s+'%',4,y(s)+4)}
 for(const c of ticks){g.fillText(c,x(c)-(c>9?7:3),H-8)}
 if(!nets.length){g.fillText('Aucun réseau sur cette bande',L+12,T+h/2);return}
 const me=WIFI.cur?WIFI.cur.bssid:'';const used={};nets.slice().sort((a,b)=>b.signal-a.signal).forEach((n,i)=>{const ch=+n.channel;if(!ch)return;const col=n.bssid===me?'#f59c1a':PAL[(i+1)%PAL.length];
  g.beginPath();g.moveTo(x(ch-half),y(0));g.bezierCurveTo(x(ch-half*0.55),y(n.signal*4/3),x(ch+half*0.55),y(n.signal*4/3),x(ch+half),y(0));
  g.fillStyle=col+(n.bssid===me?'55':'22');g.fill();g.strokeStyle=col;g.lineWidth=n.bssid===me?2.5:1.3;g.stroke();
  g.fillStyle=col;const lab=n.ssid.length>16?n.ssid.slice(0,15)+'…':n.ssid;const ly=Math.max(T+10,y(n.signal)-6,used[ch]===undefined?-1e9:used[ch]+13);used[ch]=ly;g.fillText(lab,x(ch)-g.measureText(lab).width/2,ly)})}
"""


def main():
    ap = argparse.ArgumentParser(description=f"{APP} - outils réseau")
    ap.add_argument("--selftest", default="", help=argparse.SUPPRESS)
    ap.add_argument("--fulltest", default="", help=argparse.SUPPRESS)
    args = ap.parse_args()
    html = build_page("net", APP, "Outils réseau",
                      [("lan", "Réseau local"), ("ping", "Ping"), ("trace", "Traceroute"), ("dns", "DNS"),
                       ("calc", "Calculateur IP"), ("wifi", "Wi-Fi")],
                      BODY, CSS, JS, nav="<span class='host' id='host'></span>")
    return run_window(f"{APP} - Outils réseau", html, NetBridge(args))


if __name__ == "__main__":
    finish(main())
