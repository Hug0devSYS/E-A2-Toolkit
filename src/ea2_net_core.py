# -*- coding: utf-8 -*-
"""Moteur réseau d'E-A2 Net : ICMP, ARP, NetBIOS, DNS, ports, constructeurs, Wi-Fi."""
from __future__ import annotations

import concurrent.futures as cf
import ipaddress
import random
import re
import socket
import struct
import subprocess
import time

from ea2ui import IS_WIN, NO_WINDOW, run, ps_cmd

try:
    import psutil  # type: ignore
except Exception:  # pragma: no cover
    psutil = None

# --------------------------------------------------------------------------- #
# ICMP (IcmpSendEcho, sans droits admin) et ARP (SendARP)
# --------------------------------------------------------------------------- #
if IS_WIN:
    import ctypes
    from ctypes import wintypes

    class IP_OPTION_INFORMATION(ctypes.Structure):
        _fields_ = [("Ttl", ctypes.c_ubyte), ("Tos", ctypes.c_ubyte), ("Flags", ctypes.c_ubyte),
                    ("OptionsSize", ctypes.c_ubyte), ("OptionsData", ctypes.c_void_p)]

    class ICMP_ECHO_REPLY(ctypes.Structure):
        _fields_ = [("Address", ctypes.c_ulong), ("Status", ctypes.c_ulong), ("RoundTripTime", ctypes.c_ulong),
                    ("DataSize", ctypes.c_ushort), ("Reserved", ctypes.c_ushort), ("Data", ctypes.c_void_p),
                    ("Options", IP_OPTION_INFORMATION)]

    _ip = ctypes.WinDLL("iphlpapi", use_last_error=True)
    _ip.IcmpCreateFile.restype = wintypes.HANDLE
    _ip.IcmpCloseHandle.argtypes = [wintypes.HANDLE]
    _ip.IcmpSendEcho.argtypes = [wintypes.HANDLE, ctypes.c_ulong, ctypes.c_void_p, ctypes.c_ushort,
                                 ctypes.POINTER(IP_OPTION_INFORMATION), ctypes.c_void_p, ctypes.c_ulong, ctypes.c_ulong]
    _ip.IcmpSendEcho.restype = ctypes.c_ulong
    _ip.SendARP.argtypes = [ctypes.c_ulong, ctypes.c_ulong, ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong)]
    _ip.SendARP.restype = ctypes.c_ulong

IP_SUCCESS, IP_TTL_EXPIRED = 0, 11013
ICMP_STATUS = {11002: "réseau injoignable", 11003: "hôte injoignable", 11004: "protocole injoignable",
               11005: "port injoignable", 11010: "délai dépassé", 11013: "TTL expiré", 11050: "échec"}


def _ip2ul(ip):
    return int.from_bytes(socket.inet_aton(ip), "little")


def _ul2ip(v):
    return socket.inet_ntoa(int(v).to_bytes(4, "little"))


def icmp(ip, timeout_ms=1000, ttl=128, size=32):
    """Renvoie (status, rtt_ms|None, adresse_répondante|None)."""
    if not IS_WIN:
        return _icmp_fallback(ip, timeout_ms)
    h = _ip.IcmpCreateFile()
    try:
        data = ctypes.create_string_buffer(b"E-A2Net" + b"x" * max(0, size - 7), size)
        opts = IP_OPTION_INFORMATION(ttl, 0, 0, 0, None)
        rsize = ctypes.sizeof(ICMP_ECHO_REPLY) + size + 64
        rbuf = ctypes.create_string_buffer(rsize)
        t0 = time.perf_counter()
        n = _ip.IcmpSendEcho(h, _ip2ul(ip), data, size, ctypes.byref(opts), rbuf, rsize, int(timeout_ms))
        el = (time.perf_counter() - t0) * 1000
        rep = ICMP_ECHO_REPLY.from_buffer(rbuf)
        if rep.Address and (n or rep.Status in (IP_TTL_EXPIRED, 11003, 11002)):
            rtt = rep.RoundTripTime if rep.RoundTripTime > 0 else round(min(el, 0.9), 2)
            return rep.Status, float(rtt), _ul2ip(rep.Address)
        return 11010, None, None
    finally:
        _ip.IcmpCloseHandle(h)


def _icmp_fallback(ip, timeout_ms):
    out = run(["ping", "-c", "1", "-W", str(max(1, int(timeout_ms / 1000))), ip], timeout=timeout_ms / 1000 + 3)
    m = re.search(r"time[=<]([\d.]+)", out)
    return (0, float(m.group(1)), ip) if m else (11010, None, None)


def arp(ip):
    """MAC via ARP (répond même si le pare-feu bloque le ping), ou None."""
    if not IS_WIN:
        return None
    mac = (ctypes.c_ubyte * 8)()
    ln = ctypes.c_ulong(6)
    if _ip.SendARP(_ip2ul(ip), 0, ctypes.byref(mac), ctypes.byref(ln)) == 0 and ln.value == 6:
        m = ":".join(f"{b:02X}" for b in mac[:6])
        return None if m in ("00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF") else m
    return None


# --------------------------------------------------------------------------- #
# Interfaces, passerelle, DNS système
# --------------------------------------------------------------------------- #
def default_gateway():
    try:
        if IS_WIN:
            out = run(["route", "print", "-4", "0.0.0.0"], timeout=10)
            best = None
            for m in re.finditer(r"^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+)",
                                 out, re.M):
                if best is None or int(m.group(3)) < best[2]:
                    best = (m.group(1), m.group(2), int(m.group(3)))
            return best[0] if best else None
        out = run(["ip", "route", "show", "default"], timeout=5)
        m = re.search(r"default via (\S+)", out)
        return m.group(1) if m else None
    except Exception:
        return None


VIRTUAL = re.compile(r"virtualbox|vmware|hyper-v|vethernet|loopback|docker|wsl|tailscale|zerotier|vpn|tap-|tun|wintun|npcap", re.I)


def interfaces():
    gw = default_gateway()
    res = []
    if not psutil:
        return res, gw
    stats = psutil.net_if_stats()
    for name, addrs in psutil.net_if_addrs().items():
        st = stats.get(name)
        if not st or not st.isup:
            continue
        mac = next((a.address.replace("-", ":").upper() for a in addrs if a.family == getattr(psutil, "AF_LINK", -1)), "")
        for a in addrs:
            if a.family != socket.AF_INET or not a.netmask:
                continue
            if a.address.startswith(("127.", "169.254.")):
                continue
            try:
                net = ipaddress.IPv4Network(f"{a.address}/{a.netmask}", strict=False)
            except ValueError:
                continue
            res.append({"name": name, "ip": a.address, "mask": a.netmask, "prefix": net.prefixlen, "net": str(net),
                        "mac": mac, "speed": st.speed, "virtual": bool(VIRTUAL.search(name)),
                        "gw": bool(gw and ipaddress.IPv4Address(gw) in net)})
    res.sort(key=lambda r: (not r["gw"], r["virtual"], r["name"]))
    return res, gw


def system_dns():
    out = []
    if IS_WIN:
        txt = run(ps_cmd("Get-DnsClientServerAddress -AddressFamily IPv4 | ForEach-Object { $_.ServerAddresses } | "
                         "Select-Object -Unique"), timeout=20)
        out = re.findall(r"^\s*(\d+\.\d+\.\d+\.\d+)\s*$", txt, re.M)
    else:
        try:
            out = re.findall(r"^nameserver\s+(\d+\.\d+\.\d+\.\d+)", open("/etc/resolv.conf").read(), re.M)
        except Exception:
            pass
    seen = []
    for s in out:
        if s not in seen and not s.startswith("127."):
            seen.append(s)
    return seen


# --------------------------------------------------------------------------- #
# Constructeurs (base IEEE OUI compactée)
# --------------------------------------------------------------------------- #
_OUI = None


def vendor(mac):
    global _OUI
    if not mac:
        return ""
    if _OUI is None:
        try:
            import ea2_oui
            _OUI = ea2_oui.load()
        except Exception:
            _OUI = {}
    p = mac.replace(":", "").replace("-", "").upper()
    if len(p) >= 2 and int(p[1], 16) & 2:
        return "Adresse privée (aléatoire)"
    return _OUI.get(p[:6], "")


# --------------------------------------------------------------------------- #
# Noms : NetBIOS + DNS inverse
# --------------------------------------------------------------------------- #
def netbios(ip, timeout=0.8):
    tid = random.randint(0, 0xFFFF)
    pkt = struct.pack(">HHHHHH", tid, 0, 1, 0, 0, 0) + b"\x20" + b"CK" + b"A" * 30 + b"\x00" + struct.pack(">HH", 0x21, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(pkt, (ip, 137))
        data, _ = s.recvfrom(2048)
    except Exception:
        return None, None
    finally:
        s.close()
    try:
        off = 12
        if data[off] & 0xC0 == 0xC0:
            off += 2
        else:
            while data[off]:
                off += data[off] + 1
            off += 1
        off += 10
        n = data[off]
        off += 1
        name = group = None
        for _ in range(n):
            nm = data[off:off + 15].decode("latin-1").strip()
            suf, flags = data[off + 15], struct.unpack(">H", data[off + 16:off + 18])[0]
            off += 18
            if suf == 0x00 and not flags & 0x8000 and not name:
                name = nm
            elif suf == 0x00 and flags & 0x8000 and not group:
                group = nm
        return name, group
    except Exception:
        return None, None


def rdns(ip):
    try:
        n = socket.gethostbyaddr(ip)[0]
        return "" if n == ip else n
    except Exception:
        return ""


# --------------------------------------------------------------------------- #
# Ports et type d'appareil
# --------------------------------------------------------------------------- #
PORTS = {21: "FTP", 22: "SSH", 23: "Telnet", 53: "DNS", 80: "HTTP", 135: "RPC", 139: "NetBIOS", 443: "HTTPS",
         445: "SMB", 515: "LPD", 554: "RTSP", 631: "IPP", 3389: "RDP", 5000: "5000", 5001: "5001", 5900: "VNC",
         8080: "HTTP-8080", 8443: "HTTPS-8443", 9100: "Impr. RAW", 62078: "Apple"}
WEB = {80: "http", 443: "https", 5000: "http", 5001: "https", 8080: "http", 8443: "https", 631: "http"}


def tcp_ports(ip, ports=PORTS, timeout=0.45):
    found = []

    def probe(p):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            return p if s.connect_ex((ip, p)) == 0 else None
        except Exception:
            return None
        finally:
            s.close()
    with cf.ThreadPoolExecutor(max_workers=len(ports)) as ex:
        for r in ex.map(probe, ports):
            if r:
                found.append(r)
    return sorted(found)


_V = [
    ("Imprimante", r"\b(hewlett|hp inc|canon|epson|seiko epson|brother|xerox|kyocera|ricoh|lexmark|konica|sharp|oki data|zebra|dymo)"),
    ("NAS", r"synology|qnap|asustor|terramaster|western digital|buffalo|drobo"),
    ("Caméra", r"hikvision|dahua|axis comm|reolink|foscam|ezviz|uniview|hanwha|amcrest|annke"),
    ("Équipement réseau", r"ubiquiti|tp-link|netgear|cisco|aruba|mikrotik|routerboard|d-link|zyxel|tenda|linksys|juniper|fortinet|"
                          r"sagemcom|technicolor|arcadyan|huawei|zte|sercomm|freebox|free sas|bouygues|sfr|orange|nokia shanghai|"
                          r"avm|draytek|stormshield|ruckus|cambium|grandstream|engenius|edimax|watchguard|sophos"),
    ("Téléphonie IP", r"yealink|snom|polycom|gigaset|avaya|mitel|alcatel-lucent ent"),
    ("Apple", r"\bapple\b"),
    ("Multimédia / objet connecté", r"sonos|google|amazon|roku|samsung|lg electronics|sony|philips|signify|xiaomi|espressif|tuya|"
                                    r"nintendo|bose|denon|yamaha|chromecast|netatmo|nest labs|shelly|ring llc|tado|withings|vestel|tcl"),
    ("Raspberry Pi / Linux", r"raspberry"),
    ("Ordinateur", r"intel corp|dell|lenovo|asustek|micro-star|gigabyte|hewlett packard enterprise|acer|msi|realtek|liteon|azurewave|"
                   r"giga-byte|elitegroup|fujitsu|toshiba|clevo|framework|microsoft|cloud network technology|hon hai|foxconn|"
                   r"wistron|quanta|compal|pegatron|inventec|universal global scientific|chicony"),
]


_NAME = [("Imprimante", r"^(brn|brw|npi|epson|hp[0-9a-f]{6}|canon|kyocera|ricoh|xerox|printer|imprimante)"),
         ("NAS", r"(^|[-_.])nas([-_.\d]|$)|diskstation|synology|qnap"),
         ("Apple", r"iphone|ipad|macbook|imac|mac-mini|apple-tv|appletv|homepod"),
         ("Mobile", r"android|galaxy|redmi|pixel|oneplus|huawei-|honor-|oppo|xiaomi|smartphone"),
         ("Ordinateur Windows", r"^(desktop|laptop|pc|portable|poste)-|-pc(\.|$)"),
         ("Multimédia / objet connecté", r"chromecast|sonos|tv|freebox-player|roku|echo|alexa|nest|shelly|tasmota")]


def device_type(ip, mac, vend, ports, gw, local_ips, name=""):
    v = (vend or "").lower()
    nm = (name or "").lower()
    if ip in local_ips:
        return "Ce poste"
    if gw and ip == gw:
        return "Passerelle / box"
    for label, rx in _NAME:
        if nm and re.search(rx, nm):
            if label == "Ordinateur Windows" and 62078 in ports:
                continue
            return label
    if any(p in ports for p in (9100, 515, 631)):
        return "Imprimante"
    if 554 in ports:
        return "Caméra"
    for label, rx in _V:
        if re.search(rx, v):
            if label == "Ordinateur":
                if 3389 in ports or (135 in ports and 445 in ports):
                    return "Ordinateur Windows"
                if not any(p in ports for p in (135, 139, 445, 3389, 22, 5900)):
                    return "Ordinateur / carte réseau"
            return label
    if 62078 in ports:
        return "Apple"
    if 3389 in ports or (135 in ports and 445 in ports):
        return "Ordinateur Windows"
    if 5000 in ports and 5001 in ports:
        return "NAS"
    if "privée" in v:
        return "Mobile (MAC privée)"
    if 22 in ports:
        return "Linux / équipement"
    return "Inconnu"


# --------------------------------------------------------------------------- #
# Client DNS (A, AAAA, MX, TXT, CNAME, NS, SOA, PTR, SRV)
# --------------------------------------------------------------------------- #
QTYPES = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "MX": 15, "TXT": 16, "AAAA": 28, "SRV": 33}
RCODES = {0: "OK", 1: "Requête invalide", 2: "Échec serveur", 3: "Nom inexistant", 4: "Non supporté", 5: "Refusé"}


def _qname(name):
    out = b""
    for part in name.strip(".").split("."):
        b = part.encode("idna") if part else b""
        out += bytes([len(b)]) + b
    return out + b"\x00"


def _rname(data, off, depth=0):
    labels = []
    jumped, end = False, off
    while True:
        if depth > 20 or off >= len(data):
            break
        ln = data[off]
        if ln & 0xC0 == 0xC0:
            ptr = ((ln & 0x3F) << 8) | data[off + 1]
            if not jumped:
                end = off + 2
            jumped = True
            off = ptr
            depth += 1
            continue
        if ln == 0:
            if not jumped:
                end = off + 1
            break
        labels.append(data[off + 1:off + 1 + ln].decode("latin-1"))
        off += ln + 1
    return ".".join(labels), end


def dns_query(server, name, qtype="A", timeout=2.5):
    t = QTYPES[qtype]
    if qtype == "PTR":
        try:
            name = ipaddress.ip_address(name).reverse_pointer
        except ValueError:
            pass
    tid = random.randint(0, 0xFFFF)
    pkt = (struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 1) + _qname(name) + struct.pack(">HH", t, 1)
           + b"\x00" + struct.pack(">HHIH", 41, 4096, 0, 0))  # EDNS0 : réponses jusqu'à 4096 octets
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    t0 = time.perf_counter()
    try:
        s.sendto(pkt, (server, 53))
        while True:
            data, _ = s.recvfrom(4096)
            if struct.unpack(">H", data[:2])[0] == tid:
                break
    except socket.timeout:
        return {"ok": False, "ms": None, "rcode": "Pas de réponse", "answers": []}
    except Exception as e:
        return {"ok": False, "ms": None, "rcode": f"Erreur : {e}", "answers": []}
    finally:
        s.close()
    ms = (time.perf_counter() - t0) * 1000
    flags, qd, an = struct.unpack(">HHH", data[2:8])
    rc = flags & 0xF
    off = 12
    for _ in range(qd):
        _, off = _rname(data, off)
        off += 4
    answers = []
    for _ in range(an):
        try:
            _, off = _rname(data, off)
            rtype, _, ttl, rdl = struct.unpack(">HHIH", data[off:off + 10])
            off += 10
            rd = data[off:off + rdl]
            val = None
            if rtype == 1 and rdl == 4:
                val = socket.inet_ntoa(rd)
            elif rtype == 28 and rdl == 16:
                val = socket.inet_ntop(socket.AF_INET6, rd)
            elif rtype in (2, 5, 12):
                val = _rname(data, off)[0]
            elif rtype == 15:
                val = f"{struct.unpack('>H', rd[:2])[0]} {_rname(data, off + 2)[0]}"
            elif rtype == 16:
                parts, i = [], 0
                while i < len(rd):
                    ln = rd[i]
                    parts.append(rd[i + 1:i + 1 + ln].decode("utf-8", "replace"))
                    i += ln + 1
                val = "".join(parts)
            elif rtype == 33:
                pr, wt, pt = struct.unpack(">HHH", rd[:6])
                val = f"{pr} {wt} {pt} {_rname(data, off + 6)[0]}"
            elif rtype == 6:
                mn, o2 = _rname(data, off)
                rn, o3 = _rname(data, o2)
                serial = struct.unpack(">I", data[o3:o3 + 4])[0]
                val = f"{mn} {rn} (série {serial})"
            name_t = {v: k for k, v in QTYPES.items()}.get(rtype, str(rtype))
            if val is not None:
                answers.append({"type": name_t, "value": val, "ttl": ttl})
            off += rdl
        except Exception:
            break
    if flags & 0x0200:
        answers.append({"type": "!", "value": "Réponse tronquée (TC) : réponse complète en TCP non affichée", "ttl": 0})
    return {"ok": rc == 0, "ms": round(ms, 1), "rcode": RCODES.get(rc, f"Code {rc}"), "answers": answers}


def resolve_target(target):
    target = (target or "").strip()
    try:
        return str(ipaddress.IPv4Address(target))
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(target, None, socket.AF_INET)
        return infos[0][4][0]
    except Exception:
        return None


# --------------------------------------------------------------------------- #
# Wi-Fi (netsh, FR/EN) + déclenchement d'un scan frais (wlanapi)
# --------------------------------------------------------------------------- #
def wlan_trigger_scan():
    if not IS_WIN:
        return False
    try:
        class GUID(ctypes.Structure):
            _fields_ = [("Data1", ctypes.c_ulong), ("Data2", ctypes.c_ushort), ("Data3", ctypes.c_ushort),
                        ("Data4", ctypes.c_ubyte * 8)]

        class WLAN_INTERFACE_INFO(ctypes.Structure):
            _fields_ = [("InterfaceGuid", GUID), ("strInterfaceDescription", ctypes.c_wchar * 256),
                        ("isState", ctypes.c_uint)]

        class WLAN_INTERFACE_INFO_LIST(ctypes.Structure):
            _fields_ = [("dwNumberOfItems", ctypes.c_ulong), ("dwIndex", ctypes.c_ulong),
                        ("InterfaceInfo", WLAN_INTERFACE_INFO * 1)]
        w = ctypes.WinDLL("wlanapi")
        h, ver = wintypes.HANDLE(), ctypes.c_ulong()
        if w.WlanOpenHandle(2, None, ctypes.byref(ver), ctypes.byref(h)) != 0:
            return False
        lst = ctypes.POINTER(WLAN_INTERFACE_INFO_LIST)()
        ok = False
        if w.WlanEnumInterfaces(h, None, ctypes.byref(lst)) == 0:
            n = lst.contents.dwNumberOfItems
            arr = ctypes.cast(ctypes.byref(lst.contents.InterfaceInfo), ctypes.POINTER(WLAN_INTERFACE_INFO * n)).contents
            for i in range(n):
                if w.WlanScan(h, ctypes.byref(arr[i].InterfaceGuid), None, None, None) == 0:
                    ok = True
            w.WlanFreeMemory(lst)
        w.WlanCloseHandle(h, None)
        return ok
    except Exception:
        return False


_K = {"auth": ("authentification", "authentication"), "enc": ("chiffrement", "encryption", "cipher"),
      "signal": ("signal",), "radio": ("type de radio", "radio type"), "band": ("bande", "band"),
      "channel": ("canal", "channel"), "ssid": ("ssid",), "bssid": ("bssid", "ap bssid"),
      "rx": ("débit de réception (mbits/s)", "réception (mbits/s)", "receive rate (mbps)"),
      "tx": ("débit de transmission (mbits/s)", "transmission (mbits/s)", "transmit rate (mbps)"),
      "rssi": ("rssi",), "state": ("état", "state"), "name": ("nom", "name"), "desc": ("description",)}


def _norm(t):
    return t.replace("\xa0", " ").replace("\u202f", " ").replace("\u2019", "'")


def _key(k):
    k = _norm(k).strip().lower()
    if k.startswith("point d'accès d'identificateur ssid") or k.startswith("access point bssid"):
        return "bssid"
    for std, alts in _K.items():
        if k in alts:
            return std
    return None


def _band(ch, band):
    b = (band or "").replace(",", ".")
    if "6" in b and "GHz" in b and not b.startswith("5"):
        return "6 GHz"
    if b.startswith("5"):
        return "5 GHz"
    if b.startswith("2"):
        return "2,4 GHz"
    try:
        c = int(ch)
        return "2,4 GHz" if c <= 14 else "5 GHz"
    except Exception:
        return ""


def wifi_scan(fresh=True):
    if not IS_WIN:
        return {"error": "Disponible sous Windows uniquement.", "nets": [], "cur": None}
    if fresh and wlan_trigger_scan():
        time.sleep(4)
    out = _norm(run(["netsh", "wlan", "show", "networks", "mode=bssid"], timeout=20))
    cur = _norm(run(["netsh", "wlan", "show", "interfaces"], timeout=20))
    nets, net, ap = [], None, None
    for line in out.splitlines():
        m = re.match(r"^SSID \d+\s*: ?(.*)$", line)
        if m:
            net = {"ssid": m.group(1).strip() or "(réseau masqué)", "auth": "", "enc": ""}
            ap = None
            continue
        m = re.match(r"^\s+BSSID \d+\s*: ?([0-9a-fA-F:]{17})", line)
        if m and net is not None:
            ap = dict(net, bssid=m.group(1).upper(), signal=0, radio="", band="", channel="")
            nets.append(ap)
            continue
        m = re.match(r"^\s+(.+?)\s*:\s(.*)$", line)
        if m:
            k, v = _key(m.group(1)), m.group(2).strip()
            if not k:
                continue
            tgt = ap if ap is not None else net
            if tgt is None:
                continue
            if k == "signal":
                mm = re.search(r"(\d+)", v)
                tgt["signal"] = int(mm.group(1)) if mm else 0
            elif k in ("auth", "enc", "radio", "band", "channel"):
                tgt[k] = v
    for a in nets:
        a["band"] = _band(a.get("channel"), a.get("band"))
        a["dbm"] = round(a["signal"] / 2 - 100)
    conn = None
    info = {}
    for line in cur.splitlines():
        if re.match(r"^\s+BSSID\s*:", line):   # points d'accès colocalisés (Wi-Fi 7 multi-liens) : ignorés
            continue
        m = re.match(r"^\s+(.+?)\s*:\s(.*)$", line)
        if not m:
            continue
        k = _key(m.group(1))
        if k and k not in info:
            info[k] = m.group(2).strip()
    if info.get("ssid"):
        conn = {"ssid": info.get("ssid"), "bssid": (info.get("bssid") or "").upper()[:17],
                "signal": info.get("signal", "") + (f"  ({info['rssi']} dBm)" if info.get("rssi") else ""),
                "channel": info.get("channel", ""), "radio": info.get("radio", ""), "auth": info.get("auth", ""),
                "rx": info.get("rx", ""), "tx": info.get("tx", ""), "band": _band(info.get("channel"), info.get("band")),
                "iface": info.get("desc") or info.get("name", "")}
    err = ""
    if not nets:
        low = (out + cur).lower()
        if "emplacement" in low or "location" in low:
            err = ("Windows bloque la liste des réseaux Wi-Fi : activer l'accès à la localisation "
                   "(Paramètres > Confidentialité > Localisation) puis actualiser.")
        elif "aucune interface" in low or "no wireless interface" in low or "service" in low and "wlansvc" in low:
            err = "Aucune carte Wi-Fi active sur ce poste."
        else:
            err = "Aucun réseau Wi-Fi détecté."
    nets.sort(key=lambda a: -a["signal"])
    return {"error": err, "nets": nets, "cur": conn}
