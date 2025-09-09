#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations
import os
import re
import ipaddress
import json
import time
import socket
import hashlib
import base64
import uuid
from pathlib import Path
from typing import List, Optional, Dict, Any, Tuple
from concurrent.futures import ThreadPoolExecutor

from flask import Flask, request, Response, jsonify, make_response, render_template

# Optional deps (graceful degradation)
try:
    import psutil  # type: ignore
except Exception:  # pragma: no cover
    psutil = None  # noqa: N816

# GeoIP is optional
GEOIP_MMDB = os.getenv("GEOIP_MMDB", "")
try:
    import geoip2.database  # type: ignore
except Exception:  # pragma: no cover
    geoip2 = None  # noqa: F401, N816

# ----------------------------- Base paths -----------------------------
BASE_DIR = Path(__file__).resolve().parent
SERVICE_VERSION = "2025-09-09.r4"

app = Flask(__name__, template_folder=str(BASE_DIR / "templates"), static_folder=str(BASE_DIR / "static"))

# ----------------------------- Regexes -----------------------------
_RE_FORWARDED_PAIR = re.compile(r"(?P<k>[a-zA-Z]+)=((?P<q>\"[^\"]*\")|(?P<t>[^;,\s]+))")
_IP_TOKEN = re.compile(r"(?<![A-Za-z0-9_:])(?:\\d{1,3}(?:\\.\\d{1,3}){3}|\\[[0-9a-fA-F:]+\\]|[0-9a-fA-F:]{2,})(?![A-Za-z0-9_:])")

SINGLE_IP_HEADERS = [
    "X-Real-IP", "True-Client-IP", "Client-IP", "CF-Connecting-IP", "Fastly-Client-Ip",
    "X-Cluster-Client-Ip", "X-Forwarded-Client-IP", "X-Client-IP", "X-Device-IP",
    "X-Remote-Addr", "X-Remote-IP", "X-ProxyUser-IP", "X-From-IP",
]

PROXY_SIGNAL_HEADERS = [
    "Via", "Forwarded", "X-Forwarded-Host", "X-Forwarded-Proto", "X-Forwarded-Port", "Proxy-Authorization",
]

CGNAT_CIDR = ipaddress.ip_network("100.64.0.0/10")

# ----------------------------- IP helpers -----------------------------

def _is_public(ip: ipaddress._BaseAddress) -> bool:
    return not (ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_link_local or ip.is_multicast)

def _scope_label(ip: ipaddress._BaseAddress) -> str:
    if ip.is_loopback: return "loopback"
    if ip.is_link_local: return "link_local"
    if ip in CGNAT_CIDR: return "cgnat"
    if ip.is_private: return "private"
    if ip.is_multicast: return "multicast"
    if ip.is_reserved: return "reserved"
    return "public"

def _clean_token_to_ip(token: str) -> Optional[ipaddress._BaseAddress]:
    if not token: return None
    t = token.strip().strip('"').strip("'").strip("[]")
    if ":" in t and t.count(":") == 1:
        host, maybe_port = t.split(":", 1)
        if maybe_port.isdigit(): t = host
    try:
        return ipaddress.ip_address(t)
    except ValueError:
        return None

# ----------------------------- Header parsing -----------------------------

def parse_forwarded_full(val: str) -> List[Dict[str, Optional[str]]]:
    out: List[Dict[str, Optional[str]]] = []
    if not val: return out
    entries = [e.strip() for e in val.split(',')]
    for e in entries:
        pairs = {m.group('k').lower(): (m.group('q') or m.group('t')) for m in _RE_FORWARDED_PAIR.finditer(e)}
        rec: Dict[str, Optional[str]] = {}
        for k in ("for","by","proto","host"):
            v = pairs.get(k)
            if v:
                v = v.strip('"')
                if v.startswith('[') and v.endswith(']'): v = v[1:-1]
                if ':' in v and v.count(':') == 1 and v.split(':',1)[1].isdigit(): v = v.split(':',1)[0]
            rec[k] = v or None
        out.append(rec)
    return out

def parse_xff_list(val: str) -> List[str]:
    if not val: return []
    out: List[str] = []
    for item in val.split(','):
        t = item.strip().strip('"').strip("[]")
        if ':' in t and t.count(':') == 1:
            host, port = t.split(':',1)
            if port.isdigit(): t = host
        if t: out.append(t)
    return out

def parse_via_chain(val: str) -> List[Dict[str, Optional[str]]]:
    chain: List[Dict[str, Optional[str]]] = []
    if not val: return chain
    for part in val.split(','):
        s = part.strip()
        comment = None
        if '(' in s and s.endswith(')'):
            comment = s[s.find('(')+1:-1]
            s = s[:s.find('(')].strip()
        toks = s.split()
        proto = None; rby = None
        if len(toks) == 1: rby = toks[0]
        elif len(toks) >= 2: proto, rby = toks[0], toks[1]
        chain.append({"protocol": proto, "received_by": rby, "comment": comment})
    return chain

# ----------------------------- Utilities -----------------------------

def _get_remote_ip() -> Optional[ipaddress._BaseAddress]:
    ra = request.remote_addr
    try:
        return ipaddress.ip_address(ra) if ra else None
    except ValueError:
        return None

def reverse_dns(ip: str, timeout_ms: int = 500) -> Optional[str]:
    try:
        addr = ipaddress.ip_address(ip.strip("[]"))
    except Exception:
        return None
    if addr.is_private:
        return None
    def _lookup():
        try:
            return socket.gethostbyaddr(addr.exploded)[0]
        except Exception:
            return None
    with ThreadPoolExecutor(max_workers=1) as ex:
        fut = ex.submit(_lookup)
        try:
            return fut.result(timeout=timeout_ms/1000.0)
        except Exception:
            return None

def sha256_b64(data: bytes) -> str:
    return base64.b64encode(hashlib.sha256(data).digest()).decode("ascii")

# Optional: GeoIP/ASN lookup
def geoip_lookup(ip_txt: Optional[str]) -> Optional[Dict[str, Any]]:
    if not ip_txt or not GEOIP_MMDB: return None
    try:
        import geoip2.database  # type: ignore
        reader = geoip2.database.Reader(GEOIP_MMDB)
        try:
            city = reader.city(ip_txt)
            asn = None
            try: asn = reader.asn(ip_txt)
            except Exception: pass
            return {
                "country": getattr(city.country, "iso_code", None),
                "city": getattr(city.city, "name", None),
                "asn": getattr(asn, "autonomous_system_number", None) if asn else None,
                "org": getattr(asn, "autonomous_system_organization", None) if asn else None,
                "location": {"lat": getattr(city.location, "latitude", None), "lon": getattr(city.location, "longitude", None)},
            }
        finally:
            reader.close()
    except Exception:
        return None

# Best-effort: infer local interface + MAC for outbound path to client
def infer_local_path_to(remote_ip: Optional[str]) -> Dict[str, Any]:
    out = {"local_ip": None, "iface": None, "mac": None, "speed_mbps": None}
    try:
        if not remote_ip: return out
        s = socket.socket(socket.AF_INET if ":" not in remote_ip else socket.AF_INET6, socket.SOCK_DGRAM)
        try:
            s.connect((remote_ip, 33434))
            out["local_ip"] = s.getsockname()[0]
        finally:
            s.close()
        if psutil and out["local_ip"]:
            for iface, addrs in psutil.net_if_addrs().items():
                ipv4 = next((a for a in addrs if getattr(a, 'family', None) == socket.AF_INET and a.address == out["local_ip"]), None)
                ipv6 = next((a for a in addrs if getattr(a, 'family', None) == socket.AF_INET6 and a.address.split('%')[0] == out["local_ip"]), None)
                if ipv4 or ipv6:
                    out["iface"] = iface
                    mac = next((a.address for a in addrs if str(getattr(a, 'family', '')) == 'AddressFamily.AF_LINK' or getattr(a, 'family', None) == getattr(psutil, 'AF_LINK', object())), None)
                    out["mac"] = mac
                    sp = Path(f"/sys/class/net/{iface}/speed")
                    if sp.exists():
                        try: out["speed_mbps"] = int(sp.read_text().strip())
                        except Exception: pass
                    break
    except Exception:
        pass
    return out

# ----------------------------- Format negotiation -----------------------------

def _preferred_format() -> str:
    fmt = (request.args.get('format') or '').lower()
    if fmt in ('json','html'): return fmt
    accept = request.headers.get('Accept','')
    ua = (request.headers.get('User-Agent','') or '').lower()
    cli_markers = ('curl/','wget/','httpie','python-requests','aiohttp','okhttp','node-fetch','axios','postman','insomnia','powershell','go-http-client','libcurl','dart')
    if any(m in ua for m in cli_markers): return 'json'
    if 'application/json' in accept and 'text/html' not in accept: return 'json'
    if 'text/html' in accept or any(b in ua for b in ('mozilla','safari','chrome','edg')): return 'html'
    return 'json'

# ----------------------------- Route/origin analysis -----------------------------

def _merge_hops_with_evidence(fwd_entries, xff_list, single_map, remote_ip: Optional[ipaddress._BaseAddress]):
    hops: List[Dict[str, Any]] = []
    evidence: Dict[str, List[Dict[str, Any]]] = {}
    order = 0

    for idx, rec in enumerate(fwd_entries):
        ip = _clean_token_to_ip(rec.get('for') or '')
        ip_txt = (ip.compressed if ip else (rec.get('for') or ''))
        if not ip_txt: continue
        order += 1
        hop = {"order": order, "source": "Forwarded.for", "ip": ip_txt,
               "ip_version": (ip.version if ip else None), "scope": (_scope_label(ip) if ip else None),
               "public": (_is_public(ip) if ip else None), "proto": rec.get('proto'),
               "host": rec.get('host'), "by": rec.get('by'), "role": "forwarder"}
        hops.append(hop)
        evidence.setdefault(ip_txt, []).append({"src":"fwd", "pos": idx})

    for idx, s in enumerate(xff_list):
        ip = _clean_token_to_ip(s)
        ip_txt = (ip.compressed if ip else s)
        if not ip_txt: continue
        order += 1
        hop = {"order": order, "source": "X-Forwarded-For", "ip": ip_txt,
               "ip_version": (ip.version if ip else None), "scope": (_scope_label(ip) if ip else None),
               "public": (_is_public(ip) if ip else None), "role": "forwarder"}
        hops.append(hop)
        evidence.setdefault(ip_txt, []).append({"src":"xff", "pos": idx})

    for hdr, val in single_map.items():
        ip = _clean_token_to_ip(val)
        if not ip: continue
        ip_txt = ip.compressed
        order += 1
        hop = {"order": order, "source": hdr, "ip": ip_txt,
               "ip_version": ip.version, "scope": _scope_label(ip), "public": _is_public(ip),
               "role": "side_hint"}
        hops.append(hop)
        evidence.setdefault(ip_txt, []).append({"src":"single", "hdr": hdr})

    if remote_ip is not None:
        order += 1
        hops.append({"order": order, "source": "remote_addr", "ip": remote_ip.compressed,
                     "ip_version": remote_ip.version, "scope": _scope_label(remote_ip),
                     "public": _is_public(remote_ip), "role": "server_peer"})

    remote_txt = remote_ip.compressed if remote_ip else None
    client_assigned = False
    for hop in hops:
        if hop["source"] == "remote_addr":
            hop["role"] = "server_peer"; continue
        if hop.get("public") is True and hop.get("ip") != remote_txt:
            if not client_assigned: hop["role"] = "client"; client_assigned = True
            else: hop["role"] = "proxy"
        elif hop["role"] == "forwarder":
            hop["role"] = "proxy"

    return hops, evidence

def _score_origins(evidence: Dict[str, List[Dict[str, Any]]], remote_ip: Optional[ipaddress._BaseAddress]) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    scores: Dict[str, float] = {}; reasons: Dict[str, List[str]] = {}
    def add(ip_txt: str, pts: float, why: str):
        scores[ip_txt] = scores.get(ip_txt, 0.0) + pts; reasons.setdefault(ip_txt, []).append(why)
    for ip_txt, items in evidence.items():
        if remote_ip is not None and ip_txt == remote_ip.compressed: continue
        try: ip = ipaddress.ip_address(ip_txt)
        except ValueError: continue
        if not _is_public(ip): continue
        for it in items:
            src = it.get('src')
            if src == 'fwd': pos = int(it.get('pos', 0)); add(ip_txt, 3.0 - min(pos, 2)*0.5, f"forwarded_pos={pos}")
            elif src == 'xff': pos = int(it.get('pos', 0)); add(ip_txt, 2.0 - min(pos, 2)*0.25, f"xff_pos={pos}")
            elif src == 'single': hdr = it.get('hdr',''); add(ip_txt, 1.0, f"header={hdr}")
    ranked = sorted(scores.items(), key=lambda kv: kv[1], reverse=True)
    candidates: List[Dict[str, Any]] = [{"ip": ip_txt, "score": round(sc, 2), "evidence": reasons.get(ip_txt, [])} for ip_txt, sc in ranked]
    origin_ip = candidates[0]["ip"] if candidates else None
    return candidates, origin_ip

def _classify_proxy(signals: Dict[str, bool], leaks: List[Dict[str, str]], hops: List[Dict[str, Any]], remote_ip: Optional[ipaddress._BaseAddress]) -> str:
    any_signal = any(signals.values()); has_leak = bool(leaks)
    public_hops = [h for h in hops if h.get('public') is True]
    if not any_signal and not has_leak and len(public_hops) == 1 and public_hops[0]['source'] == 'remote_addr': return 'direct'
    if has_leak and any_signal: return 'transparent'
    if not has_leak and any_signal: return 'anonymous'
    if not any_signal and not has_leak: return 'elite'
    return 'unknown'

def _detect_anomalies(fwd_entries, xff_list, hops: List[Dict[str, Any]], headers: Dict[str, str]) -> List[str]:
    issues: List[str] = []
    for s in xff_list:
        ip = _clean_token_to_ip(s)
        if not ip: continue
        sc = _scope_label(ip)
        if sc in ("private","loopback","link_local","cgnat"): issues.append(f"xff_contains_{sc}")
    if fwd_entries and xff_list:
        f0 = _clean_token_to_ip(fwd_entries[0].get('for') or ''); x0 = _clean_token_to_ip(xff_list[0])
        if f0 and x0 and f0.compressed != x0.compressed: issues.append("forwarded_xff_firsthop_mismatch")
    if not headers.get('User-Agent'): issues.append("empty_user_agent")
    total_hdr_len = sum(len(k)+len(v) for k,v in headers.items())
    if total_hdr_len > 24*1024: issues.append("headers_very_large")
    if headers.get('Proxy-Authorization'): issues.append("proxy_authorization_present")
    return issues

def collect_route(req) -> Dict[str, Any]:
    trusted_hops = int(os.getenv("TRUSTED_HOPS", "0") or "0")
    remote_ip_obj = _get_remote_ip(); remote_ip = remote_ip_obj
    fwd_entries = parse_forwarded_full(req.headers.get("Forwarded", ""))
    xff_list = parse_xff_list(req.headers.get("X-Forwarded-For", ""))
    via_chain = parse_via_chain(req.headers.get("Via", ""))
    if trusted_hops > 0:
        xff_list = xff_list[:-trusted_hops] if len(xff_list) > trusted_hops else []
        fwd_entries = fwd_entries[:-trusted_hops] if len(fwd_entries) > trusted_hops else []
    single_map: Dict[str, str] = {h: v for h in SINGLE_IP_HEADERS if (v := req.headers.get(h))}
    hops, evidence = _merge_hops_with_evidence(fwd_entries, xff_list, single_map, remote_ip)
    leaks: List[Dict[str, str]] = []
    remote_txt = remote_ip.compressed if remote_ip else None
    for h in hops:
        if h["source"] != "remote_addr" and h.get("public") is True and h.get("ip") != remote_txt:
            leaks.append({"header": h["source"], "ip": h["ip"]})
    sig = {k.lower(): bool(req.headers.get(k)) for k in PROXY_SIGNAL_HEADERS}
    strict = os.getenv("STRICT", "0") == "1"
    require_via = os.getenv("REQUIRE_VIA", "0") == "1"
    private_local_ok = os.getenv("PRIVATE_LOCAL_OK", "1") == "1"
    has_signal = any(sig.values()) or (private_local_ok and remote_ip and not _is_public(remote_ip))
    if require_via: has_signal = has_signal and sig.get("via", False)
    transparent_relaxed = len(leaks) > 0
    transparent_strict = transparent_relaxed and has_signal
    transparent = transparent_strict if strict else transparent_relaxed
    origin_candidates, origin_ip = _score_origins(evidence, remote_ip)
    x_proto = req.headers.get("X-Forwarded-Proto")
    x_host = req.headers.get("X-Forwarded-Host") or req.headers.get("Host")
    x_port = req.headers.get("X-Forwarded-Port")
    if fwd_entries:
        fe0 = fwd_entries[0]
        x_proto = fe0.get('proto') or x_proto
        x_host = fe0.get('host') or x_host
    eff_scheme = (x_proto or request.scheme)
    eff_host = x_host or request.host
    try:
        eff_port = int(x_port) if x_port else (int(request.host.split(':',1)[1]) if ':' in request.host else (443 if eff_scheme == 'https' else 80))
    except Exception:
        eff_port = 443 if eff_scheme == 'https' else 80
    nodes, edges, prev = [], [], None
    for h in hops:
        ip = h["ip"]
        if ip not in nodes: nodes.append(ip)
        if prev and prev != ip: edges.append({"from": prev, "to": ip})
        prev = ip
    classification = _classify_proxy(sig, leaks, hops, remote_ip)
    anomalies = _detect_anomalies(fwd_entries, xff_list, hops, {k:v for k,v in request.headers.items()})
    return {
        "hops": hops, "hop_count": len(hops), "via_chain": via_chain,
        "forwarded_chain": fwd_entries, "xff_chain": xff_list, "leaks": leaks,
        "origin_ip": origin_ip, "origin_candidates": origin_candidates, "proxy_signals": sig,
        "transparent_proxy": bool(transparent), "transparent_mode": ("strict" if strict else "relaxed"),
        "proxy_class": classification, "anomalies": anomalies,
        "effective_path": {"scheme": eff_scheme, "host": eff_host, "port": eff_port,
                           "url_example": f"{eff_scheme}://{eff_host}{request.full_path if request.query_string else request.path}"},
        "graph": {"nodes": nodes, "edges": edges},
    }

# ----------------------------- OSI snapshot -----------------------------

def collect_osi(payload: Dict[str, Any]) -> Dict[str, Any]:
    r = payload["request"]; a = payload["analysis"]
    l7 = {"method": r["method"], "url": r["url"], "path": r["path"], "http_version": r["http_version"],
          "headers_count": len(r["headers"]), "cookies_count": len(payload["request"].get("cookies", {})) if "cookies" in payload["request"] else 0,
          "content_type": r["body"]["content_type"], "body_length": r["body"]["length"]}
    env = request.environ
    tls_info = {k: env.get(k) for k in env.keys() if k.startswith("SSL_")}
    if env.get("HTTPS"): tls_info.setdefault("HTTPS", env.get("HTTPS"))
    if request.is_secure: tls_info.setdefault("url_scheme", "https")
    cfv = request.headers.get("CF-Visitor")
    if cfv: tls_info["CF-Visitor"] = cfv
    l6 = {"https": bool(request.is_secure or env.get("HTTPS") == "on"), "tls": tls_info or None}
    hdrs = r["headers"]; conn = hdrs.get("Connection") or hdrs.get("connection")
    l5 = {"keep_alive": (conn.lower() == "keep-alive") if isinstance(conn, str) else None,
          "upgrade": hdrs.get("Upgrade") or hdrs.get("upgrade"), "proxy_auth_present": bool(hdrs.get("Proxy-Authorization"))}
    remote_port = request.environ.get("REMOTE_PORT"); server_port = request.environ.get("SERVER_PORT")
    l4 = {"protocol": "tcp",
          "remote_port": int(remote_port) if str(remote_port or "").isdigit() else remote_port,
          "server_port": int(server_port) if str(server_port or "").isdigit() else server_port}
    client_ip = r["client"]["remote_addr"]; client_geo = geoip_lookup(client_ip); local_path = infer_local_path_to(client_ip)
    l3 = {"client_ip": client_ip,
          "client_scope": (_scope_label(ipaddress.ip_address(client_ip)) if client_ip else None) if client_ip else None,
          "client_rdns": r["client"]["reverse_dns"], "server_local_ip": local_path.get("local_ip"),
          "geo": client_geo, "hops_public": [h for h in a["hops"] if h.get("public") is True]}
    l2 = {"iface": local_path.get("iface"), "mac": local_path.get("mac"), "link_speed_mbps": local_path.get("speed_mbps")}
    l1 = {"medium": "ethernet (assumed)", "notes": "Physical-layer specifics need host privileges; reporting NIC speed if exposed by /sys."}
    return {"l7_http": l7, "l6_presentation": l6, "l5_session": l5, "l4_transport": l4, "l3_network": l3, "l2_link": l2, "l1_physical": l1}

# ----------------------------- Builder -----------------------------

def _trace_ids() -> Dict[str, str]:
    inbound = request.headers.get("X-Request-Id") or request.headers.get("X-Request-ID")
    traceparent = request.headers.get("traceparent")
    rid = inbound or str(uuid.uuid4())
    return {"request_id": rid, "traceparent": traceparent}

def build_response_json() -> Dict[str, Any]:
    t0 = time.time()
    headers = {k: v for k, v in request.headers.items()}
    route_info = collect_route(request)
    remote_ip_obj = _get_remote_ip()
    remote_ip = remote_ip_obj.compressed if remote_ip_obj else None
    raw_body = request.get_data(cache=False, as_text=False)
    body_len = len(raw_body) if raw_body is not None else 0
    body_sha256 = sha256_b64(raw_body) if raw_body else ""
    truncated = False; preview = None
    if body_len > 1024:
        preview = base64.b64encode(raw_body[:512]).decode("ascii"); truncated = True
    json_body = request.get_json(silent=True) if request.is_json else None
    rdns = reverse_dns(remote_ip, timeout_ms=int(os.getenv("RDNS_TIMEOUT_MS","500"))) if (os.getenv("ENABLE_RDNS","1") == "1" and remote_ip) else None
    deep = request.args.get('deep') == '1'
    ip_hits: List[Dict[str,str]] = []; environ_headers: Dict[str, str] = {}
    if deep:
        for k, v in headers.items():
            for token in _IP_TOKEN.findall(v or ''):
                ip_obj = _clean_token_to_ip(token)
                if ip_obj and _is_public(ip_obj): ip_hits.append({"header": k, "ip": ip_obj.compressed})
        for k, v in request.environ.items():
            if k.startswith('HTTP_') or k in ('REMOTE_ADDR','REMOTE_PORT','SERVER_NAME','SERVER_PROTOCOL','SERVER_PORT','SERVER_SOFTWARE'):
                try: environ_headers[k] = str(v)
                except Exception: pass
    trace = _trace_ids()
    risk = 0
    risk += 40 if route_info.get("leaks") else 0
    risk += 25 if any(route_info.get("proxy_signals", {}).values()) else 0
    risk += 5 * len(route_info.get("anomalies", []))
    risk = max(0, min(100, risk))
    data: Dict[str, Any] = {
        "meta": {
            "service_version": SERVICE_VERSION,
            "server_time_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "processing_ms": round((time.time()-t0)*1000, 2),
            "transparent_detection_mode": route_info["transparent_mode"],
            "base_dir": str(BASE_DIR),
            "config": {
                "STRICT": os.getenv("STRICT","0"),
                "REQUIRE_VIA": os.getenv("REQUIRE_VIA","0"),
                "TRUSTED_HOPS": os.getenv("TRUSTED_HOPS","0"),
                "PRIVATE_LOCAL_OK": os.getenv("PRIVATE_LOCAL_OK","1"),
                "ENABLE_RDNS": os.getenv("ENABLE_RDNS","1"),
            },
            **trace,
        },
        "request": {
            "method": request.method,
            "scheme": request.scheme,
            "secure": bool(request.is_secure),
            "http_version": request.environ.get("SERVER_PROTOCOL",""),
            "url": request.url,
            "path": request.full_path if request.query_string else request.path,
            "headers": headers,
            "cookies": {k:v for k,v in request.cookies.items()},
            "client": {
                "remote_addr": remote_ip,
                "remote_ip_version": (remote_ip_obj.version if remote_ip_obj else None),
                "reverse_dns": rdns,
                "user_agent": headers.get("User-Agent",""),
                "accept_language": headers.get("Accept-Language",""),
            },
            "body": {
                "length": body_len,
                "content_type": headers.get("Content-Type",""),
                "sha256_b64": body_sha256,
                "json": json_body,
                "preview_b64": preview,
                "truncated": truncated,
            }
        },
        "analysis": {**route_info, **({"header_ip_hits": ip_hits} if deep else {}), "risk_score": risk},
    }
    data["osi"] = collect_osi(data)
    if request.args.get("summary") == "1":
        data = {"time": data["meta"]["server_time_utc"], "processing_ms": data["meta"]["processing_ms"],
                "request_id": data["meta"]["request_id"], "client_ip": data["request"]["client"]["remote_addr"],
                "effective_path": data["analysis"]["effective_path"], "proxy_class": data["analysis"].get("proxy_class"),
                "transparent": data["analysis"]["transparent_proxy"], "origin_ip": data["analysis"]["origin_ip"],
                "leaks": data["analysis"]["leaks"], "risk": data["analysis"]["risk_score"]}
    if deep:
        data["debug"] = {"environ": environ_headers}
    return data

# ----------------------------- Endpoints -----------------------------

from flask import render_template

@app.route("/", methods=["GET","POST","PUT","PATCH","DELETE","HEAD","OPTIONS"])
def root():
    payload = build_response_json()
    fmt = _preferred_format() if request.method == 'GET' else 'json'
    if fmt == 'html' and request.method == 'GET':
        raw_json = json.dumps(payload, ensure_ascii=False, indent=2)
        resp = make_response(render_template("inspector.html", **payload, raw_json=raw_json))
    else:
        resp = make_response(jsonify(payload))
    resp.headers['X-Request-Id'] = payload['meta'].get('request_id','')
    if payload['meta'].get('traceparent'): resp.headers['Traceparent'] = payload['meta']['traceparent']
    resp.headers['Server'] = 'request-inspector'
    # resp.headers['Content-Security-Policy'] = "default-src 'none'; style-src 'unsafe-inline'"
    resp.headers['Content-Security-Policy'] = "Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self';"
    return resp

@app.route('/json', methods=['GET','POST'])
def only_json():
    payload = build_response_json()
    resp = make_response(jsonify(payload))
    resp.headers['X-Request-Id'] = payload['meta'].get('request_id','')
    return resp

@app.route('/html', methods=['GET'])
def only_html():
    payload = build_response_json()
    raw_json = json.dumps(payload, ensure_ascii=False, indent=2)
    resp = make_response(render_template("inspector.html", **payload, raw_json=raw_json))
    resp.headers['X-Request-Id'] = payload['meta'].get('request_id','')
    
    return resp

@app.route('/ip', methods=['GET'])
def client_ip():
    ip = request.headers.get('CF-Connecting-IP') or request.headers.get('X-Real-IP') or request.remote_addr or ''
    return Response((ip + "\\n"), mimetype='text/plain')

@app.route('/headers', methods=['GET'])
def headers_plain():
    lines = [f"{k}: {v}" for k,v in request.headers.items()]
    return Response("\\n".join(lines) + "\\n", mimetype='text/plain')

@app.route('/echo', methods=['POST','PUT','PATCH'])
def echo_body():
    raw = request.get_data(cache=False, as_text=False) or b''
    return Response(raw, mimetype=request.headers.get('Content-Type','application/octet-stream'))

@app.route("/healthz", methods=["GET","HEAD"])
def healthz():
    return Response("ok", mimetype="text/plain")

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "80"))
    app.run(host="0.0.0.0", port=port)
