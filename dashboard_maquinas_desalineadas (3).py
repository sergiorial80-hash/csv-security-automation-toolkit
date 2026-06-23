# -*- coding: utf-8 -*-
import os
import re
import csv
import json
import unicodedata
from datetime import datetime
from collections import Counter

# =========================================================
# CONFIG
# =========================================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

def resolve_input_dir(base_dir):
    p1 = os.path.join(base_dir, "input")
    p2 = os.path.join(base_dir, "Dashboard", "input")
    if os.path.isdir(p1):
        return p1
    if os.path.isdir(p2):
        return p2
    return p1

INPUT_DIR  = resolve_input_dir(BASE_DIR)
OUTPUT_DIR = os.path.join(os.path.dirname(INPUT_DIR), "Dashboard Desalineadas")
OUT_HTML   = os.path.join(OUTPUT_DIR, "dashboard_maquinas_desalineadas.html")

RE_FILE   = re.compile(r"^(\d{8})_Critical_(SGTO|SANTEC)\.csv$", re.I)
ENCODINGS = ["utf-8-sig", "utf-8", "cp1252", "latin-1"]
DELIMS    = [",", ";", "\t", "|"]

# =========================================================
# UTILS BÁSICOS
# =========================================================
def ensure_dir(path):
    os.makedirs(path, exist_ok=True)

def clean(x):
    return str(x).strip() if x is not None else ""

def hnorm(x):
    s = clean(x).lower()
    s = unicodedata.normalize("NFKD", s).encode("ascii", "ignore").decode("ascii")
    return re.sub(r"[^a-z0-9]+", "", s)

def detect_file(path):
    last = None
    for enc in ENCODINGS:
        try:
            f = open(path, "r", encoding=enc, errors="replace", newline="")
            sample = f.read(4096)
            f.seek(0)
            try:
                delim = csv.Sniffer().sniff(sample, delimiters=DELIMS).delimiter
            except Exception:
                counts = {d: sample.count(d) for d in DELIMS}
                delim = max(counts, key=counts.get) if counts else ";"
            return f, delim
        except Exception as e:
            last = e
    raise last if last else RuntimeError("No se pudo abrir: " + path)

def is_real_daily_csv(name):
    b = os.path.basename(name)
    return (
        not (b.startswith("~") or b.startswith(".") or b.startswith(".~lock."))
        and bool(RE_FILE.match(b))
    )

def parse_snapshot_from_filename(name):
    m = RE_FILE.match(os.path.basename(name))
    if not m:
        return None, None
    return datetime.strptime(m.group(1), "%Y%m%d").date(), m.group(2).upper()

# =========================================================
# DETECCIÓN DE COLUMNAS
# =========================================================
def build_exact_index(headers):
    return {hnorm(h): h for h in headers}

def find_exact(idx, *targets):
    for t in targets:
        k = hnorm(t)
        if k in idx:
            return idx[k]
    return None

def find_contains(idx, *fragments):
    for frag in fragments:
        frag_n = hnorm(frag)
        if len(frag_n) <= 2:
            if frag_n in idx:
                return idx[frag_n]
        else:
            for norm_h, orig_h in idx.items():
                if frag_n in norm_h:
                    return orig_h
    return None

def detect_columns(headers):
    idx = build_exact_index(headers)

    c_machine = (
        find_exact(idx, "NetBIOSName", "Hostname", "DNSName", "ComputerName",
                        "AssetName", "FQDN", "Host", "Computer", "Machine",
                        "Maquina", "AssetID", "BIOSSerialNumber", "Serial")
        or find_contains(idx, "netbios", "hostname", "dnsname", "computer",
                              "machine", "maquina", "assetid", "serial")
    )
    c_ent      = find_exact(idx, "Entidad")    or find_contains(idx, "entidad")
    c_sub      = find_exact(idx, "Subentidad") or find_contains(idx, "subentidad")
    c_activity = (
        find_exact(idx, "Activity", "LastActivity", "LastReport", "LastReportDate")
        or find_contains(idx, "lastreport", "ultimoreporte", "ultimaactividad")
    )
    c_sccm = (
        find_exact(idx, "Estado_SCCM", "Estado:SCCM", "SCCM", "Sccm", "sccm")
        or find_contains(idx, "sccm")
    )
    c_da = (
        find_exact(idx, "DA", "D.A.", "da", "Estado_DA", "Estado:DA")
        or find_contains(idx, "estadoda", "directorioactivo")
    )
    c_minerva = (
        find_exact(idx, "Minerva", "MINERVA", "minerva",
                   "Estado_Minerva", "Estado:Minerva")
        or find_contains(idx, "minerva")
    )

    return {
        "machine":  c_machine,
        "ent":      c_ent,
        "sub":      c_sub,
        "activity": c_activity,
        "sccm":     c_sccm,
        "da":       c_da,
        "minerva":  c_minerva,
    }

# =========================================================
# LÓGICA DE NEGOCIO
# =========================================================
_DA_MINERVA_OK = {"productiva", "productivo", "operativa", "operativo"}
_CACHE_SCCM   = {}
_CACHE_DA_MIN = {}

def normalize_sccm(raw):
    v = clean(raw)
    if v in _CACHE_SCCM:
        return _CACHE_SCCM[v]
    n = hnorm(v)
    if not n:
        result = None
    elif n == "ensccm" or n == "sccm" or "ensccm" in n:
        result = True
    else:
        result = False
    _CACHE_SCCM[v] = result
    return result

def normalize_da_minerva(raw):
    v = clean(raw)
    if v in _CACHE_DA_MIN:
        return _CACHE_DA_MIN[v]
    n = hnorm(v)
    if not n:
        result = None
    else:
        result = n in _DA_MINERVA_OK
    _CACHE_DA_MIN[v] = result
    return result

def cross_status(sccm_val, da_val, minerva_val, has_sccm_col, has_da_col, has_minerva_col):
    if not has_sccm_col and not has_da_col and not has_minerva_col:
        return "Sin datos"
    sccm_ok    = normalize_sccm(sccm_val)         if has_sccm_col    else None
    da_ok      = normalize_da_minerva(da_val)      if has_da_col      else None
    minerva_ok = normalize_da_minerva(minerva_val) if has_minerva_col else None
    if not has_sccm_col or not has_da_col or not has_minerva_col:
        return "Parcial"
    if sccm_ok is None or da_ok is None or minerva_ok is None:
        return "Parcial"
    if sccm_ok and da_ok and minerva_ok:
        return "Alineada"
    return "Desalineada"

def display_sccm(raw, has_col):
    if not has_col:
        return "Sin columna"
    v = clean(raw)
    return v if v else "Sin datos"

def display_da_minerva(raw, has_col):
    if not has_col:
        return "Sin columna"
    v = clean(raw)
    return v if v else "Sin datos"

# =========================================================
# PARSING DE FECHAS
# =========================================================
DATE_PATTERNS = [
    "%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d",
    "%d/%m/%Y %H:%M:%S", "%d/%m/%Y %H:%M", "%d/%m/%Y",
    "%m/%d/%Y %H:%M:%S", "%m/%d/%Y %H:%M", "%m/%d/%Y",
    "%d-%m-%Y %H:%M:%S", "%d-%m-%Y %H:%M", "%d-%m-%Y",
    "%Y/%m/%d %H:%M:%S", "%Y/%m/%d %H:%M", "%Y/%m/%d",
]

def detect_date_format(sample_values):
    scores = {fmt: 0 for fmt in DATE_PATTERNS}
    for raw in sample_values:
        s = clean(raw).replace(".", "/")
        if not s:
            continue
        for fmt in DATE_PATTERNS:
            try:
                datetime.strptime(s, fmt)
                scores[fmt] += 1
                break
            except Exception:
                pass
    best = max(scores, key=scores.get)
    return best if scores[best] > 0 else None

def parse_date_fast(raw, fmt):
    s = clean(raw).replace(".", "/")
    if not s:
        return None
    if fmt:
        try:
            return datetime.strptime(s, fmt).date()
        except Exception:
            pass
    m = re.search(r"(\d{4}-\d{2}-\d{2})", s)
    if m:
        try:
            return datetime.strptime(m.group(1), "%Y-%m-%d").date()
        except Exception:
            pass
    m = re.search(r"(\d{2}/\d{2}/\d{4})", s)
    if m:
        for fmt2 in ("%d/%m/%Y", "%m/%d/%Y"):
            try:
                return datetime.strptime(m.group(1), fmt2).date()
            except Exception:
                pass
    return None

def classify_range(days):
    if days <= 0:   return "HOY"
    if days <= 2:   return "1-2 días"
    if days <= 10:  return "3-10 días"
    return ">10 días"

# =========================================================
# LOAD DATA
# =========================================================
def load_data():
    files = []
    if not os.path.isdir(INPUT_DIR):
        raise FileNotFoundError("No existe la carpeta input: " + INPUT_DIR)
    for name in os.listdir(INPUT_DIR):
        if not is_real_daily_csv(name):
            continue
        snap_date, env = parse_snapshot_from_filename(name)
        if snap_date and env:
            files.append((snap_date, env, os.path.join(INPUT_DIR, name)))
    files.sort(key=lambda x: (x[0], x[1]))
    if not files:
        raise FileNotFoundError("No se encontraron CSV válidos en " + INPUT_DIR)

    _CACHE_SCCM.clear()
    _CACHE_DA_MIN.clear()

    agg = {}

    for snapshot_date, env, path in files:
        f, delim = detect_file(path)
        try:
            reader = csv.DictReader(f, delimiter=delim)
            if not reader.fieldnames:
                continue

            headers    = [clean(h) for h in reader.fieldnames]
            cols       = detect_columns(headers)
            c_machine  = cols["machine"]
            c_ent      = cols["ent"]
            c_sub      = cols["sub"]
            c_activity = cols["activity"]
            c_sccm     = cols["sccm"]
            c_da       = cols["da"]
            c_minerva  = cols["minerva"]

            has_sccm    = c_sccm    is not None
            has_da      = c_da      is not None
            has_minerva = c_minerva is not None

            print(f"  [{os.path.basename(path)}]")
            print(f"    machine={c_machine!r}  activity={c_activity!r}")
            print(f"    sccm={c_sccm!r}  da={c_da!r}  minerva={c_minerva!r}")

            if not c_machine or not c_activity:
                print(f"    ⚠️  Saltando: falta machine o activity")
                continue

            sample_rows = []
            for raw_row in reader:
                sample_rows.append(raw_row)
                if len(sample_rows) >= 30:
                    break
            date_fmt = detect_date_format(
                [clean(r.get(c_activity, "")) for r in sample_rows]
            )
            print(f"    formato fecha → {date_fmt!r}")

            all_rows = sample_rows
            for raw_row in reader:
                all_rows.append(raw_row)

            snap_iso = snapshot_date.isoformat()

            for raw_row in all_rows:
                machine = clean(raw_row.get(c_machine, "")) if c_machine else ""
                if not machine:
                    continue
                activity_date = parse_date_fast(
                    raw_row.get(c_activity, "") if c_activity else "", date_fmt
                )
                if not activity_date:
                    continue

                ent = clean(raw_row.get(c_ent, "")) if c_ent else ""
                sub = clean(raw_row.get(c_sub, "")) if c_sub else ""
                ent = ent or "SIN_ENTIDAD"
                sub = sub or "SIN_SUBENTIDAD"

                sccm_raw    = clean(raw_row.get(c_sccm,    "")) if has_sccm    else ""
                da_raw      = clean(raw_row.get(c_da,      "")) if has_da      else ""
                minerva_raw = clean(raw_row.get(c_minerva, "")) if has_minerva else ""

                key = (snap_iso, env, ent, sub, machine)

                if key not in agg:
                    agg[key] = {
                        "last_report_date": activity_date,
                        "sccm_raw":         sccm_raw,
                        "da_raw":           da_raw,
                        "minerva_raw":      minerva_raw,
                        "has_sccm":         has_sccm,
                        "has_da":           has_da,
                        "has_minerva":      has_minerva,
                    }
                else:
                    if activity_date > agg[key]["last_report_date"]:
                        agg[key]["last_report_date"] = activity_date
                    if sccm_raw and not agg[key]["sccm_raw"]:
                        agg[key]["sccm_raw"] = sccm_raw
                    if da_raw and not agg[key]["da_raw"]:
                        agg[key]["da_raw"] = da_raw
                    if minerva_raw and not agg[key]["minerva_raw"]:
                        agg[key]["minerva_raw"] = minerva_raw
        finally:
            f.close()

    rows        = []
    history_acc = {}

    for (snap_iso, env, ent, sub, machine), b in agg.items():
        snapshot_date = datetime.strptime(snap_iso, "%Y-%m-%d").date()
        last_report   = b["last_report_date"]
        days          = max((snapshot_date - last_report).days, 0)
        rng           = classify_range(days)

        cruce = cross_status(
            b["sccm_raw"], b["da_raw"], b["minerva_raw"],
            b["has_sccm"], b["has_da"], b["has_minerva"]
        )

        rows.append({
            "fecha":               snap_iso,
            "env":                 env,
            "ent":                 ent,
            "sub":                 sub,
            "machine":             machine,
            "activity":            last_report.isoformat(),
            "days_without_report": days,
            "range":               rng,
            "sccm":                display_sccm(b["sccm_raw"], b["has_sccm"]),
            "da":                  display_da_minerva(b["da_raw"], b["has_da"]),
            "minerva":             display_da_minerva(b["minerva_raw"], b["has_minerva"]),
            "cruce":               cruce,
        })

        if snap_iso not in history_acc:
            history_acc[snap_iso] = {"HOY": 0, "1-2 días": 0, "3-10 días": 0, ">10 días": 0}
        history_acc[snap_iso][rng] = history_acc[snap_iso].get(rng, 0) + 1

    rows.sort(key=lambda x: (x["fecha"], x["env"], x["ent"], x["sub"], x["machine"]))
    fechas = sorted({r["fecha"] for r in rows})

    history = {
        "labels": fechas,
        "hoy":    [history_acc.get(f, {}).get("HOY",       0) for f in fechas],
        "r12":    [history_acc.get(f, {}).get("1-2 días",  0) for f in fechas],
        "r310":   [history_acc.get(f, {}).get("3-10 días", 0) for f in fechas],
        "gt10":   [history_acc.get(f, {}).get(">10 días",  0) for f in fechas],
    }

    print("\n📊 Distribución de cruces (última fecha):")
    if fechas:
        ultima = fechas[-1]
        for k, v in sorted(Counter(r["cruce"] for r in rows if r["fecha"] == ultima).items()):
            print(f"   {k}: {v}")
        print("\n📊 Muestra valores SCCM únicos (primeros 10):")
        for v in list({r["sccm"] for r in rows if r["fecha"] == ultima})[:10]:
            print(f"   {v!r}")
        print("\n📊 Muestra valores DA únicos (primeros 10):")
        for v in list({r["da"] for r in rows if r["fecha"] == ultima})[:10]:
            print(f"   {v!r}")
        print("\n📊 Muestra valores Minerva únicos (primeros 10):")
        for v in list({r["minerva"] for r in rows if r["fecha"] == ultima})[:10]:
            print(f"   {v!r}")

    return fechas, rows, history

# =========================================================
# HTML
# =========================================================
HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8">
<title>Estado de máquinas</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
:root{
  --bg:#06122c;--card:#102450;--card2:#183468;--text:#fff;--muted:#c8d4ec;
  --line:rgba(255,255,255,.10);--ok:#22c55e;--warn:#f59e0b;--danger:#ef4444;--info:#3b82f6;
  --purple:#8b5cf6;--slate:#64748b;
  --rowOk:rgba(34,197,94,.10);--rowWarn:rgba(245,158,11,.12);--rowDanger:rgba(239,68,68,.12);
}
*{box-sizing:border-box}
body{margin:0;background:linear-gradient(180deg,#06122c 0%,#081936 100%);color:var(--text);font-family:Segoe UI,Arial,sans-serif;padding:24px}
h1,h2{margin-top:0}
.header{display:flex;align-items:flex-start;justify-content:space-between;margin-bottom:16px;gap:16px;flex-wrap:wrap}
.header-left h1{margin:0 0 4px;font-size:26px;font-weight:700;line-height:1.2}
.header-left h1 .fecha-highlight{color:#3b82f6}
.header-left .sub{color:#b7c3d9;font-size:13px}
.btn-back{display:inline-flex;align-items:center;gap:7px;padding:9px 18px;border-radius:10px;border:1px solid rgba(255,255,255,.25);background:#0f214b;color:#fff;cursor:pointer;font-size:13px;font-weight:600;white-space:nowrap;text-decoration:none;transition:background .15s;flex-shrink:0}
.btn-back:hover{background:#183468}

/* ── Controles ── */
.controls{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:16px;align-items:flex-end}
.ctrl{display:flex;flex-direction:column;min-width:150px}
.ctrl label{font-size:11px;color:#b7c3d9;margin-bottom:4px;text-transform:uppercase;letter-spacing:.04em}
.ctrl select{padding:8px 10px;border-radius:10px;border:1px solid rgba(255,255,255,.15);background:#0f214b;color:#fff;outline:none;font-size:13px}

/* ── Botón exportar ── */
.btn-export{
  padding:8px 18px;border-radius:10px;border:1px solid rgba(255,255,255,.25);
  background:#1e3a6e;color:#fff;cursor:pointer;font-size:13px;font-weight:600;
  white-space:nowrap;transition:background .15s;align-self:flex-end;height:36px
}
.btn-export:hover{background:#2a4f96}

/* ── Buscador is-one-of ── */
.search-box{display:flex;flex-direction:column;min-width:280px;flex:1}
.search-input-wrap{position:relative}
.search-input-wrap input{
  width:100%;padding:8px 36px 8px 10px;border-radius:10px;
  border:1px solid rgba(255,255,255,.15);background:#0f214b;
  color:#fff;outline:none;font-size:13px
}
.search-input-wrap input::placeholder{color:#6b7fa3}
.search-clear{position:absolute;right:10px;top:50%;transform:translateY(-50%);
  background:none;border:none;color:#6b7fa3;cursor:pointer;font-size:16px;line-height:1}
.search-tags{display:flex;flex-wrap:wrap;gap:6px;margin-top:6px;min-height:0}
.tag{display:inline-flex;align-items:center;gap:4px;background:#183468;
  border:1px solid rgba(255,255,255,.2);border-radius:6px;padding:3px 8px;font-size:12px}
.tag button{background:none;border:none;color:#94a3b8;cursor:pointer;font-size:14px;line-height:1;padding:0}
.search-dropdown{
  position:absolute;top:calc(100% + 4px);left:0;right:0;z-index:100;
  background:#0f214b;border:1px solid rgba(255,255,255,.2);border-radius:10px;
  max-height:200px;overflow-y:auto;display:none
}
.search-dropdown.open{display:block}
.search-dropdown div{padding:8px 12px;font-size:13px;cursor:pointer}
.search-dropdown div:hover{background:#183468}

/* ── Cards ── */
.card{background:var(--card);padding:15px;border-radius:14px;margin:12px 0;
  border:1px solid rgba(255,255,255,.10);box-shadow:0 10px 20px rgba(0,0,0,.12)}
.kpis{display:flex;gap:12px;flex-wrap:wrap}
.kpi{flex:1;min-width:160px;background:var(--card2);padding:14px;border-radius:12px}
.kpi .label{font-size:12px;color:var(--muted);margin-bottom:6px}
.kpi .value{font-size:26px;font-weight:700}
.kpi .small{color:#c1cde3;font-size:11px;margin-top:4px}
.layout{display:flex;gap:16px;flex-wrap:wrap}
.chartCard{flex:1;min-width:280px}

/* ── Paneles laterales mejorados ── */
.side-panel-title{font-size:15px;font-weight:600;color:#fff;margin:0 0 14px}
.stat-row-mini{display:flex;gap:8px;margin-bottom:10px}
.stat-mini{flex:1;background:#0f214b;border-radius:10px;padding:10px 12px;border:1px solid rgba(255,255,255,.07)}
.stat-mini .sm-lbl{font-size:10px;color:#64748b;text-transform:uppercase;letter-spacing:.05em;margin-bottom:4px}
.stat-mini .sm-val{font-size:18px;font-weight:700;line-height:1.1}
.stat-mini .sm-sub{font-size:10px;color:#475569;margin-top:3px}
.sep{height:1px;background:rgba(255,255,255,.07);margin:12px 0}
.prog-row{margin-bottom:7px}
.prog-label{display:flex;justify-content:space-between;font-size:11px;color:#94a3b8;margin-bottom:3px}
.prog-bar{height:5px;border-radius:3px;background:#0a1628;overflow:hidden}
.prog-fill{height:100%;border-radius:3px}
.section-label{font-size:10px;color:#475569;text-transform:uppercase;letter-spacing:.06em;margin-bottom:8px}
.cause-row{display:flex;align-items:center;gap:8px;margin-bottom:7px}
.cause-dot{width:7px;height:7px;border-radius:50%;flex-shrink:0}
.cause-name{font-size:11px;color:#cbd5e1;flex:1}
.cause-val{font-size:12px;font-weight:700;color:#fff}
.cause-pct{font-size:10px;color:#475569;margin-left:3px}
.summary-row{display:flex;justify-content:space-between;font-size:11px;color:#94a3b8;margin-bottom:5px}
.chart-mini-wrap{position:relative;height:100px;margin-top:10px}
.align-rate{display:flex;align-items:baseline;gap:6px;margin-top:4px}
.align-rate .rate-val{font-size:22px;font-weight:700}
.align-rate .rate-lbl{font-size:11px;color:#64748b}

/* ── Tabla ── */
.tableCard{min-width:100%}
.tableWrap{overflow-x:auto;max-height:560px;overflow-y:auto}
table{width:100%;border-collapse:collapse;min-width:1400px}
th{background:#0b1837;text-align:left;position:sticky;top:0;z-index:2;white-space:nowrap}
th,td{border-bottom:1px solid var(--line);padding:7px 10px;font-size:12px}
td.num{text-align:right}
.row-ok td{background:var(--rowOk)}
.row-warn td{background:var(--rowWarn)}
.row-danger td{background:var(--rowDanger)}
.badge{display:inline-flex;align-items:center;padding:3px 8px;border-radius:999px;
  font-size:11px;font-weight:700;border:1px solid rgba(255,255,255,.15);background:rgba(255,255,255,.05)}
.pager{display:flex;align-items:center;gap:10px;margin-top:10px;font-size:13px;flex-wrap:wrap}
.pager button{padding:5px 14px;border-radius:8px;border:1px solid rgba(255,255,255,.2);
  background:#0f214b;color:#fff;cursor:pointer;font-size:13px}
.pager button:disabled{opacity:.4;cursor:default}
.small{color:#c1cde3;font-size:12px}
</style>
</head>
<body>

<div class="header">
  <div class="header-left">
    <h1>Estado de máquinas real a: <span class="fecha-highlight" id="header_fecha">—</span></h1>
    <div class="sub">Alineada = En SCCM · Productiva/Operativa en DA · Productiva/Operativa en Minerva</div>
  </div>
  <a class="btn-back" href="app.html">
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"/></svg>
    Volver a la app
  </a>
</div>

<div class="controls">
  <div class="ctrl"><label>Fecha</label><select id="sel_fecha"></select></div>
  <div class="ctrl"><label>Entorno</label><select id="sel_env"></select></div>
  <div class="ctrl"><label>Entidad</label><select id="sel_ent"></select></div>
  <div class="ctrl"><label>Subentidad</label><select id="sel_sub"></select></div>
  <div class="ctrl"><label>Rango reporte</label><select id="sel_range"></select></div>
  <div class="ctrl"><label>SCCM</label><select id="sel_sccm"></select></div>
  <div class="ctrl"><label>DA</label><select id="sel_da"></select></div>
  <div class="ctrl"><label>Minerva</label><select id="sel_minerva"></select></div>
  <div class="ctrl"><label>Cruce</label><select id="sel_cruce"></select></div>

  <div class="search-box">
    <label style="font-size:11px;color:#b7c3d9;margin-bottom:4px;text-transform:uppercase;letter-spacing:.04em">
      Buscar máquinas (is one of)
    </label>
    <div class="search-input-wrap" style="position:relative">
      <input type="text" id="search_input" placeholder="Escribe o pega nombres, pulsa Enter o coma…" autocomplete="off">
      <button class="search-clear" onclick="clearSearch()" title="Limpiar búsqueda">×</button>
      <div class="search-dropdown" id="search_dropdown"></div>
    </div>
    <div class="search-tags" id="search_tags"></div>
  </div>

  <button class="btn-export" onclick="exportCSV()">⬇ Exportar CSV</button>
</div>

<!-- KPIs -->
<div class="card">
  <div class="kpis">
    <div class="kpi">
      <div class="label">Total filtradas</div>
      <div class="value" id="k_total">0</div>
      <div class="small">máquinas en selección</div>
    </div>
    <div class="kpi">
      <div class="label">Reportan hoy</div>
      <div class="value" id="k_hoy" style="color:var(--ok)">0</div>
      <div class="small">Activity = snapshot</div>
    </div>
    <div class="kpi">
      <div class="label">1–2 días</div>
      <div class="value" id="k_12" style="color:var(--info)">0</div>
      <div class="small">sin reportar</div>
    </div>
    <div class="kpi">
      <div class="label">3–10 días</div>
      <div class="value" id="k_310" style="color:var(--warn)">0</div>
      <div class="small">sin reportar</div>
    </div>
    <div class="kpi">
      <div class="label">&gt;10 días</div>
      <div class="value" id="k_gt10" style="color:var(--danger)">0</div>
      <div class="small">candidatas a purga</div>
    </div>
    <div class="kpi">
      <div class="label">Alineadas</div>
      <div class="value" id="k_alin" style="color:var(--ok)">0</div>
      <div class="small">SCCM + DA + Minerva OK</div>
    </div>
    <div class="kpi">
      <div class="label">Desalineadas</div>
      <div class="value" id="k_desalin" style="color:var(--danger)">0</div>
      <div class="small">estado discrepante</div>
    </div>
    <div class="kpi">
      <div class="label">Parcial / Sin datos</div>
      <div class="value" id="k_parcial" style="color:var(--warn)">0</div>
      <div class="small">falta alguna fuente</div>
    </div>
  </div>
</div>

<!-- Gráficos -->
<div class="layout">

  <!-- PANEL IZQUIERDO: Rangos de reporte -->
  <div class="card chartCard">
    <p class="side-panel-title">Rangos de reporte</p>

    <div class="stat-row-mini">
      <div class="stat-mini">
        <div class="sm-lbl">Hoy</div>
        <div class="sm-val" id="sp_hoy" style="color:var(--ok)">0</div>
        <div class="sm-sub" id="sp_hoy_pct">0%</div>
      </div>
      <div class="stat-mini">
        <div class="sm-lbl">1–2 días</div>
        <div class="sm-val" id="sp_12" style="color:var(--info)">0</div>
        <div class="sm-sub" id="sp_12_pct">0%</div>
      </div>
    </div>
    <div class="stat-row-mini">
      <div class="stat-mini">
        <div class="sm-lbl">3–10 días</div>
        <div class="sm-val" id="sp_310" style="color:var(--warn)">0</div>
        <div class="sm-sub" id="sp_310_pct">0%</div>
      </div>
      <div class="stat-mini">
        <div class="sm-lbl">&gt;10 días</div>
        <div class="sm-val" id="sp_gt10" style="color:var(--danger)">0</div>
        <div class="sm-sub" id="sp_gt10_pct">0%</div>
      </div>
    </div>

    <div class="sep"></div>

    <div class="prog-row">
      <div class="prog-label"><span>Hoy</span><span id="pb_hoy_pct" style="color:var(--ok)">0%</span></div>
      <div class="prog-bar"><div class="prog-fill" id="pb_hoy" style="background:var(--ok);width:0%"></div></div>
    </div>
    <div class="prog-row">
      <div class="prog-label"><span>1–2 días</span><span id="pb_12_pct" style="color:var(--info)">0%</span></div>
      <div class="prog-bar"><div class="prog-fill" id="pb_12" style="background:var(--info);width:0%"></div></div>
    </div>
    <div class="prog-row">
      <div class="prog-label"><span>3–10 días</span><span id="pb_310_pct" style="color:var(--warn)">0%</span></div>
      <div class="prog-bar"><div class="prog-fill" id="pb_310" style="background:var(--warn);width:0%"></div></div>
    </div>
    <div class="prog-row">
      <div class="prog-label"><span>&gt;10 días</span><span id="pb_gt10_pct" style="color:var(--danger)">0%</span></div>
      <div class="prog-bar"><div class="prog-fill" id="pb_gt10" style="background:var(--danger);width:0%"></div></div>
    </div>

    <div class="sep"></div>

    <div class="summary-row">
      <span>Total en selección</span>
      <span id="sp_total_sum" style="font-size:13px;font-weight:700;color:#fff">0</span>
    </div>
    <div class="summary-row">
      <span>Candidatas a purga (&gt;10d)</span>
      <span id="sp_purga" style="color:var(--danger);font-weight:700">0</span>
    </div>

    <div class="chart-mini-wrap">
      <canvas id="ch_bars" role="img" aria-label="Gráfico de barras de rangos de reporte"></canvas>
    </div>
  </div>

  <!-- PANEL CENTRAL: Evolución histórica -->
  <div class="card chartCard" style="flex:2;min-width:400px">
    <p class="side-panel-title">Evolución histórica</p>
    <canvas id="ch_history" height="200" role="img" aria-label="Gráfico de evolución histórica de rangos"></canvas>
  </div>

  <!-- PANEL DERECHO: Alineación por BBDD -->
  <div class="card chartCard">
    <p class="side-panel-title">Alineación por BBDD</p>

    <div style="display:flex;gap:10px;margin-bottom:12px">
      <div class="stat-mini" style="flex:1">
        <div class="sm-lbl">Alineadas</div>
        <div class="sm-val" id="cr_alin" style="color:var(--ok)">0</div>
        <div class="sm-sub" id="cr_alin_pct">0%</div>
      </div>
      <div class="stat-mini" style="flex:1">
        <div class="sm-lbl">Desalineadas</div>
        <div class="sm-val" id="cr_desalin" style="color:var(--danger)">0</div>
        <div class="sm-sub" id="cr_desalin_pct">0%</div>
      </div>
    </div>

    <div class="align-rate">
      <span class="rate-val" id="cr_rate" style="color:var(--ok)">0%</span>
      <span class="rate-lbl">tasa de alineación global</span>
    </div>

    <div class="sep"></div>

    <div class="section-label">Estado por fuente</div>
    <div class="prog-row">
      <div class="prog-label">
        <span>SCCM <span style="color:#475569">— En SCCM</span></span>
        <span id="src_sccm_pct" style="color:var(--ok)">0%</span>
      </div>
      <div class="prog-bar"><div class="prog-fill" id="src_sccm_bar" style="background:var(--ok);width:0%"></div></div>
    </div>
    <div class="prog-row">
      <div class="prog-label">
        <span>DA <span style="color:#475569">— Productiva/Operativa</span></span>
        <span id="src_da_pct" style="color:var(--ok)">0%</span>
      </div>
      <div class="prog-bar"><div class="prog-fill" id="src_da_bar" style="background:var(--ok);width:0%"></div></div>
    </div>
    <div class="prog-row">
      <div class="prog-label">
        <span>Minerva <span style="color:#475569">— Productiva/Operativa</span></span>
        <span id="src_min_pct" style="color:var(--warn)">0%</span>
      </div>
      <div class="prog-bar"><div class="prog-fill" id="src_min_bar" style="background:var(--warn);width:0%"></div></div>
    </div>

    <div class="sep"></div>

    <div class="section-label">Causas de desalineación</div>
    <div class="cause-row">
      <div class="cause-dot" style="background:var(--danger)"></div>
      <span class="cause-name">Solo fuera de SCCM</span>
      <span class="cause-val" id="ca_sccm">0</span>
      <span class="cause-pct" id="ca_sccm_p"></span>
    </div>
    <div class="cause-row">
      <div class="cause-dot" style="background:var(--warn)"></div>
      <span class="cause-name">Solo DA no OK</span>
      <span class="cause-val" id="ca_da">0</span>
      <span class="cause-pct" id="ca_da_p"></span>
    </div>
    <div class="cause-row">
      <div class="cause-dot" style="background:var(--purple)"></div>
      <span class="cause-name">Solo Minerva no OK</span>
      <span class="cause-val" id="ca_min">0</span>
      <span class="cause-pct" id="ca_min_p"></span>
    </div>
    <div class="cause-row">
      <div class="cause-dot" style="background:var(--slate)"></div>
      <span class="cause-name">Múltiples fuentes KO</span>
      <span class="cause-val" id="ca_multi">0</span>
      <span class="cause-pct" id="ca_multi_p"></span>
    </div>

    <div class="sep"></div>
    <div class="summary-row">
      <span>Parcial / Sin datos</span>
      <span id="cr_parcial" style="color:var(--warn);font-weight:700">0</span>
    </div>
  </div>

</div>

<!-- Tabla -->
<div class="card tableCard">
  <h2 style="font-size:15px">
    Detalle de máquinas
    <span id="tbl_count" class="small"></span>
  </h2>
  <div class="tableWrap" id="tbl_wrap"></div>
  <div class="pager">
    <button id="btn_prev" onclick="changePage(-1)">← Anterior</button>
    <span id="pager_info" class="small"></span>
    <button id="btn_next" onclick="changePage(1)">Siguiente →</button>
    <span class="small" style="color:#6b7fa3">200 filas por página</span>
  </div>
</div>

<script>
const DATA    = __DATA__;
const HISTORY = __HISTORY__;

const PAGE_SIZE = 200;
let currentPage  = 0;
let filteredRows = [];
let searchTerms  = [];
let chBars = null, chHistory = null;

const fmt  = n => Number(n||0).toLocaleString("es-ES");
const pct  = (a,b) => b ? (a/b*100).toFixed(1)+"%" : "0%";
const esc  = s => String(s||"").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");
const DA_MIN_OK = new Set(["Productiva","Productivo","Operativa","Operativo"]);

function getV(id){ return document.getElementById(id).value; }
function setTxt(id,v){ document.getElementById(id).textContent = v; }
function setStyle(id,prop,v){ document.getElementById(id).style[prop] = v; }

// ── Exportar CSV ──────────────────────────────────────────
function exportCSV() {
  const headers = ["Fecha","Entorno","Entidad","Subentidad","Máquina",
    "Último reporte","Días sin reporte","Rango","SCCM","DA","Minerva","Cruce"];
  const fields  = ["fecha","env","ent","sub","machine",
    "activity","days_without_report","range","sccm","da","minerva","cruce"];
  const cell = v => {
    const s = String(v===null||v===undefined?"":v);
    return /[",\n\r]/.test(s) ? '"'+s.replace(/"/g,'""')+'"' : s;
  };
  const lines = [headers.join(",")];
  filteredRows.forEach(r => lines.push(fields.map(f=>cell(r[f])).join(",")));
  const bom  = "\uFEFF";
  const blob = new Blob([bom+lines.join("\r\n")],{type:"text/csv;charset=utf-8;"});
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement("a");
  const fechaSel = getV("sel_fecha").replace(/-/g,"");
  const now  = new Date();
  const ts   = now.getFullYear()+String(now.getMonth()+1).padStart(2,"0")+String(now.getDate()).padStart(2,"0")
               +"_"+String(now.getHours()).padStart(2,"0")+String(now.getMinutes()).padStart(2,"0");
  a.href = url; a.download = `dashboard_${fechaSel}_export_${ts}.csv`;
  document.body.appendChild(a); a.click(); document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

// ── Buscador is-one-of ────────────────────────────────────
function parsePaste(raw){
  return raw.split(/[,;\t\n\r]+/)
    .map(s=>s.trim().replace(/[\u00A0\u200B\u200C\u200D\uFEFF]/g,"").trim())
    .filter(Boolean);
}
function addTerms(terms){
  terms.forEach(t=>{
    const tl=t.toLowerCase().trim();
    if(tl && !searchTerms.some(s=>s.toLowerCase().trim()===tl)) searchTerms.push(t.trim());
  });
  renderTags(); render();
}
function removeTerm(t){ searchTerms=searchTerms.filter(s=>s!==t); renderTags(); render(); }
function clearSearch(){
  searchTerms=[]; document.getElementById("search_input").value="";
  closeDropdown(); renderTags(); render();
}
function renderTags(){
  document.getElementById("search_tags").innerHTML = searchTerms.map(t=>
    `<span class="tag">${esc(t)}<button onclick='removeTerm(${JSON.stringify(t)})' title="Quitar">×</button></span>`
  ).join("");
}
let _allMachines=null;
function getAllMachines(){
  if(!_allMachines){
    const f=getV("sel_fecha"); const set=new Set();
    DATA.rows.forEach(r=>{ if(r.fecha===f) set.add(r.machine); });
    _allMachines=[...set].sort();
  }
  return _allMachines;
}
function openDropdown(query){
  const dd=document.getElementById("search_dropdown");
  if(!query){ dd.classList.remove("open"); return; }
  const ql=query.toLowerCase();
  const matches=getAllMachines().filter(m=>m.toLowerCase().includes(ql)).slice(0,30);
  if(!matches.length){ dd.classList.remove("open"); return; }
  dd.innerHTML=matches.map(m=>`<div onclick='addTerms([${JSON.stringify(m)}]);document.getElementById("search_input").value="";closeDropdown()'>${esc(m)}</div>`).join("");
  dd.classList.add("open");
}
function closeDropdown(){ document.getElementById("search_dropdown").classList.remove("open"); }
document.getElementById("search_input").addEventListener("input",e=>{
  const raw=e.target.value;
  if(/[,;\t\n\r]/.test(raw)){ const t=parsePaste(raw); if(t.length) addTerms(t); e.target.value=""; closeDropdown(); }
  else openDropdown(raw.trim());
});
document.getElementById("search_input").addEventListener("keydown",e=>{
  if(e.key==="Enter"){ e.preventDefault(); const v=e.target.value.trim(); if(v){ addTerms(parsePaste(v)); e.target.value=""; } closeDropdown(); }
  if(e.key==="Escape") closeDropdown();
});
document.addEventListener("click",e=>{ if(!e.target.closest(".search-box")) closeDropdown(); });

// ── Combos ────────────────────────────────────────────────
function updateHeaderFecha(){
  const f=getV("sel_fecha");
  const now=new Date();
  const hora=String(now.getHours()).padStart(2,"0")+":"+String(now.getMinutes()).padStart(2,"0");
  // Formatear fecha YYYY-MM-DD → DD/MM/YYYY
  const parts=f.split("-");
  const fechaFmt=parts.length===3?parts[2]+"/"+parts[1]+"/"+parts[0]:f;
  document.getElementById("header_fecha").textContent=fechaFmt+" · "+hora+"h";
}

function buildStaticCombos(){
  const fs=document.getElementById("sel_fecha");
  fs.innerHTML=""; DATA.fechas.forEach(f=>fs.appendChild(new Option(f,f)));
  if(DATA.fechas.length) fs.value=DATA.fechas[DATA.fechas.length-1];
  const es=document.getElementById("sel_env");
  es.innerHTML=""; es.appendChild(new Option("(Todos)","ALL"));
  [...new Set(DATA.rows.map(r=>r.env))].sort().forEach(v=>es.appendChild(new Option(v,v)));
  const rs=document.getElementById("sel_range");
  rs.innerHTML="";
  [["(Todos)","ALL"],["Hoy","HOY"],["1–2 días","1-2 días"],["3–10 días","3-10 días"],[">10 días",">10 días"]]
    .forEach(([t,v])=>rs.appendChild(new Option(t,v)));
  const cs=document.getElementById("sel_cruce");
  cs.innerHTML="";
  [["(Todos)","ALL"],["Alineada","Alineada"],["Desalineada","Desalineada"],["Parcial","Parcial"],["Sin datos","Sin datos"]]
    .forEach(([t,v])=>cs.appendChild(new Option(t,v)));
}
function rebuildDependentCombos(){
  const fecha=getV("sel_fecha"); const env=getV("sel_env");
  _allMachines=null;
  const entSel=document.getElementById("sel_ent"); const curEnt=entSel.value;
  const ents=new Set();
  DATA.rows.forEach(r=>{ if(r.fecha!==fecha) return; if(env!=="ALL"&&r.env!==env) return; ents.add(r.ent); });
  entSel.innerHTML=""; entSel.appendChild(new Option("(Todos)","ALL"));
  [...ents].sort().forEach(v=>entSel.appendChild(new Option(v,v)));
  entSel.value=[...entSel.options].some(o=>o.value===curEnt)?curEnt:"ALL";
  const subSel=document.getElementById("sel_sub"); const curSub=subSel.value;
  const subs=new Set();
  DATA.rows.forEach(r=>{ if(r.fecha!==fecha) return; if(env!=="ALL"&&r.env!==env) return; if(getV("sel_ent")!=="ALL"&&r.ent!==getV("sel_ent")) return; subs.add(r.sub); });
  subSel.innerHTML=""; subSel.appendChild(new Option("(Todos)","ALL"));
  [...subs].sort().forEach(v=>subSel.appendChild(new Option(v,v)));
  subSel.value=[...subSel.options].some(o=>o.value===curSub)?curSub:"ALL";
  rebuildValueCombo("sel_sccm","sccm",fecha,env);
  rebuildValueCombo("sel_da","da",fecha,env);
  rebuildValueCombo("sel_minerva","minerva",fecha,env);
}
function rebuildValueCombo(selId,field,fecha,env){
  const sel=document.getElementById(selId); const cur=sel.value; const vals=new Set();
  DATA.rows.forEach(r=>{ if(r.fecha!==fecha) return; if(env!=="ALL"&&r.env!==env) return; if(r[field]) vals.add(r[field]); });
  sel.innerHTML=""; sel.appendChild(new Option("(Todos)","ALL"));
  [...vals].sort().forEach(v=>sel.appendChild(new Option(v,v)));
  sel.value=[...sel.options].some(o=>o.value===cur)?cur:"ALL";
}

// ── Filtrado ──────────────────────────────────────────────
function applyFilters(){
  const fecha=getV("sel_fecha"),env=getV("sel_env"),ent=getV("sel_ent"),sub=getV("sel_sub");
  const range=getV("sel_range"),sccm=getV("sel_sccm"),da=getV("sel_da");
  const minerva=getV("sel_minerva"),cruce=getV("sel_cruce");
  const terms=searchTerms.map(t=>t.toLowerCase());
  filteredRows=DATA.rows.filter(r=>{
    if(r.fecha!==fecha) return false;
    if(env!=="ALL"&&r.env!==env) return false;
    if(ent!=="ALL"&&r.ent!==ent) return false;
    if(sub!=="ALL"&&r.sub!==sub) return false;
    if(range!=="ALL"&&r.range!==range) return false;
    if(sccm!=="ALL"&&r.sccm!==sccm) return false;
    if(da!=="ALL"&&r.da!==da) return false;
    if(minerva!=="ALL"&&r.minerva!==minerva) return false;
    if(cruce!=="ALL"&&r.cruce!==cruce) return false;
    if(terms.length){ const ml=r.machine.toLowerCase().trim(); if(!terms.some(t=>t.toLowerCase().trim()===ml)) return false; }
    return true;
  });
  currentPage=0;
}

function counts(){
  let hoy=0,r12=0,r310=0,gt10=0,alin=0,desalin=0,parcial=0,sindat=0;
  let sccmOk=0,daOk=0,minOk=0;
  let caSccm=0,caDa=0,caMin=0,caMulti=0;
  const tot=filteredRows.length||1;
  filteredRows.forEach(r=>{
    if(r.range==="HOY") hoy++;
    else if(r.range==="1-2 días") r12++;
    else if(r.range==="3-10 días") r310++;
    else if(r.range===">10 días") gt10++;
    if(r.cruce==="Alineada") alin++;
    else if(r.cruce==="Desalineada") desalin++;
    else if(r.cruce==="Parcial") parcial++;
    else sindat++;
    // por fuente
    const s=(r.sccm==="En SCCM");
    const d=DA_MIN_OK.has(r.da);
    const m=DA_MIN_OK.has(r.minerva);
    if(s) sccmOk++; if(d) daOk++; if(m) minOk++;
    // causas desalineación
    if(r.cruce==="Desalineada"){
      const ko=(!s?1:0)+(!d?1:0)+(!m?1:0);
      if(ko>=2) caMulti++;
      else if(!s) caSccm++;
      else if(!d) caDa++;
      else caMin++;
    }
  });
  return {hoy,r12,r310,gt10,alin,desalin,parcial,sindat,
          sccmOk,daOk,minOk,caSccm,caDa,caMin,caMulti,tot:filteredRows.length};
}

// ── KPIs principales ──────────────────────────────────────
function renderKpis(){
  const c=counts();
  setTxt("k_total",fmt(c.tot));
  setTxt("k_hoy",fmt(c.hoy));
  setTxt("k_12",fmt(c.r12));
  setTxt("k_310",fmt(c.r310));
  setTxt("k_gt10",fmt(c.gt10));
  setTxt("k_alin",fmt(c.alin));
  setTxt("k_desalin",fmt(c.desalin));
  setTxt("k_parcial",fmt(c.parcial+c.sindat));
}

// ── Panel izquierdo: Rangos ───────────────────────────────
function renderBars(){
  const c=counts();
  const tot=c.tot||1;
  const p=v=>(v/tot*100).toFixed(1);

  // mini-KPIs
  setTxt("sp_hoy",fmt(c.hoy));    setTxt("sp_hoy_pct",p(c.hoy)+"%");
  setTxt("sp_12",fmt(c.r12));     setTxt("sp_12_pct",p(c.r12)+"%");
  setTxt("sp_310",fmt(c.r310));   setTxt("sp_310_pct",p(c.r310)+"%");
  setTxt("sp_gt10",fmt(c.gt10));  setTxt("sp_gt10_pct",p(c.gt10)+"%");
  setTxt("sp_total_sum",fmt(c.tot));
  setTxt("sp_purga",fmt(c.gt10)+" ("+p(c.gt10)+"%)");

  // barras de progreso
  setTxt("pb_hoy_pct",p(c.hoy)+"%");   setStyle("pb_hoy","width",p(c.hoy)+"%");
  setTxt("pb_12_pct",p(c.r12)+"%");    setStyle("pb_12","width",p(c.r12)+"%");
  setTxt("pb_310_pct",p(c.r310)+"%");  setStyle("pb_310","width",p(c.r310)+"%");
  setTxt("pb_gt10_pct",p(c.gt10)+"%"); setStyle("pb_gt10","width",p(c.gt10)+"%");

  // gráfico de barras
  const SCALE={x:{ticks:{color:"#64748b",font:{size:10}},grid:{display:false}},
               y:{ticks:{color:"#64748b",font:{size:10},callback:v=>v>=1000?Math.round(v/1000)+"k":v},grid:{color:"rgba(255,255,255,.05)"}}};
  if(chBars) chBars.destroy();
  chBars=new Chart(document.getElementById("ch_bars"),{
    type:"bar",
    data:{
      labels:["Hoy","1–2 días","3–10 días",">10 días"],
      datasets:[{data:[c.hoy,c.r12,c.r310,c.gt10],
        backgroundColor:["#22c55e","#3b82f6","#f59e0b","#ef4444"],
        borderWidth:0,borderRadius:4}]
    },
    options:{responsive:true,maintainAspectRatio:false,
      plugins:{legend:{display:false},tooltip:{callbacks:{label:v=>fmt(v.raw)}}},
      scales:SCALE}
  });
}

// ── Panel central: Histórico ──────────────────────────────
function renderHistory(){
  const SCALE={x:{ticks:{color:"#64748b",font:{size:10}},grid:{color:"rgba(255,255,255,.05)"}},
               y:{ticks:{color:"#64748b",font:{size:10},callback:v=>v>=1000?Math.round(v/1000)+"k":v},grid:{color:"rgba(255,255,255,.05)"}}};
  if(chHistory) chHistory.destroy();
  chHistory=new Chart(document.getElementById("ch_history"),{
    type:"line",
    data:{
      labels:HISTORY.labels,
      datasets:[
        {label:"Hoy",      data:HISTORY.hoy,  borderColor:"#22c55e",tension:.3,fill:false,pointRadius:2,borderWidth:2},
        {label:"1–2 días", data:HISTORY.r12,  borderColor:"#3b82f6",tension:.3,fill:false,pointRadius:2,borderWidth:2},
        {label:"3–10 días",data:HISTORY.r310, borderColor:"#f59e0b",tension:.3,fill:false,pointRadius:2,borderWidth:2},
        {label:">10 días", data:HISTORY.gt10, borderColor:"#ef4444",tension:.3,fill:false,pointRadius:2,borderWidth:2},
      ]
    },
    options:{responsive:true,maintainAspectRatio:true,
      plugins:{legend:{labels:{color:"#94a3b8",boxWidth:12,font:{size:11}}}},scales:SCALE}
  });
}

// ── Panel derecho: Alineación ─────────────────────────────
function renderCruce(){
  const c=counts();
  const tot=c.tot||1;
  const desalin=c.desalin||1;

  // contadores y tasa
  setTxt("cr_alin",fmt(c.alin));
  setTxt("cr_alin_pct",(c.alin/tot*100).toFixed(1)+"%");
  setTxt("cr_desalin",fmt(c.desalin));
  setTxt("cr_desalin_pct",(c.desalin/tot*100).toFixed(1)+"%");
  setTxt("cr_rate",(c.alin/tot*100).toFixed(1)+"%");
  const rateEl=document.getElementById("cr_rate");
  rateEl.style.color=c.alin/tot>=.7?"#22c55e":c.alin/tot>=.5?"#f59e0b":"#ef4444";

  // barras por fuente
  const sp=(v)=>(v/tot*100).toFixed(1);
  const sccmP=sp(c.sccmOk), daP=sp(c.daOk), minP=sp(c.minOk);
  setTxt("src_sccm_pct",sccmP+"%"); setStyle("src_sccm_bar","width",sccmP+"%");
  document.getElementById("src_sccm_pct").style.color=c.sccmOk/tot>=.7?"#22c55e":"#f59e0b";
  document.getElementById("src_sccm_bar").style.background=c.sccmOk/tot>=.7?"#22c55e":"#f59e0b";
  setTxt("src_da_pct",daP+"%"); setStyle("src_da_bar","width",daP+"%");
  document.getElementById("src_da_pct").style.color=c.daOk/tot>=.7?"#22c55e":"#f59e0b";
  document.getElementById("src_da_bar").style.background=c.daOk/tot>=.7?"#22c55e":"#f59e0b";
  setTxt("src_min_pct",minP+"%"); setStyle("src_min_bar","width",minP+"%");
  document.getElementById("src_min_pct").style.color=c.minOk/tot>=.7?"#22c55e":"#f59e0b";
  document.getElementById("src_min_bar").style.background=c.minOk/tot>=.7?"#22c55e":"#f59e0b";

  // causas
  const pp=v=>c.desalin>0?" ("+((v/c.desalin)*100).toFixed(0)+"%)":"";
  setTxt("ca_sccm",fmt(c.caSccm));   setTxt("ca_sccm_p",pp(c.caSccm));
  setTxt("ca_da",fmt(c.caDa));       setTxt("ca_da_p",pp(c.caDa));
  setTxt("ca_min",fmt(c.caMin));     setTxt("ca_min_p",pp(c.caMin));
  setTxt("ca_multi",fmt(c.caMulti)); setTxt("ca_multi_p",pp(c.caMulti));

  // parcial / sin datos
  setTxt("cr_parcial",fmt(c.parcial+c.sindat));
}

// ── Tabla ─────────────────────────────────────────────────
function rowCls(range){
  return range==="HOY"?"row-ok":range==="3-10 días"?"row-warn":range===">10 días"?"row-danger":"";
}
function badgeCruce(c){
  const s={
    "Alineada":   "background:rgba(34,197,94,.2);border-color:rgba(34,197,94,.6)",
    "Desalineada":"background:rgba(239,68,68,.2);border-color:rgba(239,68,68,.6)",
    "Parcial":    "background:rgba(245,158,11,.2);border-color:rgba(245,158,11,.6)",
    "Sin datos":  "background:rgba(100,116,139,.2);border-color:rgba(100,116,139,.6)",
  };
  return `<span class="badge" style="${s[c]||""}">${esc(c)}</span>`;
}
function renderTable(){
  const wrap=document.getElementById("tbl_wrap");
  const total=filteredRows.length;
  const pages=Math.max(1,Math.ceil(total/PAGE_SIZE));
  currentPage=Math.min(currentPage,pages-1);
  setTxt("tbl_count",total?`(${fmt(total)} máquinas · pág. ${currentPage+1}/${pages})`:"");
  setTxt("pager_info",`Página ${currentPage+1} de ${pages}`);
  document.getElementById("btn_prev").disabled=currentPage===0;
  document.getElementById("btn_next").disabled=currentPage>=pages-1;
  if(!total){ wrap.innerHTML='<div class="small" style="padding:12px">Sin datos con los filtros actuales.</div>'; return; }
  const slice=filteredRows.slice(currentPage*PAGE_SIZE,(currentPage+1)*PAGE_SIZE);
  wrap.innerHTML=`<table>
    <thead><tr>
      <th>Máquina</th><th>Entorno</th><th>Entidad</th><th>Subentidad</th>
      <th>Último reporte</th><th class="num">Días</th><th>Rango</th>
      <th>SCCM</th><th>DA</th><th>Minerva</th><th>Cruce</th>
    </tr></thead>
    <tbody>${slice.map(r=>`<tr class="${rowCls(r.range)}">
      <td>${esc(r.machine)}</td><td>${esc(r.env)}</td><td>${esc(r.ent)}</td><td>${esc(r.sub)}</td>
      <td>${esc(r.activity)}</td><td class="num">${fmt(r.days_without_report)}</td><td>${esc(r.range)}</td>
      <td>${esc(r.sccm)}</td><td>${esc(r.da)}</td><td>${esc(r.minerva)}</td>
      <td>${badgeCruce(r.cruce)}</td></tr>`).join("")}
    </tbody></table>`;
}
function changePage(d){ currentPage+=d; renderTable(); document.getElementById("tbl_wrap").scrollTop=0; }

// ── Render principal ──────────────────────────────────────
function render(){
  applyFilters();
  renderKpis();
  renderBars();
  renderHistory();
  renderCruce();
  renderTable();
}

// ── Eventos ───────────────────────────────────────────────
document.getElementById("sel_fecha").addEventListener("change",()=>{updateHeaderFecha();rebuildDependentCombos();render();});
document.getElementById("sel_env").addEventListener("change",()=>{rebuildDependentCombos();render();});
["sel_ent","sel_sub"].forEach(id=>
  document.getElementById(id).addEventListener("change",()=>{rebuildDependentCombos();render();})
);
["sel_range","sel_sccm","sel_da","sel_minerva","sel_cruce"].forEach(id=>
  document.getElementById(id).addEventListener("change",render)
);

buildStaticCombos();
rebuildDependentCombos();
updateHeaderFecha();
render();
</script>
</body>
</html>
"""

def build_html(data):
    return (HTML_TEMPLATE
            .replace("__DATA__",    json.dumps({"fechas": data["fechas"], "rows": data["rows"]}, ensure_ascii=False))
            .replace("__HISTORY__", json.dumps(data["history"], ensure_ascii=False)))

# =========================================================
# MAIN
# =========================================================
def main():
    ensure_dir(OUTPUT_DIR)
    print("🔍 Input:", INPUT_DIR)
    fechas, rows, history = load_data()
    html = build_html({"fechas": fechas, "rows": rows, "history": history})
    with open(OUT_HTML, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"\n✅ Dashboard: {OUT_HTML}")
    print(f"✅ Fechas: {len(fechas)}  |  Máquinas (snapshots): {len(rows)}")

if __name__ == "__main__":
    main()
