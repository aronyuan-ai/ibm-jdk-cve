# -*- coding: utf-8 -*-
"""
IBM JDK / Semeru Runtimes CVE report generator.

On each run it tries to LIVE-SCRAPE the official IBM vulnerability pages and
rebuild index.html. If scraping fails (network blocked, page markup changed,
IBM returns an error, too few rows parsed, ...) it falls back to the bundled
snapshot in snapshot.py so the page always rebuilds.

Usage:
    pip install -r requirements.txt
    python generate.py

Output: index.html  (self-contained, ready for GitHub Pages)
"""
import json, re, sys, datetime

# ---- source pages -----------------------------------------------------------
SOURCES = [
    ("IBM Semeru Runtimes",
     "https://www.ibm.com/support/pages/semeru-runtimes-security-vulnerabilities"),
    ("IBM SDK Java Technology Edition",
     "https://www.ibm.com/support/pages/java-sdk-security-vulnerabilities"),
]

MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
     "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], start=1)}

# A line that names an advisory / update batch (used to title each table).
TITLE_RE = re.compile(
    r'((?:Oracle|OpenJDK)\s+\w+\s+\d{1,2}\s+\d{4}.*?(?:CPU|Vulnerability Advisory)'
    r'|IBM Security Update\s+\w+\s+\d{4})', re.I)
CVE_RE = re.compile(r'CVE-\d{4}-\d{3,7}', re.I)
VER_RE = re.compile(r'\d+\.\d+\.\d+(?:\.\d+)?')


def _parse_date(title):
    """Return YYYY-MM-DD parsed from an advisory title."""
    m = re.search(r'([A-Z][a-z]{2})[a-z]*\s+(\d{1,2})\s+(\d{4})', title)
    if m:
        mo = MONTHS.get(m.group(1)[:3].title())
        if mo:
            return "%s-%02d-%02d" % (m.group(3), mo, int(m.group(2)))
    m = re.search(r'([A-Z][a-z]{2})[a-z]*\s+(\d{4})', title)   # "Month YYYY"
    if m:
        mo = MONTHS.get(m.group(1)[:3].title())
        if mo:
            # IBM monthly updates have no day; use month end for stable sorting
            import calendar
            d = calendar.monthrange(int(m.group(2)), mo)[1]
            return "%s-%02d-%02d" % (m.group(2), mo, d)
    return "1970-01-01"


def _line_of(header):
    """Map a fix-column header to a JDK line number, e.g. 'Semeru 17 Fix'->'17'."""
    h = header.lower()
    if "cve" in h or "cvss" in h or "note" in h:
        return None
    if not any(k in h for k in ("fix", "semeru", "ibm")):
        return None
    m = re.search(r'\b(\d{1,2})\b', h)
    return m.group(1) if m else None


def severity(cvss):
    if cvss >= 9.0: return "Critical"
    if cvss >= 7.0: return "High"
    if cvss >= 4.0: return "Medium"
    return "Low"


def scrape():
    """Return list of entry dicts, or [] on any failure."""
    try:
        import requests
        from bs4 import BeautifulSoup
    except Exception as e:
        print("[scrape] libraries unavailable:", e)
        return []

    headers = {"User-Agent": "Mozilla/5.0 (compatible; IBM-JDK-CVE-report/1.0)"}
    entries = []

    for product, url in SOURCES:
        try:
            r = requests.get(url, headers=headers, timeout=30)
            r.raise_for_status()
            soup = BeautifulSoup(r.text, "lxml")
        except Exception as e:
            print("[scrape] fetch failed for %s: %s" % (url, e))
            return []   # give up entirely -> fall back to snapshot

        tables = soup.find_all("table")
        for table in tables:
            try:
                rows = table.find_all("tr")
                if len(rows) < 2:
                    continue
                headers_txt = [c.get_text(" ", strip=True)
                               for c in rows[0].find_all(["th", "td"])]
                if not any("cve" in h.lower() for h in headers_txt):
                    continue

                col = {"cve": None, "cvss": None, "notes": None, "fix": {}}
                for i, h in enumerate(headers_txt):
                    hl = h.lower()
                    if col["cve"] is None and "cve" in hl:
                        col["cve"] = i
                    elif col["cvss"] is None and "cvss" in hl:
                        col["cvss"] = i
                    elif col["notes"] is None and "note" in hl:
                        col["notes"] = i
                    else:
                        ln = _line_of(h)
                        if ln:
                            col["fix"][i] = ln
                if col["cve"] is None:
                    continue

                # advisory title (nearest preceding matching string) + date + info link
                title = None
                for s in table.find_all_previous(string=True):
                    mt = TITLE_RE.search(s.strip())
                    if mt:
                        title = mt.group(1).strip()
                        break
                if not title:
                    title = product + " advisory"
                date = _parse_date(title)

                info = url
                p = table.find_next(
                    lambda t: t.name in ("p", "div")
                    and "Further information" in t.get_text())
                if p:
                    a = p.find("a", href=True)
                    if a:
                        info = a["href"]

                for tr in rows[1:]:
                    cells = tr.find_all(["td", "th"])
                    if len(cells) < 2:
                        continue
                    ctext = [c.get_text(" ", strip=True) for c in cells]
                    mcve = CVE_RE.search(ctext[col["cve"]])
                    if not mcve:
                        continue
                    cve = mcve.group(0).upper()
                    try:
                        cvss = float(re.search(r'\d+(?:\.\d+)?',
                                     ctext[col["cvss"]]).group(0))
                    except Exception:
                        cvss = 0.0
                    fixes = {}
                    for i, ln in col["fix"].items():
                        if i >= len(ctext):
                            continue
                        cell = ctext[i]
                        if "fix in progress" in cell.lower():
                            fixes[ln] = "Fix in progress"
                            continue
                        vers = VER_RE.findall(cell)
                        if vers:
                            fixes[ln] = " ".join(dict.fromkeys(vers))
                    notes = ctext[col["notes"]] if col["notes"] is not None \
                        and col["notes"] < len(ctext) else ""
                    entries.append({
                        "product": product, "bulletin": title, "bulletinUrl": info,
                        "cve": cve, "cveUrl": "https://www.cve.org/CVERecord?id=" + cve,
                        "cvss": cvss, "severity": severity(cvss),
                        "date": date, "fixes": fixes, "notes": notes,
                    })
            except Exception as e:
                print("[scrape] table skipped:", e)
                continue

    # de-duplicate (same CVE + product + date + bulletin)
    seen, uniq = set(), []
    for e in entries:
        key = (e["cve"], e["product"], e["date"], e["bulletin"])
        if key in seen:
            continue
        seen.add(key)
        uniq.append(e)
    return uniq


def build(entries, mode, gen_time):
    entries.sort(key=lambda e: (e["date"], e["cvss"]), reverse=True)
    html = TEMPLATE
    html = html.replace("__DATA__", json.dumps(entries, ensure_ascii=False))
    html = html.replace("__GEN__", gen_time)
    html = html.replace("__MODE__", mode)
    with open("index.html", "w", encoding="utf-8") as f:
        f.write(html)
    crit = len([e for e in entries if e["cvss"] >= 9])
    high = len([e for e in entries if 7 <= e["cvss"] < 9])
    print("wrote index.html | mode=%s | entries=%d critical=%d high=%d"
          % (mode, len(entries), crit, high))


def main():
    gen_time = datetime.datetime.now(datetime.timezone.utc).strftime(
        "%Y-%m-%d %H:%M UTC")
    entries = scrape()
    if len(entries) >= 20:
        mode = "即時擷取 (live)"
    else:
        print("[main] scrape returned %d rows; using snapshot fallback"
              % len(entries))
        import snapshot
        entries = snapshot.get_snapshot_entries()
        mode = "快照 (snapshot fallback)"
    build(entries, mode, gen_time)


# --- HTML template (self-contained) -----------------------------------------
TEMPLATE = r"""<!DOCTYPE html>
<html lang="zh-Hant">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>IBM JDK / Semeru Runtimes — CVE Report</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=IBM+Plex+Sans:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
:root{
  --ink:#0b1f33; --ink2:#14304a; --canvas:#f2f5f8; --surface:#ffffff;
  --line:#d8dfe7; --text:#1a2634; --muted:#5c6a7a; --accent:#0f62fe;
  --crit:#b3121f; --crit-bg:#fbe9ea; --high:#c23a10; --high-bg:#fceee7;
  --med:#9a6a00; --med-bg:#fbf3dd; --low:#4a6076; --low-bg:#eef2f6;
}
*{box-sizing:border-box}
body{margin:0;background:var(--canvas);color:var(--text);
  font-family:"IBM Plex Sans",system-ui,"Noto Sans TC",sans-serif;line-height:1.5;}
a{color:var(--accent);text-decoration:none}
a:hover{text-decoration:underline}
.wrap{max-width:1280px;margin:0 auto;padding:0 20px 64px}
header.top{background:linear-gradient(135deg,var(--ink),var(--ink2));color:#eaf1f8;
  padding:34px 0 26px;border-bottom:3px solid var(--accent)}
header.top .wrap{padding-bottom:0}
h1{font-size:1.7rem;font-weight:700;margin:0 0 12px;letter-spacing:-.01em}
h1 .lock{margin-right:8px}
.meta{font-size:.86rem;color:#b9c9da;display:flex;flex-wrap:wrap;gap:6px 18px;font-family:"IBM Plex Mono",monospace}
.meta b{color:#fff;font-weight:600}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:14px;margin:24px 0 8px}
.card{background:var(--surface);border:1px solid var(--line);border-radius:10px;padding:16px 18px;
  box-shadow:0 1px 2px rgba(11,31,51,.04)}
.card .n{font-family:"IBM Plex Mono",monospace;font-size:2rem;font-weight:600;line-height:1}
.card .l{font-size:.78rem;color:var(--muted);margin-top:6px;text-transform:uppercase;letter-spacing:.05em}
.card.crit .n{color:var(--crit)} .card.high .n{color:var(--high)}
.card.med .n{color:var(--med)} .card.tot .n{color:var(--ink)}
.controls{display:flex;flex-wrap:wrap;gap:10px;align-items:center;margin:22px 0 14px}
.controls input[type=search]{flex:1 1 240px;min-width:200px;padding:9px 12px;border:1px solid var(--line);
  border-radius:8px;font-size:.9rem;font-family:inherit;background:#fff}
.seg{display:inline-flex;border:1px solid var(--line);border-radius:8px;overflow:hidden;background:#fff}
.seg button{border:0;background:#fff;padding:8px 12px;font:inherit;font-size:.82rem;color:var(--muted);cursor:pointer}
.seg button.on{background:var(--ink);color:#fff}
.seg button:not(:last-child){border-right:1px solid var(--line)}
label.lbl{font-size:.78rem;color:var(--muted);text-transform:uppercase;letter-spacing:.04em;margin-right:2px}
.tablewrap{background:var(--surface);border:1px solid var(--line);border-radius:12px;overflow:hidden;
  box-shadow:0 1px 3px rgba(11,31,51,.05)}
table{border-collapse:collapse;width:100%;font-size:.855rem}
thead th{background:#eef2f6;text-align:left;padding:11px 12px;font-weight:600;color:var(--ink);
  border-bottom:2px solid var(--line);white-space:nowrap;position:sticky;top:0;cursor:pointer;user-select:none}
thead th .ar{color:var(--muted);font-size:.7rem;margin-left:3px}
tbody td{padding:10px 12px;border-bottom:1px solid #eef1f4;vertical-align:top}
tbody tr:hover{background:#f7fafd}
.cve{font-family:"IBM Plex Mono",monospace;font-weight:500;white-space:nowrap}
.sev{display:inline-block;padding:2px 9px;border-radius:20px;font-size:.75rem;font-weight:600;white-space:nowrap}
.sev.Critical{background:var(--crit-bg);color:var(--crit)}
.sev.High{background:var(--high-bg);color:var(--high)}
.sev.Medium{background:var(--med-bg);color:var(--med)}
.sev.Low{background:var(--low-bg);color:var(--low)}
.score{font-family:"IBM Plex Mono",monospace;font-weight:600}
.prod{font-size:.8rem;color:var(--muted);white-space:nowrap}
.date{font-family:"IBM Plex Mono",monospace;color:var(--muted);white-space:nowrap}
.fixes{display:flex;flex-wrap:wrap;gap:4px}
.fx{font-family:"IBM Plex Mono",monospace;font-size:.75rem;background:#eef7ef;color:#1c6b2e;
  border:1px solid #cfe8d4;border-radius:6px;padding:1px 6px;white-space:nowrap}
.na{font-size:.78rem;color:var(--muted);font-style:italic}
.notes{font-size:.78rem;color:var(--muted)}
.count{margin:14px 2px 0;font-size:.82rem;color:var(--muted);font-family:"IBM Plex Mono",monospace}
footer.foot{margin-top:26px;padding-top:16px;border-top:1px solid var(--line);
  font-size:.8rem;color:var(--muted);font-family:"IBM Plex Mono",monospace}
.src{font-size:.8rem;color:var(--muted);margin-top:6px}
.src a{margin-right:14px}
.disc{background:#fff8e6;border:1px solid #f0e0b0;border-radius:8px;padding:10px 14px;margin:18px 0 0;
  font-size:.82rem;color:#7a5a00}
@media(max-width:820px){
  thead{display:none}
  table,tbody,tr,td{display:block;width:100%}
  tbody tr{border-bottom:8px solid var(--canvas);padding:6px 0}
  tbody td{border:0;padding:4px 12px}
  tbody td::before{content:attr(data-l);font-size:.68rem;text-transform:uppercase;letter-spacing:.05em;
    color:var(--muted);display:block;margin-bottom:2px}
}
</style>
</head>
<body>
<header class="top">
  <div class="wrap">
    <h1><span class="lock">&#128274;</span>IBM JDK &mdash; Semeru Runtimes &amp; SDK CVE Report</h1>
    <div class="meta">
      <span>資料來源：<b>IBM Security Bulletins</b></span>
      <span>涵蓋產品：<b>Semeru 8/11/17/21/23/25/26 · SDK JTE 7/8</b></span>
      <span>CVSS 門檻：<b id="thLabel">&ge; 7.0</b></span>
      <span>資料模式：<b>__MODE__</b></span>
      <span>更新時間：<b>__GEN__</b></span>
    </div>
  </div>
</header>
<div class="wrap">
  <div class="cards">
    <div class="card tot"><div class="n" id="cTot">0</div><div class="l">Total CVEs</div></div>
    <div class="card crit"><div class="n" id="cCrit">0</div><div class="l">Critical (&ge;9.0)</div></div>
    <div class="card high"><div class="n" id="cHigh">0</div><div class="l">High (7.0&ndash;8.9)</div></div>
    <div class="card med"><div class="n" id="cMed">0</div><div class="l">Medium (4.0&ndash;6.9)</div></div>
  </div>

  <div class="controls">
    <input type="search" id="q" placeholder="搜尋 CVE 編號、公告、修補版本、備註…">
    <span class="seg" id="prodSeg">
      <button data-p="all" class="on">全部產品</button>
      <button data-p="IBM Semeru Runtimes">Semeru</button>
      <button data-p="IBM SDK Java Technology Edition">SDK (7/8)</button>
    </span>
    <span class="seg" id="thSeg">
      <label class="lbl" style="padding:8px 8px 8px 12px">門檻</label>
      <button data-t="0">全部</button>
      <button data-t="4">&ge;4.0</button>
      <button data-t="7" class="on">&ge;7.0</button>
      <button data-t="9">&ge;9.0</button>
    </span>
  </div>
  <div class="count" id="count"></div>

  <div class="tablewrap">
    <table>
      <thead><tr>
        <th data-k="cve">CVE-ID<span class="ar"></span></th>
        <th data-k="severity">Severity<span class="ar"></span></th>
        <th data-k="cvss">CVSS<span class="ar">&#9660;</span></th>
        <th data-k="product">Product<span class="ar"></span></th>
        <th data-k="bulletin">Security Bulletin / Advisory<span class="ar"></span></th>
        <th data-k="date">Publish Date<span class="ar"></span></th>
        <th>Fixed Version(s)</th>
        <th>Notes</th>
      </tr></thead>
      <tbody id="tb"></tbody>
    </table>
  </div>

  <div class="disc">
    ⚠️ 本頁資料由排程自動從 IBM 官方頁面擷取重建，可能與 IBM 有數小時延遲；重大變更請以下列官方頁面為準。
    <div class="src">
      官方來源：
      <a href="https://www.ibm.com/support/pages/semeru-runtimes-security-vulnerabilities" target="_blank" rel="noopener">Semeru Runtimes 漏洞頁</a>
      <a href="https://www.ibm.com/support/pages/java-sdk-security-vulnerabilities" target="_blank" rel="noopener">Java SDK 漏洞頁</a>
      <a href="https://www.ibm.com/support/pages/semeru-runtimes-fixes-version-17" target="_blank" rel="noopener">Semeru 17 fixes</a>
      <a href="https://www.ibm.com/support/pages/semeru-runtimes-fixes-version-21" target="_blank" rel="noopener">Semeru 21 fixes</a>
    </div>
  </div>

  <footer class="foot">Generated from IBM Security Bulletins &middot; 更新時間 __GEN__ &middot; CVE 連結導向 cve.org</footer>
</div>

<script>
const DATA = __DATA__;
const LINE_ORDER = ["7","8","11","16","17","18","21","22","23","25","26"];
let state={q:"",prod:"all",th:7,sortK:"cvss",sortDir:-1};
const tb=document.getElementById("tb");
function fixesHtml(e){
  const keys=Object.keys(e.fixes);
  if(keys.length===0) return '<span class="na">'+(e.notes&&/Not applicable/i.test(e.notes)?'Not applicable':'N/A')+'</span>';
  keys.sort((a,b)=>LINE_ORDER.indexOf(a)-LINE_ORDER.indexOf(b));
  const pfx = e.product.indexOf("SDK")>=0 ? "IBM ":"";
  return '<span class="fixes">'+keys.map(k=>'<span class="fx">'+pfx+k+' → '+e.fixes[k]+'</span>').join('')+'</span>';
}
function esc(s){return (s||"").replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));}
function filtered(){
  const q=state.q.toLowerCase();
  return DATA.filter(e=>{
    if(e.cvss < state.th) return false;
    if(state.prod!=="all" && e.product!==state.prod) return false;
    if(q){
      const hay=(e.cve+" "+e.bulletin+" "+e.product+" "+e.notes+" "+Object.values(e.fixes).join(" ")).toLowerCase();
      if(hay.indexOf(q)<0) return false;
    }
    return true;
  });
}
function sortRows(rows){
  const k=state.sortK,d=state.sortDir;
  return rows.slice().sort((a,b)=>{
    let x=a[k],y=b[k];
    if(k==="cvss"){return (x-y)*d;}
    x=(""+x).toLowerCase();y=(""+y).toLowerCase();
    if(x<y)return -1*d; if(x>y)return 1*d; return 0;
  });
}
function render(){
  const rows=sortRows(filtered());
  tb.innerHTML=rows.map(e=>`<tr>
    <td data-l="CVE-ID"><a class="cve" href="${e.cveUrl}" target="_blank" rel="noopener">${e.cve}</a></td>
    <td data-l="Severity"><span class="sev ${e.severity}">${e.severity}</span></td>
    <td data-l="CVSS"><span class="score">${e.cvss.toFixed(1)}</span></td>
    <td data-l="Product"><span class="prod">${e.product.indexOf("Semeru")>=0?"Semeru Runtimes":"SDK JTE (7/8)"}</span></td>
    <td data-l="Bulletin"><a href="${e.bulletinUrl}" target="_blank" rel="noopener">${esc(e.bulletin)}</a></td>
    <td data-l="Publish Date"><span class="date">${e.date}</span></td>
    <td data-l="Fixed Version(s)">${fixesHtml(e)}</td>
    <td data-l="Notes"><span class="notes">${esc(e.notes)}</span></td>
  </tr>`).join("");
  document.getElementById("count").textContent="顯示 "+rows.length+" 筆（共 "+DATA.length+" 筆）";
  const base=DATA.filter(e=>{
    if(state.prod!=="all"&&e.product!==state.prod)return false;
    if(state.q){const q=state.q.toLowerCase();
      const hay=(e.cve+" "+e.bulletin+" "+e.product+" "+e.notes+" "+Object.values(e.fixes).join(" ")).toLowerCase();
      if(hay.indexOf(q)<0)return false;}
    return true;});
  document.getElementById("cTot").textContent=base.length;
  document.getElementById("cCrit").textContent=base.filter(e=>e.cvss>=9).length;
  document.getElementById("cHigh").textContent=base.filter(e=>e.cvss>=7&&e.cvss<9).length;
  document.getElementById("cMed").textContent=base.filter(e=>e.cvss>=4&&e.cvss<7).length;
}
document.getElementById("q").addEventListener("input",e=>{state.q=e.target.value;render();});
document.querySelectorAll("#prodSeg button").forEach(b=>b.addEventListener("click",()=>{
  document.querySelectorAll("#prodSeg button").forEach(x=>x.classList.remove("on"));
  b.classList.add("on");state.prod=b.dataset.p;render();}));
document.querySelectorAll("#thSeg button").forEach(b=>b.addEventListener("click",()=>{
  document.querySelectorAll("#thSeg button").forEach(x=>x.classList.remove("on"));
  b.classList.add("on");state.th=parseFloat(b.dataset.t);
  const lbl={0:"全部",4:"≥ 4.0",7:"≥ 7.0",9:"≥ 9.0"}[state.th];
  document.getElementById("thLabel").textContent=lbl;render();}));
document.querySelectorAll("thead th[data-k]").forEach(th=>th.addEventListener("click",()=>{
  const k=th.dataset.k;
  if(state.sortK===k)state.sortDir*=-1; else {state.sortK=k;state.sortDir=(k==="cvss"||k==="date")?-1:1;}
  document.querySelectorAll("thead th .ar").forEach(a=>a.innerHTML="");
  th.querySelector(".ar").innerHTML=state.sortDir<0?"▼":"▲";
  render();}));
render();
</script>
</body>
</html>
"""

if __name__ == "__main__":
    main()
