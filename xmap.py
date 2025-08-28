import re, json
import subprocess as sp 
import pyfiglet

def header(text: str = "XMAP", font: str = "big") -> str:
    
    ascii_art = pyfiglet.figlet_format(text, font=font)

    
    colors = ["\033[91m", "\033[93m", "\033[92m",
              "\033[96m", "\033[94m", "\033[95m"]
    reset = "\033[0m"

    
    colored_lines = []
    for i, line in enumerate(ascii_art.splitlines()):
        if line.strip():
            color = colors[i % len(colors)]
            colored_lines.append(color + line + reset)
        else:
            colored_lines.append(line)

    
    width = max(len(line) for line in ascii_art.splitlines())
    border = "+" + "-" * (width + 2) + "+"
    framed = [border] + [f"| {line.ljust(width)} |" for line in colored_lines] + [border]

    return "\n".join(framed)
print(header())    
print("\033[91m \n It filter your file and delete extra IP .\033[0m ")
print("\033[92m \n Developed by @XTOM\033[0m")   

SRC = input("\n \n \033[45m Input Nmap HTML file (e.g. scan.html):> \033[0m ").strip() or "scan.html"
if not SRC.lower().endswith(".html"):
    SRC += ".html"
OUT = input("\n \n\033[45m Output HTML file (e.g. report.html):> \033[0m ").strip() or "report.html"
if not OUT.lower().endswith(".html"):
    OUT += ".html"

# Read original Nmap HTML file
with open(SRC, "rb") as f:
    t = f.read().decode("utf-8", errors="ignore")

# Collect anchors = (id, ip)
anchors = []
for m in re.finditer(r'href="#(host_[0-9_]+)".*?>(\d+(?:\.\d+){3})<', t, flags=re.S|re.I):
    anchors.append((m.group(1), m.group(2)))
if not anchors:
    for m in re.finditer(r'<a name="(host_[0-9_]+)"></a><h2[^>]*>(\d+(?:\.\d+){3})', t, flags=re.S|re.I):
        anchors.append((m.group(1), m.group(2)))

# Helper to slice host sections
def slice_section(idx):
    aid, _ = anchors[idx]
    m_start = re.search(fr'<a name="{re.escape(aid)}"></a>', t)
    if not m_start:
        return None
    start = m_start.start()
    end = len(t)
    if idx+1 < len(anchors):
        next_aid, _ = anchors[idx+1]
        m_end = re.search(fr'<a name="{re.escape(next_aid)}"></a>', t)
        if m_end:
            end = m_end.start()
    return t[start:end]

# Parse hosts
hosts = {}
def ensure(ip):
    hosts.setdefault(ip, {"ports": [], "os": None, "scripts": [], "cves": []})

for idx, (aid, ip) in enumerate(anchors):
    sec = slice_section(idx)
    if not sec:
        continue
    ensure(ip)

    # OS details
    os_m = re.search(r'OS details</td>\s*<td>(.*?)</td>', sec, flags=re.S|re.I)
    if os_m:
        hosts[ip]["os"] = re.sub(r'<.*?>', '', os_m.group(1)).strip()

    # Ports
    for row in re.finditer(
        r'<tr class="(open|closed|filtered|unfiltered)">\s*'
        r'<td>(\d{1,5})</td>\s*<td>(tcp|udp)</td>\s*'
        r'<td>(.*?)</td>\s*<td>(.*?)</td>\s*<td>(.*?)</td>\s*<td>(.*?)</td>\s*<td>(.*?)</td>\s*</tr>',
        sec, flags=re.S|re.I):
        state = row.group(1).lower()
        portnum = row.group(2)
        proto = row.group(3)
        state_text = re.sub(r'<.*?>','',row.group(4)).strip().lower()
        service = re.sub(r'<.*?>','',row.group(5)).strip()
        reason = re.sub(r'<.*?>','',row.group(6)).strip()
        product = re.sub(r'<.*?>','',row.group(7)).strip()
        version = re.sub(r'<.*?>','',row.group(8)).strip()
        hosts[ip]["ports"].append({
            "port": f"{portnum}/{proto}",
            "state": state_text or state,
            "service": service,
            "product": product,
            "version": version,
            "reason": reason
        })

    # Script output
    for sm in re.finditer(r'<tr class="script">\s*<td>(.*?)</td>\s*<td><pre>(.*?)</pre></td>\s*</tr>', sec, flags=re.S|re.I):
        sname = re.sub(r'<.*?>','',sm.group(1)).strip()
        sout = re.sub(r'<.*?>','',sm.group(2)).strip()
        hosts[ip]["scripts"].append({"name": sname, "output": sout})
        for cve in set(re.findall(r'\bCVE-\d{4}-\d{4,7}\b', sout, flags=re.I)):
            if cve.upper() not in [c["id"] for c in hosts[ip]["cves"]]:
                hosts[ip]["cves"].append({"id": cve.upper(), "cvss": None, "severity": "Unknown"})

# Keep only responsive hosts (with ports)
hosts = {ip:v for ip,v in hosts.items() if v["ports"]}

# ---------------- HTML Report ----------------
html_doc = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title> XMAP Report</title>
<meta name="viewport" content="width=device-width, initial-scale=1" />
<style>
  :root { --bg:#0b0c10; --panel:#0f141b; --ink:#eaeaea; --muted:#9aa4af; --acc:#66ccff; --border:#1e2936; }
  body { background:var(--bg); color:var(--ink); font-family: Inter, Arial, sans-serif; margin:0; }
  header { padding:24px; text-align:center; border-bottom:1px solid #1f2833; background:#0d0e13; position:sticky; top:0; z-index:10; }
  h1 { margin:0 0 8px 0; color:var(--acc); font-size:28px; }
  .sub { color:var(--muted); font-size:13px; }
  .wrap { padding:24px; max-width:1200px; margin:0 auto; }
  .toolbar { display:flex; gap:12px; flex-wrap:wrap; margin-bottom:16px; }
  .search { flex:1 1 320px; }
  input[type=search] { width:100%; padding:12px 14px; border-radius:12px; border:1px solid #243241; background:#0f1117; color:var(--ink); }
  .btn { padding:10px 14px; border-radius:12px; border:1px solid #243241; background:#111827; color:var(--ink); cursor:pointer; }
  .btn:hover { background:#162033; }
  table { width:100%; border-collapse:separate; border-spacing:0 8px; }
  thead th { text-align:left; font-size:12px; color:var(--muted); text-transform:uppercase; padding:0 12px 8px; }
  tbody tr.group { background:var(--panel); }
  tbody tr.group td { padding:14px 12px; border-top:1px solid var(--border); border-bottom:1px solid var(--border); }
  tr.group:hover { background:#141a23; }
  .badge { padding:4px 8px; border-radius:999px; font-size:12px; border:1px solid var(--border); }
  .open { color:#10e09b; }
  .closed { color:#ff6b6b; }
  .filtered { color:#f6c177; }
  .muted { color:var(--muted); }
  .panelbox { display:none; padding:16px; background:#0b1016; border:1px solid var(--border); border-radius:12px; margin-top:-4px; }
  .ports { width:100%; border-collapse:collapse; margin-top:8px; }
  .ports th, .ports td { text-align:left; padding:8px 10px; border-bottom:1px solid var(--border); }
  .kv { background:var(--panel); padding:10px 12px; border:1px solid var(--border); border-radius:10px; }
  .grid { display:grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap:12px; }
  .scriptout { white-space:pre-wrap; font-family: monospace; font-size:12px; background:#0d1220; padding:10px; border-radius:10px; border:1px solid var(--border); color:#dbeafe; }
  a { color:var(--acc); text-decoration:none; }
  a:hover { text-decoration:underline; }
</style>
</head>
<body>
<header>
  <h1> XMAP</h1>
  <h1> Network Report</h1>
  <div class="sub">Responsive hosts • Expand rows for details</div>
</header>
<div class="wrap">
  <div class="toolbar">
    <div class="search"><input id="q" type="search" placeholder="Search IPs, ports, services…"></div>
    <button class="btn" onclick="expandAll()">Expand all</button>
    <button class="btn" onclick="collapseAll()">Collapse all</button>
  </div>
  <table>
    <thead><tr><th>IP</th><th>Open</th><th>Closed/Filtered</th><th>OS</th></tr></thead>
    <tbody id="rows"></tbody>
  </table>
</div>
<script>
const DATA = REPLACE_JSON;

function countPorts(ports){
  let open=0, other=0;
  (ports||[]).forEach(p=>{ const st=(p.state||'').toLowerCase(); if(st.includes('open')) open++; else other++; });
  return {open, other};
}
function esc(s){ return String(s||'').replace(/[&<>\"']/g, m => ({'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;'}[m])); }

function buildPanel(item){
  const ports=item.ports||[];
  const scripts=item.scripts||[];
  const cves=item.cves||[];
  const portRows = ports.map(p=>'<tr>'+
    '<td>'+esc(p.port)+'</td>'+
    '<td class="'+((p.state||'').includes('open')?'open':(((p.state||'').includes('closed')||(p.state||'').includes('filtered'))?'filtered':''))+'">'+esc(p.state)+'</td>'+
    '<td>'+esc(p.service)+'</td>'+
    '<td>'+esc(p.product)+'</td>'+
    '<td>'+esc(p.version)+'</td>'+
    '<td class="muted">'+esc(p.reason)+'</td>'+
  '</tr>').join('');
  const scriptBlocks = scripts.length ? scripts.map(s=>
    '<div class="kv"><div><strong>'+esc(s.name)+'</strong></div><div class="scriptout">'+esc(s.output)+'</div></div>'
  ).join('') : '<div class="muted">No script output.</div>';
  const cveBlocks = cves.length ? cves.map(v=>
    '<div class="kv"><div><strong>'+esc(v.id)+'</strong> • Rank: '+esc(v.severity||'Unknown')+'</div>'+
    '<div style="margin-top:6px;"><a href="https://nvd.nist.gov/vuln/detail/'+encodeURIComponent(v.id)+'" target="_blank">NVD record</a></div></div>'
  ).join('') : '<div class="muted">No CVEs found.</div>';
  return (
    '<div class="grid"><div class="kv"><strong>OS Guess</strong><div class="muted">'+(item.os?esc(item.os):'Unavailable')+'</div></div>'+
    '<div class="kv"><strong>Total Services</strong><div class="muted">'+ports.length+'</div></div></div>'+
    '<div class="kv"><table class="ports"><thead><tr><th>Port</th><th>State</th><th>Service</th><th>Product</th><th>Version</th><th>Reason</th></tr></thead><tbody>'+portRows+'</tbody></table></div>'+
    '<h3>Vulnerabilities</h3><div class="grid">'+cveBlocks+'</div>'+
    '<h3>Script Output</h3><div class="grid">'+scriptBlocks+'</div>'
  );
}
const rowsEl = document.getElementById('rows');
function render(){
  rowsEl.innerHTML='';
  const q=(document.getElementById('q').value||'').toLowerCase();
  Object.keys(DATA).sort().forEach((ip,i)=>{
    const item=DATA[ip]; const txt=(ip+' '+JSON.stringify(item)).toLowerCase();
    if(q && !txt.includes(q)) return;
    const counts=countPorts(item.ports);
    const pid='panel_'+i;
    const tr=document.createElement('tr'); tr.className='group';
    tr.innerHTML='<td><span class="badge">'+ip+'</span></td>'+
                 '<td><span class="badge open">'+counts.open+'</span></td>'+
                 '<td><span class="badge muted">'+counts.other+'</span></td>'+
                 '<td class="muted">'+(item.os?esc(item.os):'—')+'</td>';
    tr.onclick=()=>toggle(pid);
    rowsEl.appendChild(tr);
    const panel=document.createElement('tr'); panel.className='panel'; panel.id=pid;
    const td=document.createElement('td'); td.colSpan=4; td.innerHTML='<div class="panelbox">'+buildPanel(item)+'</div>';
    panel.appendChild(td); rowsEl.appendChild(panel);
  });
}
function toggle(id){
  document.querySelectorAll('tr.panel .panelbox').forEach(b=>{ if(b.parentElement.parentElement.id!==id) b.style.display='none'; });
  const box=document.querySelector('#'+id+' .panelbox'); box.style.display=(box.style.display==='block')?'none':'block';
}
function expandAll(){ document.querySelectorAll('.panelbox').forEach(b=> b.style.display='block'); }
function collapseAll(){ document.querySelectorAll('.panelbox').forEach(b=> b.style.display='none'); }
document.getElementById('q').addEventListener('input', render); render();
</script>
</body>
</html>
"""

# Insert JSON data
html_doc = html_doc.replace("REPLACE_JSON", json.dumps(hosts, ensure_ascii=False))

# Write output
with open(OUT, "w", encoding="utf-8") as f:
    f.write(html_doc)

print(f"✅ Report written: {OUT}, Hosts: {len(hosts)}")
