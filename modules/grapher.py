"""
grapher.py — Session-aware attack graph builder + SOC HTML export
Improvements:
  - Session-aware edge correlation (not just last_seen)
  - Attack stage tagging on nodes (Initial Access → Priv Esc → Persistence → Execution)
  - Cluster-based layout for large graphs (≥80 nodes switches to hierarchical)
  - JSON timeline export alongside the HTML
  - Detection alert banners wired into the UI
"""

import networkx as nx
import json
import os
from modules.parser import LogEvent

# ── Attack stage ordering for layout hints ────────────────────────────────────

STAGE_LEVEL = {
    "Initial Access":        1,
    "Privilege Escalation":  2,
    "Persistence":           3,
    "Execution":             4,
    "":                      0,
}

# ── Graph builder ─────────────────────────────────────────────────────────────

def build_graph(events: list[LogEvent]) -> tuple[nx.DiGraph, dict]:
    G = nx.DiGraph()
    nodes = []
    edges = []

    # Track last node per session (more accurate than per-user/IP)
    last_by_session: dict[str, str] = {}
    # Fallback: last node per user and per IP (for events without session_id)
    last_by_user: dict[str, str] = {}
    last_by_ip: dict[str, str] = {}

    def add_node(node_id, label, ntype, severity, **meta):
        if node_id not in G:
            G.add_node(node_id)
            nodes.append({"id": node_id, "label": label, "type": ntype,
                          "severity": severity, **meta})

    def add_edge(src, dst, label=""):
        if src and src != dst and G.has_node(src) and G.has_node(dst):
            if not G.has_edge(src, dst):   # avoid duplicate edges
                G.add_edge(src, dst)
                edges.append({"from": src, "to": dst, "label": label})

    def last_node(event: LogEvent) -> str | None:
        """Return the best predecessor node for this event."""
        if event.session_id and event.session_id in last_by_session:
            return last_by_session[event.session_id]
        if event.user and event.user in last_by_user:
            return last_by_user[event.user]
        if event.src_ip and event.src_ip in last_by_ip:
            return last_by_ip[event.src_ip]
        return None

    def update_last(event: LogEvent, nid: str):
        if event.session_id:
            last_by_session[event.session_id] = nid
        if event.user:
            last_by_user[event.user] = nid
        if event.src_ip:
            last_by_ip[event.src_ip] = nid

    # ── Seed IP attacker nodes first ──────────────────────────────────────────
    for e in events:
        if e.src_ip:
            nid = f"ip_{e.src_ip}"
            add_node(nid, e.src_ip, "attacker_ip", "critical", ip=e.src_ip)

    # ── Process events in chronological order (already sorted in parser) ──────
    for idx, e in enumerate(events):
        nid = f"evt_{idx}"
        add_node(
            nid,
            e.event_type,
            e.event_type,
            e.severity,
            timestamp=e.timestamp,
            user=e.user or "",
            src_ip=e.src_ip or "",
            command=e.command or "",
            mitre=e.mitre,
            raw=e.raw[:120],
            attack_stage=e.attack_stage,
            session_id=e.session_id or "",
            stage_level=STAGE_LEVEL.get(e.attack_stage, 0),
        )

        if e.event_type == "ssh_fail" and e.src_ip:
            add_edge(f"ip_{e.src_ip}", nid, "brute force")
            update_last(e, nid)

        elif e.event_type == "ssh_success" and e.src_ip:
            add_edge(f"ip_{e.src_ip}", nid, "login success")
            update_last(e, nid)

        elif e.event_type == "session_open":
            prev = last_node(e) or (f"ip_{e.src_ip}" if e.src_ip else None)
            add_edge(prev, nid, "session opened")
            update_last(e, nid)

        elif e.event_type in ("sudo", "usermod", "su"):
            add_edge(last_node(e), nid, "sudo exec" if e.event_type != "su" else "su")
            update_last(e, nid)
            # Also link root context forward
            if e.event_type in ("usermod", "su"):
                last_by_user["root"] = nid

        elif e.event_type == "new_user":
            prev = last_node(e) or last_by_user.get("root")
            add_edge(prev, nid, "created user")
            update_last(e, nid)
            if e.user:
                last_by_user[e.user] = nid

        elif e.event_type in ("cron_exec", "cron_modify"):
            prev = last_node(e) or last_by_user.get("root")
            lbl = "cron trigger" if e.event_type == "cron_exec" else "cron modified"
            add_edge(prev, nid, lbl)
            update_last(e, nid)

        elif e.event_type in ("passwd_change",):
            add_edge(last_node(e), nid, "passwd changed")
            update_last(e, nid)

    return G, {"nodes": nodes, "edges": edges}


# ── JSON timeline export ──────────────────────────────────────────────────────

def export_timeline_json(events: list[LogEvent], output_path: str, detections: list[dict] = None):
    """Export a machine-readable JSON timeline for use outside the UI."""
    timeline = []
    for e in events:
        timeline.append({
            "timestamp":    e.timestamp,
            "event_type":   e.event_type,
            "attack_stage": e.attack_stage,
            "severity":     e.severity,
            "mitre":        e.mitre,
            "user":         e.user,
            "src_ip":       e.src_ip,
            "command":      e.command,
            "session_id":   e.session_id,
            "host":         e.host,
        })

    out = {
        "generated_at": __import__("datetime").datetime.now().isoformat(),
        "total_events": len(timeline),
        "detections":   detections or [],
        "timeline":     timeline,
    }

    with open(output_path, "w") as f:
        json.dump(out, f, indent=2)
    print(f"[+] Timeline JSON saved → {output_path}")


# ── HTML export ───────────────────────────────────────────────────────────────

def export_html(graph_data: dict, output_path: str, summary: dict = None):
    nodes_json      = json.dumps(graph_data["nodes"])
    edges_json      = json.dumps(graph_data["edges"])
    summary_json    = json.dumps(summary or {})
    detections_json = json.dumps(summary.get("detections", []) if summary else [])

    # Switch to hierarchical layout for large graphs
    node_count   = len(graph_data["nodes"])
    use_hier     = node_count >= 80
    physics_opts = (
        """physics:{enabled:false},layout:{hierarchical:{enabled:true,direction:'LR',sortMethod:'directed',levelSeparation:200,nodeSpacing:80}}"""
        if use_hier else
        """physics:{enabled:true,solver:'forceAtlas2Based',
          forceAtlas2Based:{gravitationalConstant:-130,centralGravity:0.008,springLength:170,springConstant:0.05,damping:0.5},
          stabilization:{iterations:350,updateInterval:25}},layout:{improvedLayout:true}"""
    )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>RECONSTR SOC Visualizer</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/vis/4.21.0/vis.min.js"></script>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
html,body{{width:100%;height:100%;background:#0a0e17;color:#c9d1d9;font-family:'Courier New',monospace;overflow:hidden}}
#app{{display:flex;width:100%;height:100vh}}
#sidebar{{width:300px;min-width:300px;background:#0d1117;border-right:1px solid #1e3a5f;display:flex;flex-direction:column;z-index:10;overflow:hidden}}
#sidebar-header{{padding:14px 16px;background:#080c14;border-bottom:1px solid #1e3a5f;flex-shrink:0}}
.logo{{display:flex;align-items:center;gap:10px;margin-bottom:4px}}
.logo-icon{{width:28px;height:28px;background:#7c3aed;border-radius:5px;display:flex;align-items:center;justify-content:center;font-size:14px;color:#fff;flex-shrink:0}}
.logo h1{{font-size:13px;font-weight:700;color:#e6edf3;letter-spacing:1px}}
.logo-sub{{font-size:9px;color:#58a6ff;letter-spacing:2px;text-transform:uppercase;margin-top:2px}}
.s-section{{padding:10px 14px;border-bottom:1px solid #161b22;flex-shrink:0}}
.s-section h3{{font-size:9px;color:#58a6ff;letter-spacing:2px;text-transform:uppercase;margin-bottom:8px}}
.stat-row{{display:flex;justify-content:space-between;margin-bottom:5px}}
.stat-label{{font-size:10px;color:#6e7681}}
.stat-val{{font-size:10px;font-weight:700;color:#e6edf3}}
.stat-val.red{{color:#f85149}}.stat-val.yellow{{color:#e3b341}}.stat-val.green{{color:#56d364}}
.leg-item{{display:flex;align-items:center;gap:7px;margin-bottom:5px}}
.leg-dot{{width:9px;height:9px;border-radius:50%;flex-shrink:0}}
.leg-label{{font-size:9px;color:#6e7681}}
/* Tabs */
.tab-bar{{display:flex;border-bottom:1px solid #1e3a5f;flex-shrink:0}}
.tab{{flex:1;padding:7px 0;font-size:9px;letter-spacing:1px;text-align:center;cursor:pointer;color:#6e7681;border-bottom:2px solid transparent;transition:all 0.15s}}
.tab.active{{color:#58a6ff;border-bottom-color:#58a6ff}}
.tab-panel{{display:none;flex:1;overflow-y:auto}}
.tab-panel.active{{display:flex;flex-direction:column}}
/* Events */
#ev-list{{flex:1;overflow-y:auto}}
#ev-list::-webkit-scrollbar{{width:3px}}
#ev-list::-webkit-scrollbar-thumb{{background:#1e3a5f}}
.ev-item{{padding:7px 14px;border-bottom:1px solid #0d1117;cursor:pointer;transition:background 0.1s}}
.ev-item:hover{{background:#161b22}}
.ev-time{{font-size:9px;color:#58a6ff;margin-bottom:1px}}
.ev-type{{font-size:11px;color:#e6edf3;font-weight:700;display:flex;align-items:center;gap:5px;flex-wrap:wrap}}
.ev-detail{{font-size:9px;color:#6e7681;margin-top:1px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}}
.badge{{font-size:8px;padding:1px 4px;border-radius:2px;font-weight:700;letter-spacing:0.5px}}
.b-crit{{background:#3d1a1a;color:#f85149;border:1px solid #5c2020}}
.b-warn{{background:#2d2100;color:#e3b341;border:1px solid #4a3800}}
.b-info{{background:#0c2040;color:#58a6ff;border:1px solid #1e3a5f}}
.b-stage{{background:#1a1030;color:#bc8cff;border:1px solid #3d1f6e;font-size:7px}}
/* Detections panel */
.det-item{{padding:9px 14px;border-bottom:1px solid #161b22}}
.det-rule{{font-size:10px;font-weight:700;color:#f85149;margin-bottom:3px;display:flex;align-items:center;gap:5px}}
.det-desc{{font-size:9px;color:#c9d1d9;line-height:1.5}}
.det-mitre{{font-size:8px;color:#e3b341;margin-top:3px}}
/* Graph */
#graph-wrap{{flex:1;position:relative;background:#080c14}}
#network{{position:absolute;inset:0}}
#tooltip{{position:absolute;background:#0d1117;border:1px solid #1e3a5f;border-radius:6px;padding:10px 12px;font-size:11px;max-width:270px;z-index:100;display:none;pointer-events:none;box-shadow:0 8px 30px rgba(0,0,0,0.7)}}
.tt-title{{font-size:12px;font-weight:700;color:#e6edf3;margin-bottom:7px;padding-bottom:5px;border-bottom:1px solid #1e3a5f}}
.tt-row{{display:flex;gap:6px;margin-bottom:3px}}
.tt-key{{color:#58a6ff;min-width:75px;font-size:10px;flex-shrink:0}}
.tt-val{{color:#c9d1d9;font-size:10px;word-break:break-all}}
.tt-mitre{{margin-top:7px;padding:4px 7px;background:#161b22;border-radius:3px;font-size:9px;color:#e3b341;border-left:2px solid #e3b341}}
.tt-stage{{margin-top:5px;padding:3px 7px;background:#1a1030;border-radius:3px;font-size:9px;color:#bc8cff;border-left:2px solid #7c3aed}}
#toolbar{{position:absolute;top:48px;right:12px;display:flex;gap:5px;z-index:20;flex-wrap:wrap;max-width:300px;justify-content:flex-end}}
.tb-btn{{background:#0d1117cc;border:1px solid #1e3a5f;color:#8b949e;font-size:9px;padding:5px 9px;border-radius:3px;cursor:pointer;font-family:'Courier New',monospace;letter-spacing:0.5px;transition:all 0.15s;backdrop-filter:blur(4px)}}
.tb-btn:hover{{background:#161b22;color:#e6edf3;border-color:#58a6ff}}
.tb-btn.active{{background:#1e3a5f;color:#58a6ff;border-color:#58a6ff}}
#header-bar{{position:absolute;top:0;left:0;right:0;height:36px;background:linear-gradient(90deg,#080c14,#0a0e17);border-bottom:1px solid #1e3a5f;display:flex;align-items:center;padding:0 14px;gap:12px;z-index:15;font-size:10px}}
.hb-item{{color:#58a6ff;letter-spacing:1px}}
.hb-sep{{color:#1e3a5f}}
.hb-val{{color:#e6edf3;font-weight:700}}
/* Stage filter bar */
#stage-bar{{position:absolute;top:48px;left:12px;display:flex;gap:5px;z-index:20}}
.stage-btn{{background:#0d1117cc;border:1px solid #1e3a5f;color:#8b949e;font-size:8px;padding:4px 8px;border-radius:3px;cursor:pointer;font-family:'Courier New',monospace;letter-spacing:0.5px;transition:all 0.15s;backdrop-filter:blur(4px)}}
.stage-btn:hover,.stage-btn.active{{border-color:#7c3aed;color:#c4b5fd;background:#1a0d2ecc}}
#alerts{{position:absolute;bottom:10px;left:10px;right:10px;z-index:20;display:flex;flex-direction:column;gap:5px;max-height:130px;overflow-y:auto}}
.alert{{padding:5px 10px;border-radius:3px;font-size:9px;border:1px solid;letter-spacing:0.3px;backdrop-filter:blur(4px)}}
.a-red{{background:#1a0a0acc;border-color:#5c2020;color:#f85149}}
.a-yellow{{background:#1a1400cc;border-color:#4a3800;color:#e3b341}}
</style>
</head>
<body>
<div id="app">
<div id="sidebar">
  <div id="sidebar-header">
    <div class="logo">
      <div class="logo-icon">⬡</div>
      <div><div style="font-size:13px;font-weight:700;color:#e6edf3;letter-spacing:1px">RECONSTR</div>
      <div class="logo-sub">SOC Threat Visualizer v2</div></div>
    </div>
  </div>

  <div class="s-section"><h3>Summary</h3><div id="stat-block"></div></div>

  <div class="s-section">
    <h3>Legend</h3>
    <div class="leg-item"><div class="leg-dot" style="background:#7c3aed;border-radius:2px;transform:rotate(45deg)"></div><span class="leg-label">Attacker IP — entry point</span></div>
    <div class="leg-item"><div class="leg-dot" style="background:#f85149"></div><span class="leg-label">Critical event (sudo, privesc)</span></div>
    <div class="leg-item"><div class="leg-dot" style="background:#238636"></div><span class="leg-label">SSH login success</span></div>
    <div class="leg-item"><div class="leg-dot" style="background:#e3b341"></div><span class="leg-label">Warning (brute force, cron)</span></div>
    <div class="leg-item"><div class="leg-dot" style="background:#bc8cff"></div><span class="leg-label">Persistence (new user, cron)</span></div>
  </div>

  <!-- Tabs: Timeline | Detections -->
  <div class="tab-bar">
    <div class="tab active" onclick="switchTab('timeline',this)">TIMELINE</div>
    <div class="tab" onclick="switchTab('detections',this)">DETECTIONS <span id="det-badge" style="background:#5c2020;color:#f85149;padding:0 4px;border-radius:2px;font-size:8px"></span></div>
  </div>

  <div id="tab-timeline" class="tab-panel active">
    <div id="ev-list"></div>
  </div>
  <div id="tab-detections" class="tab-panel">
    <div id="det-list"></div>
  </div>
</div>

<div id="graph-wrap">
  <div id="header-bar">
    <span class="hb-item">NODES</span><span class="hb-sep">│</span><span class="hb-val" id="hb-nodes">—</span>
    <span class="hb-sep">│</span>
    <span class="hb-item">EDGES</span><span class="hb-sep">│</span><span class="hb-val" id="hb-edges">—</span>
    <span class="hb-sep">│</span>
    <span class="hb-item">SESSIONS</span><span class="hb-sep">│</span><span class="hb-val" id="hb-sessions">—</span>
    <span class="hb-sep">│</span>
    <span class="hb-item">DETECTIONS</span><span class="hb-sep">│</span><span class="hb-val" id="hb-dets" style="color:#f85149">—</span>
  </div>

  <div id="network" style="top:36px;position:absolute;left:0;right:0;bottom:0"></div>

  <div id="stage-bar">
    <button class="stage-btn active" onclick="filterStage('all',this)">ALL</button>
    <button class="stage-btn" onclick="filterStage('Initial Access',this)">INITIAL ACCESS</button>
    <button class="stage-btn" onclick="filterStage('Privilege Escalation',this)">PRIV ESC</button>
    <button class="stage-btn" onclick="filterStage('Persistence',this)">PERSISTENCE</button>
    <button class="stage-btn" onclick="filterStage('Execution',this)">EXECUTION</button>
  </div>

  <div id="toolbar">
    <button class="tb-btn" onclick="fitView()">FIT</button>
    <button class="tb-btn" id="freeze-btn" onclick="togglePhysics()">FREEZE</button>
    <button class="tb-btn" onclick="filterCritical()">CRITICAL ONLY</button>
    <button class="tb-btn" onclick="resetFilter()">RESET</button>
    <button class="tb-btn" onclick="exportJSON()">EXPORT JSON</button>
  </div>

  <div id="tooltip">
    <div class="tt-title" id="tt-title"></div>
    <div id="tt-body"></div>
  </div>

  <div id="alerts"></div>
</div>
</div>

<script>
const RAW_NODES   = {nodes_json};
const RAW_EDGES   = {edges_json};
const SUMMARY     = {summary_json};
const DETECTIONS  = {detections_json};

// ── Node / edge styling ───────────────────────────────────────────────────────
const C = {{
  attacker_ip:  {{bg:'#1a0d2e',border:'#7c3aed',font:'#c4b5fd'}},
  ssh_fail:     {{bg:'#1f1500',border:'#e3b341',font:'#e3b341'}},
  ssh_success:  {{bg:'#0d2818',border:'#238636',font:'#56d364'}},
  session_open: {{bg:'#0c1e35',border:'#58a6ff',font:'#79c0ff'}},
  sudo:         {{bg:'#2d1010',border:'#f85149',font:'#ffa198'}},
  usermod:      {{bg:'#2d1010',border:'#f85149',font:'#ffa198'}},
  su:           {{bg:'#2d1010',border:'#f85149',font:'#ffa198'}},
  new_user:     {{bg:'#1a0d2e',border:'#bc8cff',font:'#d2a8ff'}},
  cron_exec:    {{bg:'#2d1010',border:'#f85149',font:'#ffa198'}},
  cron_modify:  {{bg:'#1f1500',border:'#e3b341',font:'#e3b341'}},
  passwd_change:{{bg:'#2d1010',border:'#f85149',font:'#ffa198'}},
  default:      {{bg:'#161b22',border:'#30363d',font:'#8b949e'}},
}};
const SH = {{attacker_ip:'diamond',ssh_fail:'dot',ssh_success:'box',session_open:'box',sudo:'dot',su:'dot',new_user:'ellipse',cron_exec:'dot',cron_modify:'dot',passwd_change:'dot'}};

const STAGE_COLOR = {{
  'Initial Access':       '#238636',
  'Privilege Escalation': '#f85149',
  'Persistence':          '#bc8cff',
  'Execution':            '#e3b341',
}};

function nodeLabel(n) {{
  if (n.type==='attacker_ip') return n.ip;
  const labels = {{ssh_fail:'SSH FAIL',ssh_success:'SSH LOGIN',session_open:'SESSION',sudo:'SUDO',su:'SU',usermod:'USERMOD',cron_exec:'CRON EXEC',cron_modify:'CRON MOD',new_user:'NEW USER',passwd_change:'PASSWD'}};
  return (labels[n.type] || n.label.toUpperCase()) + (n.user ? '\\n' + n.user : '');
}}

function buildVisNodes(arr) {{
  return arr.map(n => {{
    const c = C[n.type]||C.default;
    const sz = n.type==='attacker_ip'?30:n.severity==='critical'?22:16;
    // Stage-coloured border ring for non-IP nodes
    const stageBorder = n.attack_stage ? (STAGE_COLOR[n.attack_stage] || c.border) : c.border;
    return {{
      id:n.id, label:nodeLabel(n),
      shape:SH[n.type]||'dot', size:sz,
      color:{{background:c.bg,border:stageBorder,highlight:{{background:c.bg,border:'#fff'}}}},
      font:{{color:c.font,size:n.type==='attacker_ip'?12:10,face:'Courier New',bold:true}},
      borderWidth:n.type==='attacker_ip'?2:1.5,
      shadow:{{enabled:true,color:c.border+'55',size:12,x:0,y:0}},
      level: n.stage_level || 0,
      _d:n
    }};
  }});
}}

const EC = {{'brute force':'#e3b341','login success':'#238636','session opened':'#58a6ff','sudo exec':'#f85149','su':'#f85149','created user':'#bc8cff','cron trigger':'#f85149','cron modified':'#e3b341','passwd changed':'#f85149'}};
function buildVisEdges(arr) {{
  return arr.map((e,i) => {{
    const col = EC[e.label]||'#444c56';
    return {{
      id:i,from:e.from,to:e.to,label:e.label,
      arrows:{{to:{{enabled:true,scaleFactor:0.65}}}},
      color:{{color:col+'88',highlight:col,hover:col}},
      font:{{color:col,size:9,face:'Courier New',strokeWidth:3,strokeColor:'#080c14',align:'middle'}},
      smooth:{{type:'curvedCW',roundness:0.15}},
      width:1.5,dashes:e.label==='brute force'
    }};
  }});
}}

// ── Network init ──────────────────────────────────────────────────────────────
let physOn = {'false' if use_hier else 'true'}, network;
const vNodes = new vis.DataSet(buildVisNodes(RAW_NODES));
const vEdges = new vis.DataSet(buildVisEdges(RAW_EDGES));

network = new vis.Network(
  document.getElementById('network'),
  {{nodes:vNodes, edges:vEdges}},
  {{ {physics_opts},
     interaction:{{hover:true,tooltipDelay:0,navigationButtons:false,keyboard:true}}
  }}
);

// ── Header bar ────────────────────────────────────────────────────────────────
document.getElementById('hb-nodes').textContent    = RAW_NODES.length;
document.getElementById('hb-edges').textContent    = RAW_EDGES.length;
document.getElementById('hb-sessions').textContent = (SUMMARY.sessions||[]).length;
document.getElementById('hb-dets').textContent     = DETECTIONS.length;

// ── Tooltip ───────────────────────────────────────────────────────────────────
const tip = document.getElementById('tooltip');
network.on('hoverNode', p => {{
  const n = RAW_NODES.find(x => x.id===p.node); if(!n) return;
  document.getElementById('tt-title').textContent = (n.type||n.label).toUpperCase().replace(/_/g,' ');
  let h = '';
  if(n.timestamp)    h+=`<div class="tt-row"><span class="tt-key">Time</span><span class="tt-val">${{n.timestamp}}</span></div>`;
  if(n.ip)           h+=`<div class="tt-row"><span class="tt-key">IP</span><span class="tt-val">${{n.ip}}</span></div>`;
  if(n.user)         h+=`<div class="tt-row"><span class="tt-key">User</span><span class="tt-val">${{n.user}}</span></div>`;
  if(n.src_ip)       h+=`<div class="tt-row"><span class="tt-key">From IP</span><span class="tt-val">${{n.src_ip}}</span></div>`;
  if(n.command)      h+=`<div class="tt-row"><span class="tt-key">Command</span><span class="tt-val">${{n.command}}</span></div>`;
  if(n.session_id)   h+=`<div class="tt-row"><span class="tt-key">Session</span><span class="tt-val">${{n.session_id}}</span></div>`;
  if(n.mitre)        h+=`<div class="tt-mitre">⚑ ${{n.mitre}}</div>`;
  if(n.attack_stage) h+=`<div class="tt-stage">◈ ${{n.attack_stage}}</div>`;
  document.getElementById('tt-body').innerHTML = h;
  const pos = p.event.center;
  tip.style.left=(pos.x+16)+'px'; tip.style.top=(pos.y-10)+'px'; tip.style.display='block';
}});
network.on('blurNode',()=>tip.style.display='none');
network.on('dragStart',()=>tip.style.display='none');

// ── Controls ──────────────────────────────────────────────────────────────────
function fitView(){{network.fit({{animation:{{duration:600,easingFunction:'easeInOutQuad'}}}});}}
function togglePhysics(){{physOn=!physOn;network.setOptions({{physics:{{enabled:physOn}}}});document.getElementById('freeze-btn').textContent=physOn?'FREEZE':'UNFREEZE';}}

function filterCritical(){{
  const ids=RAW_NODES.filter(n=>n.severity==='critical'||n.type==='attacker_ip').map(n=>n.id);
  const es=RAW_EDGES.filter(e=>ids.includes(e.from)&&ids.includes(e.to));
  vNodes.clear();vEdges.clear();
  vNodes.add(buildVisNodes(RAW_NODES.filter(n=>ids.includes(n.id))));
  vEdges.add(buildVisEdges(es));
  setTimeout(fitView,400);
}}

function filterStage(stage, btn){{
  document.querySelectorAll('.stage-btn').forEach(b=>b.classList.remove('active'));
  btn.classList.add('active');
  if(stage==='all'){{resetFilter();return;}}
  const ids=RAW_NODES.filter(n=>n.attack_stage===stage||n.type==='attacker_ip').map(n=>n.id);
  const es=RAW_EDGES.filter(e=>ids.includes(e.from)&&ids.includes(e.to));
  vNodes.clear();vEdges.clear();
  vNodes.add(buildVisNodes(RAW_NODES.filter(n=>ids.includes(n.id))));
  vEdges.add(buildVisEdges(es));
  setTimeout(fitView,400);
}}

function resetFilter(){{
  vNodes.clear();vEdges.clear();
  vNodes.add(buildVisNodes(RAW_NODES));
  vEdges.add(buildVisEdges(RAW_EDGES));
  setTimeout(fitView,400);
}}

function exportJSON(){{
  const data = {{
    nodes: RAW_NODES,
    edges: RAW_EDGES,
    summary: SUMMARY,
    detections: DETECTIONS,
    exported_at: new Date().toISOString()
  }};
  const blob = new Blob([JSON.stringify(data,null,2)],{{type:'application/json'}});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'attackpath_graph.json';
  a.click();
}}

// ── Tabs ──────────────────────────────────────────────────────────────────────
function switchTab(name, el){{
  document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));
  document.querySelectorAll('.tab-panel').forEach(p=>p.classList.remove('active'));
  el.classList.add('active');
  document.getElementById('tab-'+name).classList.add('active');
}}

// ── Sidebar stats ─────────────────────────────────────────────────────────────
const bf=SUMMARY.brute_force||{{}};
const bfIp=Object.keys(bf)[0]||'—';
const bfCnt=bf[bfIp]||0;
const spanH = SUMMARY.span_seconds ? (SUMMARY.span_seconds/3600).toFixed(1)+'h' : '—';
document.getElementById('stat-block').innerHTML=`
  <div class="stat-row"><span class="stat-label">Total events</span><span class="stat-val">${{SUMMARY.total||0}}</span></div>
  <div class="stat-row"><span class="stat-label">Attacker IPs</span><span class="stat-val red">${{(SUMMARY.ips||[]).length}} — ${{(SUMMARY.ips||[]).join(', ')}}</span></div>
  <div class="stat-row"><span class="stat-label">Users affected</span><span class="stat-val yellow">${{(SUMMARY.users||[]).join(', ')}}</span></div>
  <div class="stat-row"><span class="stat-label">Brute force hits</span><span class="stat-val red">${{bfCnt}} attempts / ${{bfIp}}</span></div>
  <div class="stat-row"><span class="stat-label">Attack span</span><span class="stat-val">${{spanH}}</span></div>
  <div class="stat-row"><span class="stat-label">Sessions</span><span class="stat-val">${{(SUMMARY.sessions||[]).length}}</span></div>
  <div class="stat-row"><span class="stat-label">Detections fired</span><span class="stat-val red">${{DETECTIONS.length}}</span></div>
`;

// ── Timeline list ─────────────────────────────────────────────────────────────
const el=document.getElementById('ev-list');
RAW_NODES.filter(n=>n.type!=='attacker_ip').forEach(n=>{{
  const bc=n.severity==='critical'?'b-crit':n.severity==='warning'?'b-warn':'b-info';
  const d=document.createElement('div');d.className='ev-item';
  const stageLabel = n.attack_stage ? `<span class="badge b-stage">${{n.attack_stage.toUpperCase()}}</span>` : '';
  d.innerHTML=`<div class="ev-time">${{n.timestamp||''}}</div>
    <div class="ev-type">${{(n.label||'').toUpperCase()}} <span class="badge ${{bc}}">${{(n.severity||'').toUpperCase()}}</span>${{stageLabel}}</div>
    <div class="ev-detail">${{n.command||n.user||n.src_ip||'—'}}</div>`;
  d.onclick=()=>{{network.focus(n.id,{{scale:1.5,animation:{{duration:500,easingFunction:'easeInOutQuad'}}}});network.selectNodes([n.id]);}};
  el.appendChild(d);
}});

// ── Detections panel ──────────────────────────────────────────────────────────
const dl=document.getElementById('det-list');
document.getElementById('det-badge').textContent = DETECTIONS.length || '';
if(DETECTIONS.length===0){{
  dl.innerHTML='<div style="padding:14px;font-size:10px;color:#6e7681">No detections fired.</div>';
}} else {{
  const icons={{'brute_force':'🔨','impossible_travel':'✈️','privesc_chain':'⬆️','persistence_combo':'🔒','brute_then_success':'💥'}};
  DETECTIONS.forEach(det=>{{
    const d=document.createElement('div');d.className='det-item';
    d.innerHTML=`
      <div class="det-rule">${{icons[det.rule]||'⚠'}} ${{det.rule.replace(/_/g,' ').toUpperCase()}}</div>
      <div class="det-desc">${{det.description}}</div>
      <div class="det-mitre">MITRE: ${{det.mitre}}</div>`;
    dl.appendChild(d);
  }});
}}

// ── Alert banners ─────────────────────────────────────────────────────────────
const ab=document.getElementById('alerts');
DETECTIONS.slice(0,3).forEach(det=>{{
  ab.innerHTML+=`<div class="alert a-red">⚠ ${{det.description}}</div>`;
}});
const cc=RAW_NODES.filter(n=>n.severity==='critical').length;
if(cc) ab.innerHTML+=`<div class="alert a-yellow">↯ ${{cc}} critical events detected</div>`;

network.once('stabilizationIterationsDone',()=>fitView());
</script>
</body>
</html>"""

    os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else ".", exist_ok=True)
    with open(output_path, "w") as f:
        f.write(html)
    print(f"[+] Graph saved → {output_path}")
