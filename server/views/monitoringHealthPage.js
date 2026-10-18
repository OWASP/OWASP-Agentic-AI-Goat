'use strict';

function esc(str) {
  if (str == null) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function renderHealthPage(payload) {
  const { body, recommendations } = payload;
  const status = body.status || 'unknown';
  const ollama = body.ollama || {};
  const system = body.system || {};
  const mem = system.memoryUsage || {};
  const ts = body.timestamp || new Date().toISOString();

  const statusColor = status === 'healthy' ? '#10b981' : status === 'degraded' ? '#f59e0b' : '#ef4444';
  const statusBg = status === 'healthy' ? '#d1fae5' : status === 'degraded' ? '#fef3c7' : '#fee2e2';
  const statusIcon = status === 'healthy' ? '&#10003;' : status === 'degraded' ? '&#9888;' : '&#10007;';

  const memPct = mem.percentage || 0;
  const memBarColor = memPct > 80 ? '#ef4444' : memPct > 60 ? '#f59e0b' : '#10b981';

  const models = (ollama.available_models || []).map(m => `<span class="chip">${esc(m)}</span>`).join('');

  const recsHtml = (recommendations || []).map(r => {
    const icon = r.type === 'error' ? '&#10007;' : '&#9888;';
    const cls = r.type === 'error' ? 'rec-error' : 'rec-warning';
    return `<div class="rec ${cls}"><span class="rec-icon">${icon}</span><div><strong>${esc(r.message)}</strong><br><small>${esc(r.action)}</small></div></div>`;
  }).join('');

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="refresh" content="30">
<title>DVAIA — System Health</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#0f172a;color:#e2e8f0;min-height:100vh;padding:2rem}
.container{max-width:900px;margin:0 auto}
header{text-align:center;margin-bottom:2.5rem}
header h1{font-size:1.75rem;font-weight:700;background:linear-gradient(135deg,#818cf8,#a78bfa);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;margin-bottom:.5rem}
header p{color:#94a3b8;font-size:.9rem}
.status-badge{display:inline-flex;align-items:center;gap:.5rem;padding:.5rem 1.25rem;border-radius:999px;font-weight:700;font-size:.95rem;margin-top:1rem;background:${statusBg};color:${statusColor}}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:1.25rem;margin-bottom:1.5rem}
.card{background:#1e293b;border:1px solid #334155;border-radius:12px;padding:1.5rem}
.card h2{font-size:1rem;font-weight:600;color:#cbd5e1;margin-bottom:1rem;display:flex;align-items:center;gap:.5rem}
.card h2 .dot{width:8px;height:8px;border-radius:50%;display:inline-block}
.metric{display:flex;justify-content:space-between;align-items:center;padding:.4rem 0;border-bottom:1px solid #334155}
.metric:last-child{border-bottom:none}
.metric .label{color:#94a3b8;font-size:.85rem}
.metric .value{font-weight:600;font-size:.9rem;color:#f1f5f9}
.bar-wrap{height:8px;background:#334155;border-radius:4px;margin-top:.5rem;overflow:hidden}
.bar-fill{height:100%;border-radius:4px;transition:width .3s}
.chip{display:inline-block;background:#334155;color:#a5b4fc;font-size:.75rem;padding:.2rem .6rem;border-radius:6px;margin:.15rem .25rem .15rem 0;font-family:monospace}
.recs{background:#1e293b;border:1px solid #334155;border-radius:12px;padding:1.25rem;margin-bottom:1.5rem}
.recs h2{font-size:1rem;font-weight:600;color:#cbd5e1;margin-bottom:.75rem}
.rec{display:flex;align-items:flex-start;gap:.75rem;padding:.6rem .75rem;border-radius:8px;margin-bottom:.5rem;font-size:.85rem}
.rec:last-child{margin-bottom:0}
.rec-warning{background:#422006;border:1px solid #854d0e}
.rec-error{background:#450a0a;border:1px solid #991b1b}
.rec-icon{font-size:1.1rem;line-height:1.3}
.rec small{color:#94a3b8}
footer{text-align:center;color:#64748b;font-size:.8rem;padding-top:1rem;border-top:1px solid #1e293b}
footer a{color:#818cf8;text-decoration:none}
footer a:hover{text-decoration:underline}
.refresh-btn{display:inline-flex;align-items:center;gap:.4rem;margin-top:1rem;padding:.55rem 1.25rem;border:1px solid #475569;border-radius:8px;background:#1e293b;color:#e2e8f0;font-size:.9rem;font-weight:600;cursor:pointer;transition:background .15s,border-color .15s}
.refresh-btn:hover{background:#334155;border-color:#818cf8}
.refresh-btn:active{transform:translateY(1px)}
@media(max-width:600px){body{padding:1rem}.grid{grid-template-columns:1fr}}
</style>
</head>
<body>
<div class="container">
  <header>
    <h1>DVAIA System Health</h1>
    <p>Damn Vulnerable AI Application — Monitoring Dashboard</p>
    <div class="status-badge">${statusIcon}&nbsp;${esc(status.toUpperCase())}</div>
    <div><button type="button" class="refresh-btn" onclick="location.reload()">&#8635;&nbsp;Refresh now</button></div>
  </header>

  <div class="grid">
    <div class="card">
      <h2><span class="dot" style="background:${system.cpuUsage > 80 ? '#ef4444' : '#10b981'}"></span> System</h2>
      <div class="metric"><span class="label">Memory</span><span class="value">${esc(String(mem.used || 0))} / ${esc(String(mem.total || 0))} MB (${esc(String(memPct))}%)</span></div>
      <div class="bar-wrap"><div class="bar-fill" style="width:${memPct}%;background:${memBarColor}"></div></div>
      <div class="metric" style="margin-top:.75rem"><span class="label">CPU Usage</span><span class="value">${esc(String(system.cpuUsage || 0))}%</span></div>
      <div class="metric"><span class="label">Active Connections</span><span class="value">${esc(String(system.activeConnections || 0))}</span></div>
    </div>

    <div class="card">
      <h2><span class="dot" style="background:${ollama.status === 'healthy' ? '#10b981' : '#ef4444'}"></span> Ollama LLM</h2>
      <div class="metric"><span class="label">Status</span><span class="value" style="color:${ollama.status === 'healthy' ? '#10b981' : '#ef4444'}">${esc(ollama.status || 'unknown')}</span></div>
      <div class="metric"><span class="label">Primary Model</span><span class="value">${esc(ollama.primary_model || 'n/a')}</span></div>
      <div class="metric"><span class="label">Concurrent / Queue</span><span class="value">${esc(String(ollama.concurrent_requests || 0))} / ${esc(String(ollama.queue_length || 0))}</span></div>
      ${models ? `<div style="margin-top:.75rem"><span class="label" style="color:#94a3b8;font-size:.8rem">Models</span><div style="margin-top:.35rem">${models}</div></div>` : ''}
    </div>
  </div>

  ${recsHtml ? `<div class="recs"><h2>Recommendations</h2>${recsHtml}</div>` : ''}

  <footer>
    <p>Last checked: ${esc(ts)} &middot; Auto-refreshes every 30s</p>
    <p style="margin-top:.4rem"><a href="?format=json">View raw JSON</a></p>
  </footer>
</div>
</body>
</html>`;
}

module.exports = renderHealthPage;
