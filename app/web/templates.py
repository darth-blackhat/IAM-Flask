"""Jinja templates for both web UIs (autoescaped: every name ends in .html). No JavaScript."""

BASE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
{% block head %}{% endblock %}
<title>{% block title %}{{ site_title }}{% endblock %} · {{ site_title }}</title>
<style>
:root{--bg:#f6f7f9;--fg:#1b1f24;--muted:#5b6470;--card:#fff;--line:#dde1e6;--ok:#1a7f37;
--bad:#c62828;--warn:#9a6700;--link:#0b5cad;--chip:#eef1f4;--accent:#0b5cad}
@media (prefers-color-scheme:dark){:root{--bg:#0f1216;--fg:#e6e9ed;--muted:#9aa4b0;--card:#171b21;
--line:#2a313a;--ok:#4cc26a;--bad:#ff6b6b;--warn:#e3b341;--link:#6cb4ff;--chip:#222831;--accent:#6cb4ff}}
*{box-sizing:border-box}body{margin:0;font:14px/1.45 system-ui,-apple-system,Segoe UI,sans-serif;
background:var(--bg);color:var(--fg)}a{color:var(--link);text-decoration:none}a:hover{text-decoration:underline}
header{background:var(--card);border-bottom:1px solid var(--line);padding:10px 16px;display:flex;
gap:16px;align-items:center;flex-wrap:wrap}header b{margin-right:6px}
nav{display:flex;gap:14px;flex-wrap:wrap;flex:1}nav a{color:var(--fg)}nav a.on{color:var(--link);font-weight:600}
.who{display:flex;gap:10px;align-items:center;color:var(--muted)}
main{padding:16px;max-width:1300px;margin:0 auto}h1{font-size:20px;margin:4px 0 14px}
h2{font-size:16px;margin:22px 0 8px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px}
.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:12px 14px}
.card .n{font-size:24px;font-weight:600}.muted{color:var(--muted)}
.wrap{overflow-x:auto;background:var(--card);border:1px solid var(--line);border-radius:8px}
table{border-collapse:collapse;width:100%}th,td{text-align:left;padding:7px 10px;border-bottom:1px solid var(--line);
vertical-align:top}th{font-weight:600;color:var(--muted);white-space:nowrap}tr:last-child td{border-bottom:0}
.ok{color:var(--ok);font-weight:600}.bad{color:var(--bad);font-weight:600}.warn{color:var(--warn);font-weight:600}
.chip{display:inline-block;background:var(--chip);border-radius:10px;padding:1px 8px;margin:1px 3px 1px 0;font-size:12px}
pre{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:12px;overflow:auto;font-size:12.5px}
form.f,form.row{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px;align-items:center}
form.inline{display:inline}
input,select,button{font:inherit;padding:5px 8px;border:1px solid var(--line);border-radius:6px;
background:var(--card);color:var(--fg)}button{cursor:pointer}button.primary{background:var(--accent);color:#fff;border-color:var(--accent)}
button.danger{color:var(--bad);border-color:var(--bad)}
.mono{font-family:ui-monospace,Consolas,monospace;font-size:12.5px}.pager{margin:12px 0}
.flash{padding:10px 12px;border-radius:8px;margin-bottom:12px;border:1px solid var(--line);background:var(--card)}
.flash.error{border-color:var(--bad);color:var(--bad)}.flash.ok{border-color:var(--ok)}
.login{max-width:360px;margin:60px auto}.login label{display:block;margin:10px 0 4px}.login input{width:100%}
.secret{font-family:ui-monospace,Consolas,monospace;word-break:break-all;background:var(--chip);padding:10px;border-radius:6px}
</style></head><body>
{% if user %}
<header><b>{{ site_title }}</b><nav>
{% for path, label, min_role in nav %}{% if can(min_role) %}
<a href="{{ path }}" class="{{ 'on' if (request.path == path or (path != '/' and request.path.startswith(path))) }}">{{ label }}</a>
{% endif %}{% endfor %}
</nav><div class="who"><span>{{ user.username }} · {{ user.role }}</span>
<a href="/account">account</a>
<form class="inline" method="post" action="/logout">{{ csrf() }}<button>log out</button></form></div></header>
{% endif %}
<main>
{% for cat, msg in get_flashed_messages(with_categories=true) %}<div class="flash {{ cat }}">{{ msg }}</div>{% endfor %}
{% block body %}{% endblock %}</main></body></html>"""

LOGIN = """{% extends "base.html" %}{% block title %}Sign in{% endblock %}{% block body %}
<div class="login card"><h1>{{ site_title }}</h1>
<form method="post" action="/login">{{ csrf() }}
<input type="hidden" name="next" value="{{ next }}">
<label for="u">Username</label><input id="u" name="username" autocomplete="username" required autofocus>
<label for="p">Password</label><input id="p" name="password" type="password" autocomplete="current-password" required>
<p><button class="primary">Sign in</button></p></form></div>
{% endblock %}"""

ACCOUNT = """{% extends "base.html" %}{% block title %}Account{% endblock %}{% block body %}
<h1>Account: {{ user.username }}</h1>
<p class="muted">Role {{ user.role }} · last sign-in {{ user.last_login_at|ts }} · password changed {{ user.password_changed_at|ts }}</p>
<h2>Change password</h2>
<form method="post" action="/account/password" class="row">{{ csrf() }}
<input name="current" type="password" placeholder="Current password" autocomplete="current-password" required>
<input name="new" type="password" placeholder="New password (12+ characters)" autocomplete="new-password" required>
<button class="primary">Change</button></form>
<h2>Sessions</h2>
<form method="post" action="/account/logout-everywhere">{{ csrf() }}<button>Log out on every device</button></form>
{% endblock %}"""

ADMIN_USERS = """{% extends "base.html" %}{% block title %}Users{% endblock %}{% block body %}
<h1>Web users</h1>
<div class="wrap"><table><tr><th>User</th><th>Role</th><th>State</th><th>Last sign-in</th><th>Actions</th></tr>
{% for u in users %}<tr><td>{{ u.username }}</td>
<td><form class="inline" method="post" action="/admin/users/{{ u.username|urlencode }}/role">{{ csrf() }}
<select name="role">{% for r in roles %}<option {{ 'selected' if r == u.role }}>{{ r }}</option>{% endfor %}</select>
<button>set</button></form></td>
<td>{% if u.disabled %}<span class="bad">disabled</span>{% elif u.locked_until and u.locked_until > now %}<span class="warn">locked</span>{% else %}<span class="ok">active</span>{% endif %}
{% if u.failed_logins %}<span class="muted">({{ u.failed_logins }} failed)</span>{% endif %}</td>
<td>{{ u.last_login_at|ts }}</td>
<td>{% if u.username != user.username %}
<form class="inline" method="post" action="/admin/users/{{ u.username|urlencode }}/{{ 'enable' if u.disabled else 'disable' }}">{{ csrf() }}<button class="{{ '' if u.disabled else 'danger' }}">{{ 'enable' if u.disabled else 'disable' }}</button></form>
{% endif %}
<form class="inline" method="post" action="/admin/users/{{ u.username|urlencode }}/unlock">{{ csrf() }}<button>unlock</button></form>
<form class="inline" method="post" action="/admin/users/{{ u.username|urlencode }}/password">{{ csrf() }}
<input name="password" type="password" placeholder="new password" autocomplete="new-password" required><button>reset</button></form>
</td></tr>{% endfor %}</table></div>
<h2>Add user</h2>
<form method="post" action="/admin/users" class="row">{{ csrf() }}
<input name="username" placeholder="username" required>
<input name="password" type="password" placeholder="password (12+ characters)" autocomplete="new-password" required>
<select name="role">{% for r in roles %}<option>{{ r }}</option>{% endfor %}</select>
<button class="primary">Add</button></form>
<p class="muted">viewer: read only · operator: also run actions · admin: also users{{ ' and API keys' if site == 'producer' }}.</p>
{% endblock %}"""

ADMIN_AUDIT = """{% extends "base.html" %}{% block title %}Audit trail{% endblock %}{% block body %}
<h1>Audit trail</h1>
<form class="f" method="get">
<input name="actor" placeholder="actor (e.g. api:hr-system)" value="{{ args.get('actor','') }}">
<select name="channel"><option value="">any channel</option>{% for c in ['web','api','cli','system'] %}<option {{ 'selected' if args.get('channel') == c }}>{{ c }}</option>{% endfor %}</select>
<select name="status"><option value="">any result</option><option value="ok" {{ 'selected' if args.get('status') == 'ok' }}>ok</option><option value="failed" {{ 'selected' if args.get('status') == 'failed' }}>refused / failed</option></select>
<button>Filter</button></form>
<div class="wrap"><table><tr><th>When</th><th>Channel</th><th>Actor</th><th>IP</th><th>Action</th><th>Target</th><th>Result</th></tr>
{% for r in rows %}<tr><td>{{ r.at|ts }}</td><td>{{ r.channel }}</td><td>{{ r.actor }}</td><td class="mono">{{ r.ip or '' }}</td>
<td>{{ r.action }}</td><td class="mono">{{ r.target or '' }}</td>
<td class="{{ 'ok' if r.ok else 'bad' }}">{{ 'ok' if r.ok else 'refused' }}{% if r.detail %} <span class="muted">{{ r.detail }}</span>{% endif %}</td></tr>
{% else %}<tr><td colspan="7" class="muted">Nothing recorded.</td></tr>{% endfor %}</table></div>
{% if next_before %}<div class="pager"><a href="?{{ dict(args, before=next_before)|urlencode }}">Older →</a></div>{% endif %}
{% endblock %}"""

REQUESTS = """{% extends "base.html" %}{% block title %}Operator requests{% endblock %}{% block body %}
<h1>Operator requests</h1>
<p class="muted">Buttons in this UI queue a request; the {{ service }} service runs it within seconds.</p>
<div class="wrap"><table><tr><th>#</th><th>Asked</th><th>By</th><th>Action</th><th>Status</th><th>Result</th></tr>
{% for r in rows %}<tr><td>{{ r.id }}</td><td>{{ r.at|ts }}</td><td>{{ r.requested_by }}</td>
<td>{{ r.action }}{% if r.params %} <span class="muted mono">{{ r.params|tojson }}</span>{% endif %}</td>
<td class="{{ 'ok' if r.status == 'done' else ('bad' if r.status == 'failed' else 'warn') }}">{{ r.status }}</td>
<td><details><summary class="muted">{{ (r.result or {})|tojson|truncate(80) }}</summary><pre>{{ r.result|pretty }}</pre></details></td></tr>
{% else %}<tr><td colspan="6" class="muted">No requests.</td></tr>{% endfor %}</table></div>
{% endblock %}"""

# ============================ producer site ==================================

P_DASHBOARD = """{% extends "base.html" %}
{% block head %}<meta http-equiv="refresh" content="30">{% endblock %}
{% block title %}Dashboard{% endblock %}{% block body %}
<h1>Producer site <span class="muted" style="font-size:13px;font-weight:400">last 24 h · refreshes every 30 s</span></h1>
<div class="cards">
 <div class="card"><div class="muted">Producer events</div>
  <div class="n"><span class="ok">{{ producer.ok }}</span> / <span class="{{ 'bad' if producer.failed }}">{{ producer.failed }}</span></div>
  <div class="muted">applied / failed</div></div>
 <div class="card"><div class="muted">AD instructions</div>
  <div class="n">{{ outbox.pending }} <span class="muted" style="font-size:14px">pending</span></div>
  <div class="muted">{{ outbox.delivered }} delivered · <span class="{{ 'bad' if outbox.dead }}">{{ outbox.dead }} dead</span></div>
  {% if outbox.last_error %}<div class="bad" style="font-size:12px">{{ outbox.last_error }}</div>{% endif %}</div>
 <div class="card"><div class="muted">Latest change detection</div>
  {% if runs %}<div class="n {{ 'ok' if runs[0].status in ('ok','baseline') else ('bad' if runs[0].status == 'failed') }}">{{ runs[0].status }}</div>
  <div class="muted">{{ runs[0].started_at|ts }}</div>{% else %}<div class="muted">no runs</div>{% endif %}</div>
</div>
{% if blocked %}<div class="flash error" style="margin-top:12px">The latest run was refused as a mass delete: {{ blocked }}.
{% if can('operator') %}After checking it is real, use <a href="/runs">Sync runs</a> → "allow mass delete".{% endif %}</div>{% endif %}
<h2>Domains exported</h2>
{% if exports %}<div class="wrap"><table><tr><th>Domain</th><th>Records</th><th>Last zip</th><th>When</th></tr>
{% for e in exports %}<tr><td>{{ e.domain }}</td><td>{{ e.records }}</td><td class="mono">{{ e.file.replace('\\\\', '/').split('/')[-1] }}</td><td>{{ e.exported_at|ts }}</td></tr>{% endfor %}
</table></div>{% else %}<p class="muted">Nothing exported yet.</p>{% endif %}
{% endblock %}"""

P_ACTIVITY = """{% extends "base.html" %}{% block title %}Producer activity{% endblock %}{% block body %}
<h1>Producer activity</h1>
<form class="f" method="get">
 <input name="employee" placeholder="Employee id" value="{{ args.get('employee','') }}">
 <select name="type"><option value="">All events</option>
 {% for t in ['hire','update','terminate','leave','return','status'] %}<option {{ 'selected' if args.get('type') == t }}>{{ t }}</option>{% endfor %}</select>
 <select name="status"><option value="">Any result</option>
 <option value="ok" {{ 'selected' if args.get('status') == 'ok' }}>Applied</option>
 <option value="failed" {{ 'selected' if args.get('status') == 'failed' }}>Failed</option></select>
 <button>Filter</button></form>
<div class="wrap"><table><tr><th>When</th><th>Employee</th><th>Event</th><th>Result</th><th>What it did</th></tr>
{% for r in rows %}<tr>
<td><a href="/producer/{{ r.id }}">{{ r.at|ts }}</a></td>
<td><a href="/producer?employee={{ r.employee_id|urlencode }}">{{ r.employee_id }}</a></td>
<td>{{ r.event_type }}{% if r.event_id %}<div class="muted mono">{{ r.event_id }}</div>{% endif %}</td>
<td>{% if r.duplicate %}<span class="muted">duplicate</span>{% elif r.ok %}<span class="ok">applied</span>{% else %}<span class="bad">failed</span>{% endif %}</td>
<td>{% for a in r.result.actions %}<span class="chip">{{ a }}</span>{% endfor %}
{% for w in r.result.warnings %}<div class="warn">{{ w }}</div>{% endfor %}
{% if r.error %}<div class="bad">{{ r.error }}</div>{% endif %}
{% if r.result.instructions %}<div class="muted">{{ r.result.instructions|length }} AD instruction(s)</div>{% endif %}</td>
</tr>{% else %}<tr><td colspan="5" class="muted">Nothing recorded yet.</td></tr>{% endfor %}</table></div>
{% if next_before %}<div class="pager"><a href="?{{ dict(args, before=next_before)|urlencode }}">Older →</a></div>{% endif %}
{% endblock %}"""

P_ACTIVITY_DETAIL = """{% extends "base.html" %}{% block title %}Producer event{% endblock %}{% block body %}
<h1>{{ e.event_type }} · {{ e.employee_id }}</h1>
<p>{{ e.at|ts }} · {% if e.duplicate %}<span class="muted">duplicate (answered from record)</span>{% elif e.ok %}<span class="ok">applied</span>{% else %}<span class="bad">failed</span>{% endif %}
{% if e.user_id %} · OpenIAM user <span class="mono">{{ e.user_id }}</span>{% endif %}
{% if e.event_id %} · message <span class="mono">{{ e.event_id }}</span>{% endif %}</p>
{% if e.error %}<p class="bad">{{ e.error }}</p>{% endif %}
<h2>Actions in OpenIAM</h2>{% for a in e.result.actions %}<span class="chip">{{ a }}</span>{% else %}<p class="muted">No change.</p>{% endfor %}
<h2>AD instructions (why)</h2>
{% if e.result.instructions %}<div class="wrap"><table><tr><th>Op</th><th>Object</th><th>Key</th><th>Why</th></tr>
{% for i in e.result.instructions %}<tr><td><b>{{ i.op }}</b></td><td>{{ i.object_class }}</td><td class="mono">{{ i.key|tojson }}</td>
<td>{{ (i.why or {}).summary }}</td></tr>{% endfor %}
</table></div>{% else %}<p class="muted">None.</p>{% endif %}
{% if person %}<h2>Current state for {{ e.employee_id }}</h2><pre>{{ person|pretty }}</pre>{% endif %}
<h2>Raw result</h2><pre>{{ e.result|pretty }}</pre>
{% endblock %}"""

P_OUTBOX = """{% extends "base.html" %}{% block title %}AD instructions{% endblock %}{% block body %}
<h1>AD instructions</h1>
{% if can('operator') and stats.dead %}<form method="post" action="/outbox/retry-dead">{{ csrf() }}
<button class="primary">Retry {{ stats.dead }} dead instruction batch(es)</button></form>{% endif %}
<div class="wrap"><table><tr><th>Seq</th><th>Detected</th><th>Change</th><th>Instructions (why)</th><th>Delivery</th></tr>
{% for r in rows %}{% set p = r.payload %}<tr>
<td><a href="/outbox/{{ r.seq }}">{{ r.seq }}</a></td><td>{{ r.created_at|ts }}</td>
<td>{{ p.type }}{% if p.employee_id %} · {{ p.employee_id }}{% endif %}
{% if p.why %}<div class="muted">{{ p.why.source }}: {{ p.why.summary }}</div>{% endif %}</td>
<td>{% for i in p.instructions or [] %}<span class="chip">{{ i.op }} {{ i.object_class }} {{ i.key.values()|first }}</span>{% else %}<span class="muted">none</span>{% endfor %}</td>
<td>{% if r.delivered_at %}<span class="ok">delivered</span> {{ r.delivered_at|ts }}{% elif r.dead %}<span class="bad">dead</span> after {{ r.attempts }}{% else %}<span class="warn">pending</span>{% if r.attempts %} ({{ r.attempts }} tries){% endif %}{% endif %}
{% if r.last_error and not r.delivered_at %}<div class="bad" style="font-size:12px">{{ r.last_error }}</div>{% endif %}</td>
</tr>{% else %}<tr><td colspan="5" class="muted">Nothing yet.</td></tr>{% endfor %}</table></div>
{% if next_before %}<div class="pager"><a href="?before={{ next_before }}">Older →</a></div>{% endif %}
{% endblock %}"""

P_OUTBOX_DETAIL = """{% extends "base.html" %}{% block title %}Outbox {{ e.seq }}{% endblock %}{% block body %}
<h1>{{ e.payload.type }} <span class="muted">#{{ e.seq }}</span></h1>
<p>{% if e.delivered_at %}<span class="ok">delivered</span> {{ e.delivered_at|ts }}{% elif e.dead %}<span class="bad">dead</span>{% else %}<span class="warn">pending</span>{% endif %}
· {{ e.attempts }} attempt(s){% if e.last_error %} · <span class="bad">{{ e.last_error }}</span>{% endif %}</p>
{% if e.payload.why %}<h2>Why</h2><pre>{{ e.payload.why|pretty }}</pre>{% endif %}
<h2>Instructions</h2><pre>{{ (e.payload.instructions or [])|pretty }}</pre>
<h2>Full event</h2><pre>{{ e.payload|pretty }}</pre>
{% endblock %}"""

P_RUNS = """{% extends "base.html" %}{% block title %}Sync runs{% endblock %}{% block body %}
<h1>Change detection and export</h1>
{% if can('operator') %}<form method="post" action="/runs/request" class="row">{{ csrf() }}
<select name="action">{% for a, label in actions.items() %}<option value="{{ a }}">{{ label }}</option>{% endfor %}</select>
<button class="primary">Run</button> <a href="/requests" class="muted">see requests</a></form>{% endif %}
<div class="wrap"><table><tr><th>Run</th><th>Started</th><th>Took</th><th>Status</th><th>Changes</th></tr>
{% for r in runs %}<tr><td>{{ r.id }}</td><td>{{ r.started_at|ts }}</td>
<td>{% if r.finished_at %}{{ '%.1f'|format(r.finished_at - r.started_at) }} s{% endif %}</td>
<td class="{{ 'ok' if r.status in ('ok','baseline') else ('bad' if r.status == 'failed') }}">{{ r.status }}</td>
<td>{% if r.summary %}{% for e, c in r.summary.items() %}<span class="chip">{{ e }} +{{ c.created }} ~{{ c.updated }} −{{ c.deleted }}</span>{% endfor %}{% endif %}
{% if r.error %}<span class="bad">{{ r.error }}</span>{% endif %}</td></tr>
{% else %}<tr><td colspan="5" class="muted">No runs.</td></tr>{% endfor %}</table></div>
{% endblock %}"""

P_APIKEYS = """{% extends "base.html" %}{% block title %}API keys{% endblock %}{% block body %}
<h1>API keys</h1>
{% if new_key %}<div class="flash ok">Key for <b>{{ new_key.name }}</b>. It is shown once; store it now:
<div class="secret">{{ new_key.key }}</div></div>{% endif %}
<div class="wrap"><table><tr><th>Name</th><th>Prefix</th><th>Scopes</th><th>Networks</th><th>Created</th><th>Last used</th><th>Expires</th><th></th></tr>
{% for k in keys %}<tr><td>{{ k.name }}</td><td class="mono">biam_{{ k.key_prefix }}_…</td>
<td>{% for s in k.scopes %}<span class="chip">{{ s }}</span>{% endfor %}</td>
<td class="mono">{{ k.allowed_cidrs|join(', ') or 'any' }}</td><td>{{ k.created_at|ts }}<div class="muted">{{ k.created_by or '' }}</div></td>
<td>{{ k.last_used_at|ts }}</td><td>{{ k.expires_at|ts or 'never' }}</td>
<td>{% if k.revoked_at %}<span class="bad">revoked {{ k.revoked_at|ts }}</span>{% else %}
<form class="inline" method="post" action="/admin/apikeys/{{ k.name|urlencode }}/revoke">{{ csrf() }}<button class="danger">revoke</button></form>{% endif %}</td></tr>
{% else %}<tr><td colspan="8" class="muted">No keys.</td></tr>{% endfor %}</table></div>
<h2>New key</h2>
<form method="post" action="/admin/apikeys" class="row">{{ csrf() }}
<input name="name" placeholder="name, e.g. hr-system" required>
<select name="scope" multiple size="4">{% for s, d in scopes.items() %}<option value="{{ s }}" title="{{ d }}">{{ s }}</option>{% endfor %}</select>
<input name="cidrs" placeholder="networks, e.g. 10.20.0.0/16 (comma)">
<input name="expires_days" type="number" min="1" placeholder="expires in days">
<button class="primary">Create</button></form>
{% endblock %}"""

# ============================ consumer site ==================================

C_DASHBOARD = """{% extends "base.html" %}
{% block head %}<meta http-equiv="refresh" content="30">{% endblock %}
{% block title %}Dashboard{% endblock %}{% block body %}
<h1>Consumer site <span class="muted" style="font-size:13px;font-weight:400">applies to: <b>{{ 'Active Directory' if target == 'ad' else 'remote OpenIAM' }}</b>
{% if target == 'ad' %}({{ ad_mode }}){% endif %} · last 24 h · refreshes every 30 s</span></h1>
<div class="cards">
 <div class="card"><div class="muted">Zips received</div>
  <div class="n">{{ files.get('applied', 0) }}</div>
  <div class="muted">applied · <span class="{{ 'warn' if files.get('partial') }}">{{ files.get('partial', 0) }} partial</span>
   · <span class="{{ 'bad' if files.get('failed') }}">{{ files.get('failed', 0) }} rejected</span>
   · {{ files.get('stale', 0) }} stale</div></div>
 {% if target == 'ad' %}<div class="card"><div class="muted">AD plans</div>
  <div class="n {{ 'warn' if waiting }}">{{ waiting }}</div><div class="muted">awaiting approval · <a href="/ad/plans">open</a></div></div>
 <div class="card"><div class="muted">AD changes outside the consumer</div>
  <div class="n {{ 'bad' if alerts }}">{{ alerts }}</div><div class="muted">open warning / critical · <a href="/ad/changes">review</a></div></div>{% endif %}
 <div class="card"><div class="muted">Drift</div>
  <div class="n {{ 'warn' if drifting }}">{{ drifting }}</div><div class="muted">domain(s) differ from their last zip · <a href="/drift">reports</a></div></div>
</div>
{% if can('operator') %}<form method="post" action="/scan" class="row" style="margin-top:12px">{{ csrf() }}<button>Scan the inbox now</button></form>{% endif %}
<h2>Domains</h2>
{% if domains %}<div class="wrap"><table><tr><th>Domain</th><th>Data as of</th><th>Records</th><th>Applied</th><th>Latest drift</th></tr>
{% for d in domains %}<tr><td><a href="/files?domain={{ d.domain|urlencode }}">{{ d.domain }}</a></td>
<td class="mono">{{ d.last_generated_at }}</td><td>{{ d.records }}</td><td>{{ d.updated_at|ts }}</td>
<td>{% set r = drift.get(d.domain) %}{% if r %}<a href="/drift/{{ r.id }}" class="{{ 'ok' if r.status == 'clean' else 'warn' }}">{{ r.status }}</a> <span class="muted">{{ r.at|ts }}</span>{% else %}<span class="muted">none</span>{% endif %}</td></tr>{% endfor %}
</table></div>{% else %}<p class="muted">No zips applied yet.</p>{% endif %}
{% endblock %}"""

C_FILES = """{% extends "base.html" %}{% block title %}Files{% endblock %}{% block body %}
<h1>Zips received</h1>
<form class="f" method="get">
 <select name="domain"><option value="">All domains</option>
 {% for d in domains %}<option {{ 'selected' if args.get('domain') == d.domain }}>{{ d.domain }}</option>{% endfor %}</select>
 <select name="status"><option value="">Any status</option>
 {% for s in ['applied','partial','failed','stale','skipped','duplicate','planned','awaiting_approval','rejected','processing'] %}<option {{ 'selected' if args.get('status') == s }}>{{ s }}</option>{% endfor %}</select>
 <button>Filter</button></form>
<div class="wrap"><table><tr><th>Received</th><th>File</th><th>Domain</th><th>Data as of</th><th>Status</th><th>Result</th></tr>
{% for f in rows %}<tr><td>{{ f.received_at|ts }}</td>
<td><a class="mono" href="/files/{{ f.sha256 }}">{{ f.name }}</a></td><td>{{ f.domain or '' }}</td>
<td class="mono">{{ f.generated_at or '' }}</td>
<td class="{{ 'ok' if f.status == 'applied' else ('bad' if f.status == 'failed' else ('warn' if f.status in ('partial','stale','awaiting_approval') else 'muted')) }}">{{ f.status }}</td>
<td>{% if f.summary %}{% for k, v in f.summary.items() %}<span class="chip">{{ k }} {{ v }}</span>{% endfor %}{% endif %}
{% if f.error %}<span class="bad">{{ f.error }}</span>{% endif %}</td></tr>
{% else %}<tr><td colspan="6" class="muted">No files received.</td></tr>{% endfor %}</table></div>
{% endblock %}"""

C_FILE = """{% extends "base.html" %}{% block title %}{{ f.name }}{% endblock %}{% block body %}
<h1 class="mono" style="font-size:16px">{{ f.name }}</h1>
<p>Domain <b>{{ f.domain or '?' }}</b> · data as of <span class="mono">{{ f.generated_at or '?' }}</span> ·
status <b>{{ f.status }}</b> · received {{ f.received_at|ts }}{% if f.processed_at %} · processed {{ f.processed_at|ts }}{% endif %}</p>
<p class="muted mono">sha256 {{ f.sha256 }}<br>{{ f.stored_at or '' }}</p>
{% if f.error %}<p class="bad">{{ f.error }}</p>{% endif %}
{% if can('operator') and f.status != 'failed' %}<form method="post" action="/files/{{ f.sha256 }}/reprocess">{{ csrf() }}
<button>Apply this zip again</button> <span class="muted">(retries failed records; already-applied records are skipped)</span></form>{% endif %}
{% if f.counts %}<h2>Contents</h2>{% for k, v in f.counts.items() %}<span class="chip">{{ k }}: {{ v }}</span>{% endfor %}{% endif %}
<h2>What was done</h2>
<div class="wrap"><table><tr><th>When</th><th>Entity</th><th>Key</th><th>Action</th><th>Detail</th></tr>
{% for a in actions %}<tr><td>{{ a.at|ts }}</td><td>{{ a.entity or '' }}</td><td class="mono">{{ a.source_id or '' }}</td>
<td class="{{ 'ok' if a.ok else 'bad' }}">{{ a.action }}</td><td>{{ a.detail or '' }}</td></tr>
{% else %}<tr><td colspan="5" class="muted">Nothing changed (all records already up to date).</td></tr>{% endfor %}</table></div>
{% endblock %}"""

C_ACTIONS = """{% extends "base.html" %}{% block title %}Actions{% endblock %}{% block body %}
<h1>Actions on the {{ 'Active Directory' if target == 'ad' else 'remote OpenIAM' }}</h1>
<form class="f" method="get"><select name="status"><option value="">Any result</option>
<option value="ok" {{ 'selected' if args.get('status') == 'ok' }}>OK</option>
<option value="failed" {{ 'selected' if args.get('status') == 'failed' }}>Failed</option></select><button>Filter</button></form>
<div class="wrap"><table><tr><th>When</th><th>Domain</th><th>Entity</th><th>Key</th><th>Action</th><th>Detail</th><th>File</th></tr>
{% for a in rows %}<tr><td>{{ a.at|ts }}</td><td>{{ a.domain or '' }}</td><td>{{ a.entity or '' }}</td>
<td class="mono">{{ a.source_id or '' }}</td><td class="{{ 'ok' if a.ok else 'bad' }}">{{ a.action }}</td><td>{{ a.detail or '' }}</td>
<td>{% if a.file_sha256 %}<a class="mono" href="/files/{{ a.file_sha256 }}">{{ a.file_sha256[:10] }}…</a>{% endif %}</td></tr>
{% else %}<tr><td colspan="7" class="muted">No actions.</td></tr>{% endfor %}</table></div>
{% if next_before %}<div class="pager"><a href="?{{ dict(args, before=next_before)|urlencode }}">Older →</a></div>{% endif %}
{% endblock %}"""

C_DRIFT = """{% extends "base.html" %}{% block title %}Drift{% endblock %}{% block body %}
<h1>Drift reports</h1>
<p class="muted">Compares the {{ 'Active Directory' if target == 'ad' else 'remote OpenIAM' }} with the last zip applied for a domain. Read-only.</p>
{% if can('operator') %}<form method="post" action="/drift" class="row">{{ csrf() }}
<select name="domain"><option value="">every domain</option>{% for d in domains %}<option>{{ d.domain }}</option>{% endfor %}</select>
<button class="primary">Run drift report</button></form>{% endif %}
<div class="wrap"><table><tr><th>#</th><th>When</th><th>Domain</th><th>Status</th><th>Summary</th><th>By</th></tr>
{% for r in rows %}<tr><td><a href="/drift/{{ r.id }}">{{ r.id }}</a></td><td>{{ r.at|ts }}</td><td>{{ r.domain }}</td>
<td class="{{ 'ok' if r.status == 'clean' else 'warn' }}">{{ r.status }}</td>
<td>{% for k, v in r.summary.items() if k not in ('zip','data_as_of','target') %}<span class="chip">{{ k }} {{ v }}</span>{% endfor %}</td>
<td>{{ r.requested_by or '' }}</td></tr>
{% else %}<tr><td colspan="6" class="muted">No reports yet.</td></tr>{% endfor %}</table></div>
{% endblock %}"""

C_DRIFT_DETAIL = """{% extends "base.html" %}{% block title %}Drift {{ r.id }}{% endblock %}{% block body %}
<h1>Drift report #{{ r.id }} · {{ r.domain }}</h1>
<p>{{ r.at|ts }} · <b class="{{ 'ok' if r.status == 'clean' else 'warn' }}">{{ r.status }}</b> · zip {{ r.summary.zip }} · data as of {{ r.summary.data_as_of }}</p>
<div class="wrap"><table><tr><th>Kind</th><th>Key</th><th>Issue</th><th>Detail</th></tr>
{% for i in r['items'] %}<tr><td>{{ i.kind }}</td><td class="mono">{{ i.key|tojson if i.key is mapping else i.key }}</td>
<td class="warn">{{ i.issue }}</td><td class="mono">{{ i.detail }}{% if i.why %}<div class="muted">{{ i.why }}</div>{% endif %}</td></tr>
{% else %}<tr><td colspan="4" class="ok">No differences.</td></tr>{% endfor %}</table></div>
{% endblock %}"""

C_PLANS = """{% extends "base.html" %}{% block title %}AD plans{% endblock %}{% block body %}
<h1>AD plans <span class="muted" style="font-size:13px;font-weight:400">mode: {{ ad_mode }}</span></h1>
<form class="f" method="get"><select name="status"><option value="">any status</option>
{% for s in ['awaiting_approval','planned','applied','partial','rejected'] %}<option {{ 'selected' if args.get('status') == s }}>{{ s }}</option>{% endfor %}</select><button>Filter</button></form>
<div class="wrap"><table><tr><th>#</th><th>When</th><th>Domain</th><th>Status</th><th>Changes</th><th>Decided</th></tr>
{% for p in rows %}<tr><td><a href="/ad/plans/{{ p.id }}">{{ p.id }}</a></td><td>{{ p.at|ts }}</td><td>{{ p.domain }}</td>
<td class="{{ 'ok' if p.status == 'applied' else ('warn' if p.status in ('awaiting_approval','partial') else 'muted') }}">{{ p.status }}</td>
<td>{% for k, v in p.summary.items() if k not in ('applied_by',) %}<span class="chip">{{ k }} {{ v }}</span>{% endfor %}</td>
<td>{{ p.decided_by or '' }} {{ p.decided_at|ts }}</td></tr>
{% else %}<tr><td colspan="6" class="muted">No plans.</td></tr>{% endfor %}</table></div>
{% endblock %}"""

C_PLAN = """{% extends "base.html" %}{% block title %}AD plan {{ p.id }}{% endblock %}{% block body %}
<h1>AD plan #{{ p.id }} · {{ p.domain }}</h1>
<p>{{ p.at|ts }} · mode {{ p.mode }} · <b>{{ p.status }}</b>{% if p.decided_by %} · decided by {{ p.decided_by }} {{ p.decided_at|ts }}{% endif %}
· <a href="/files/{{ p.file_sha256 }}">zip</a></p>
{% if p.status == 'awaiting_approval' and can('operator') %}
<form class="inline" method="post" action="/ad/plans/{{ p.id }}/approve">{{ csrf() }}<button class="primary">Approve and apply</button></form>
<form class="inline" method="post" action="/ad/plans/{{ p.id }}/reject">{{ csrf() }}<button class="danger">Reject</button></form>
<p class="muted">Applying re-checks AD first, so only what is still needed is changed.</p>{% endif %}
<div class="wrap"><table><tr><th>#</th><th>Instruction</th><th>LDAP</th><th>Object</th><th>Change</th><th>Why</th></tr>
{% for i in p['items'] %}<tr><td>{{ i.seq }}</td><td><b>{{ i.op }}</b> {{ i.object_class }} <span class="mono">{{ i.key|tojson }}</span></td>
<td class="{{ 'bad' if i.ldap == 'error' or i.ok == false else ('muted' if i.ldap in ('noop','skipped') else 'warn') }}">{{ i.ldap }}{% if i.ok is defined and i.ok is not none %} {{ '✓' if i.ok else '✗' }}{% endif %}</td>
<td class="mono">{{ i.dn or '' }}{% if i.member_dn %}<div class="muted">member {{ i.member_dn }}</div>{% endif %}</td>
<td class="mono">{% if i.attributes %}{{ i.attributes|tojson }}{% elif i.changes %}{{ i.changes|tojson }}{% endif %}{% if i.error %}<div class="bad">{{ i.error }}</div>{% endif %}{% if i.note %}<div class="muted">{{ i.note }}</div>{% endif %}</td>
<td>{{ i.why or '' }}</td></tr>{% endfor %}</table></div>
{% endblock %}"""

C_ALERTS = """{% extends "base.html" %}{% block title %}AD changes{% endblock %}{% block body %}
<h1>AD changes made outside the consumer</h1>
<p class="muted">The consumer's own writes never appear here. LDAP cannot tell who made a change: check the
domain controllers' security log (events 4720, 4722, 4725, 4728, 4729, 4732, 4738, 4756) for the account.</p>
<form class="f" method="get">
<select name="show"><option value="open">unacknowledged</option><option value="all" {{ 'selected' if not open_only }}>all</option></select>
<select name="severity"><option value="">any severity</option>{% for s in ['critical','warning','info'] %}<option {{ 'selected' if args.get('severity') == s }}>{{ s }}</option>{% endfor %}</select>
<button>Filter</button></form>
{% if can('operator') %}<form method="post" action="/ad/changes/check" class="row">{{ csrf() }}<button>Check AD now</button></form>{% endif %}
<div class="wrap"><table><tr><th>Seen</th><th>Severity</th><th>What</th><th>Object</th><th>Changes</th><th>Acknowledged</th></tr>
{% for a in rows %}<tr><td>{{ a.at|ts }}</td>
<td class="{{ 'bad' if a.severity == 'critical' else ('warn' if a.severity == 'warning' else 'muted') }}">{{ a.severity }}</td>
<td>{{ a.kind }} {{ a.object_class }}</td><td class="mono">{{ a.dn }}</td>
<td class="mono">{% for attr, c in a.changes.items() %}<div><b>{{ attr }}</b>:
{% if c.added is defined %}{% if c.added %}+{{ c.added|join(', ') }}{% endif %} {% if c.removed %}-{{ c.removed|join(', ') }}{% endif %}
{% else %}{{ c.old|tojson }} → {{ c.new|tojson }}{% endif %}</div>{% endfor %}</td>
<td>{% if a.acknowledged_at %}{{ a.acknowledged_by }} {{ a.acknowledged_at|ts }}{% if a.note %}<div class="muted">{{ a.note }}</div>{% endif %}
{% elif can('operator') %}<form method="post" action="/ad/changes/{{ a.id }}/ack" class="row">{{ csrf() }}
<input name="note" placeholder="note (who / why)"><button>acknowledge</button></form>{% endif %}</td></tr>
{% else %}<tr><td colspan="6" class="ok">No changes outside the consumer.</td></tr>{% endfor %}</table></div>
{% endblock %}"""

TEMPLATES = {
    "base.html": BASE, "login.html": LOGIN, "account.html": ACCOUNT,
    "admin_users.html": ADMIN_USERS, "admin_audit.html": ADMIN_AUDIT, "requests.html": REQUESTS,
    "p_dashboard.html": P_DASHBOARD, "p_activity.html": P_ACTIVITY,
    "p_activity_detail.html": P_ACTIVITY_DETAIL, "p_outbox.html": P_OUTBOX,
    "p_outbox_detail.html": P_OUTBOX_DETAIL, "p_runs.html": P_RUNS, "p_apikeys.html": P_APIKEYS,
    "c_dashboard.html": C_DASHBOARD, "c_files.html": C_FILES, "c_file.html": C_FILE,
    "c_actions.html": C_ACTIONS, "c_drift.html": C_DRIFT, "c_drift_detail.html": C_DRIFT_DETAIL,
    "c_plans.html": C_PLANS, "c_plan.html": C_PLAN, "c_alerts.html": C_ALERTS,
}
