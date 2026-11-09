"""Jinja templates for both web UIs (autoescaped: every name ends in .html).

No inline script or style: CSS and JS are same-origin files in static/ (CSP 'self' only),
vendored libraries carry SRI hashes, and every page works with JavaScript off.
"""

BASE = """<!doctype html>
<html lang="en" data-theme="{{ theme }}"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
{% block head %}{% endblock %}
<title>{% block title %}{{ site_title }}{% endblock %} · {{ site_title }}</title>
<link rel="stylesheet" href="/static/vendor/dataTables.dataTables.min.css" integrity="sha384-bK2L0Q3Sn2fB8YZTIjKejpTUJXd8xNtKn4RcIm7KM3EX3orMlOI31hwtNH0iyky/">
<link rel="stylesheet" href="/static/app.css">
<script src="/static/vendor/jquery.min.js" integrity="sha384-1H217gwSVyLSIfaLxHbE7dRb3v4mYCKbpQvzx0cegeju1MVsGrX5xXxAvs/HgeFs" defer></script>
<script src="/static/vendor/dataTables.min.js" integrity="sha384-MgwUq0TVErv5Lkj/jIAgQpC+iUIqwhwXxJMfrZQVAOhr++1MR02yXH8aXdPc3fk0" defer></script>
<script src="/static/app.js" defer></script></head><body>
{% if user %}
<header><b>{{ site_title }}</b><nav>
{% for path, label, min_role in nav %}{% if can(min_role) %}
<a href="{{ path }}" class="{{ 'on' if (request.path == path or (path != '/' and request.path.startswith(path))) }}">{{ label }}</a>
{% endif %}{% endfor %}
</nav><div class="who">
<form class="inline theme" method="post" action="/theme" title="Colour theme">{{ csrf() }}
{% for t, label in [('light','light'),('dark','dark'),('auto','auto')] %}<button name="theme" value="{{ t }}" class="{{ 'on' if theme == t }}">{{ label }}</button>{% endfor %}</form>
<span>{{ user.username }} · {{ user.role }}</span>
<a href="/account">account</a>
<form class="inline" method="post" action="/logout">{{ csrf() }}<button>log out</button></form></div></header>
{% endif %}
<main>
{% for cat, msg in get_flashed_messages(with_categories=true) %}<div class="flash {{ cat }}">{{ msg }}</div>{% endfor %}
{% block body %}{% endblock %}</main></body></html>"""

# Rendered via the save_search_form() global (see SAVE_SEARCH): current page + a name.
SAVE_SEARCH = """{% if user %}<form method="post" action="/searches" class="row">{{ csrf() }}
<input type="hidden" name="path" value="{{ request.full_path }}"><input name="name" placeholder="name this search" maxlength="100" required>
<button>Save search</button>{% for s in saved_searches() %}<span class="chip"><a href="{{ s.path }}">{{ s.name }}</a></span>{% endfor %}</form>{% endif %}"""

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
<h2>Two-factor sign-in</h2>
<p><a href="/account/mfa">{{ 'Manage' if user.totp_secret else 'Set up' }} two-factor sign-in</a>
{% if user.totp_secret %}<span class="ok">on</span>{% else %}<span class="warn">off</span>{% endif %}</p>
<h2>Sessions</h2>
<form method="post" action="/account/logout-everywhere">{{ csrf() }}<button>Log out on every device</button></form>
{% endblock %}"""

LOGIN_MFA = """{% extends "base.html" %}{% block title %}Two-factor sign-in{% endblock %}{% block body %}
<div class="login card"><h1>Two-factor sign-in</h1>
<p class="muted">Enter the 6-digit code from your authenticator app.</p>
<form method="post" action="/login/mfa">{{ csrf() }}
<label for="c">Code</label><input id="c" name="code" inputmode="numeric" autocomplete="one-time-code"
 pattern="[0-9 ]{6,7}" maxlength="7" required autofocus>
<p><button class="primary">Verify</button></p></form>
<details><summary class="muted">Lost your device? Use a recovery code</summary>
<form method="post" action="/login/mfa">{{ csrf() }}<input type="hidden" name="kind" value="recovery">
<label for="r">Recovery code</label><input id="r" name="code" autocomplete="off" maxlength="20" required>
<p><button>Use recovery code</button></p></form></details>
<p><a href="/login">Start again</a></p></div>
{% endblock %}"""

ACCOUNT_MFA = """{% extends "base.html" %}{% block title %}Two-factor sign-in{% endblock %}{% block body %}
<h1>Two-factor sign-in</h1><p><a href="/account">← Account</a></p>
{% if enrolled %}
<p class="ok"><b>On.</b> Every sign-in needs a code from your authenticator app.</p>
<p class="muted">{{ recovery_left }} unused recovery code(s) left.</p>
<h2>New recovery codes</h2>
<form method="post" action="/account/mfa/recovery" class="row">{{ csrf() }}
<input name="code" placeholder="current 6-digit code" inputmode="numeric" autocomplete="one-time-code" required maxlength="20">
<button>Generate new codes</button></form><p class="muted">The old codes stop working.</p>
{% if not required %}<h2>Turn off</h2>
<form method="post" action="/account/mfa/disable" class="row">{{ csrf() }}
<input name="password" type="password" placeholder="password" autocomplete="current-password" required>
<input name="code" placeholder="code or recovery code" autocomplete="one-time-code" required maxlength="20">
<button class="danger" data-confirm="Turn off two-factor sign-in?">Turn off</button></form>
{% else %}<p class="muted">Your role requires two-factor sign-in.</p>{% endif %}
{% else %}
<ol><li>In an authenticator app (Microsoft Authenticator, Google Authenticator, 1Password, ...) add an
account with <b>enter a setup key</b> (time based):
<div class="secret">{{ secret_b32 }}</div>
<p class="muted">or open this link on the device: <span class="mono">{{ uri }}</span></p></li>
<li>Enter the 6-digit code it shows:
<form method="post" action="/account/mfa/enable" class="row">{{ csrf() }}
<input name="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9 ]{6,7}" maxlength="7" required autofocus>
<button class="primary">Turn on</button></form></li></ol>
<p class="muted">You will then get recovery codes for when the device is lost.</p>
{% endif %}
{% endblock %}"""

ACCOUNT_MFA_CODES = """{% extends "base.html" %}{% block title %}Recovery codes{% endblock %}{% block body %}
<h1>Recovery codes</h1>
<p class="warn"><b>Shown once.</b> Store them somewhere safe (a password manager). Each works once,
instead of an authenticator code.</p>
<div class="secret">{% for c in codes %}{{ c }}<br>{% endfor %}</div>
<p><a href="/account/mfa">Done</a></p>
{% endblock %}"""

ADMIN_USERS = """{% extends "base.html" %}{% block title %}Users{% endblock %}{% block body %}
<h1>Web users</h1>
<div class="wrap"><table><tr><th>User</th><th>Role</th><th>State</th><th>MFA</th><th>Approves</th><th>Employee</th><th>Last sign-in</th><th>Actions</th></tr>
{% for u in users %}<tr><td>{{ u.username }}{% if u.auth_source == 'ldap' %} <span class="chip" title="{{ u.external_dn }}">AD</span>{% endif %}</td>
<td><form class="inline" method="post" action="/admin/users/{{ u.username|urlencode }}/role">{{ csrf() }}
<select name="role">{% for r in roles %}<option {{ 'selected' if r == u.role }}>{{ r }}</option>{% endfor %}</select>
<button>set</button></form></td>
<td>{% if u.disabled %}<span class="bad">disabled</span>{% elif u.locked_until and u.locked_until > now %}<span class="warn">locked</span>{% else %}<span class="ok">active</span>{% endif %}
{% if u.failed_logins %}<span class="muted">({{ u.failed_logins }} failed)</span>{% endif %}</td>
<td>{% if u.mfa %}<span class="ok">on</span> <span class="muted">({{ u.recovery_left }} codes)</span>
{% if u.username != user.username %}<form class="inline" method="post" action="/admin/users/{{ u.username|urlencode }}/mfa-reset">{{ csrf() }}<button class="danger" data-confirm="Reset two-factor sign-in for {{ u.username }}? They must set it up again.">reset</button></form>{% endif %}
{% else %}<span class="warn">off</span>{% endif %}</td>
<td>{% if u.role == 'admin' and site == 'producer' %}<form class="inline" method="post" action="/admin/users/{{ u.username|urlencode }}/scope">{{ csrf() }}
<input name="scope" value="{{ (u.approver_scope or [])|join(', ') }}" placeholder="all domains / OUs" maxlength="2000"><button>set</button></form>{% else %}<span class="muted">-</span>{% endif %}</td>
<td>{% if site == 'producer' %}<form class="inline" method="post" action="/admin/users/{{ u.username|urlencode }}/employee">{{ csrf() }}
<input name="employee_id" value="{{ u.employee_id or '' }}" placeholder="employee id" maxlength="255" size="10"><button>link</button></form>{% endif %}</td>
<td>{{ u.last_login_at|ts }}</td>
<td>{% if u.username != user.username %}
<form class="inline" method="post" action="/admin/users/{{ u.username|urlencode }}/{{ 'enable' if u.disabled else 'disable' }}">{{ csrf() }}<button class="{{ '' if u.disabled else 'danger' }}">{{ 'enable' if u.disabled else 'disable' }}</button></form>
{% endif %}
<form class="inline" method="post" action="/admin/users/{{ u.username|urlencode }}/unlock">{{ csrf() }}<button>unlock</button></form>
{% if u.auth_source != 'ldap' %}<form class="inline" method="post" action="/admin/users/{{ u.username|urlencode }}/password">{{ csrf() }}
<input name="password" type="password" placeholder="new password" autocomplete="new-password" required><button>reset</button></form>
{% else %}<span class="muted small">role from AD groups at each sign-in</span>{% endif %}
</td></tr>{% endfor %}</table></div>
<h2>Add user</h2>
<form method="post" action="/admin/users" class="row">{{ csrf() }}
<input name="username" placeholder="username" required>
<input name="password" type="password" placeholder="password (12+ characters)" autocomplete="new-password" required>
<select name="role">{% for r in roles %}<option>{{ r }}</option>{% endfor %}</select>
<button class="primary">Add</button></form>
<p class="muted">viewer: read only · auditor: also reads the audit trail, approvals, reports and alerts, changes nothing ·
operator: also run actions · admin: also users{{ ' and API keys' if site == 'producer' }}.
{% if site == 'producer' %}Approves: comma-separated domains / organizations an admin may approve changes for (empty: all).{% endif %}</p>
{% endblock %}"""

ADMIN_AUDIT = """{% extends "base.html" %}{% block title %}Audit trail{% endblock %}{% block body %}
<h1>Audit trail</h1>
<form method="post" action="/admin/audit/verify" class="row">{{ csrf() }}<button>Verify integrity (hash chain)</button>
<span class="muted">Each entry carries the hash of the one before: a changed or removed entry is detected.</span></form>
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
<h1>Operator requests</h1><span data-refresh-while=".status-running,.status-pending"></span>
<p class="muted">Buttons in this UI queue a request; the {{ service }} service runs it within seconds.</p>
<div class="wrap"><table data-dt><tr><th>#</th><th>Asked</th><th>By</th><th>Action</th><th>Status</th><th>Result</th></tr>
{% for r in rows %}<tr><td>{{ r.id }}</td><td>{{ r.at|ts }}</td><td>{{ r.requested_by }}</td>
<td>{{ r.action }}{% if r.params %} <span class="muted mono">{{ r.params|tojson }}</span>{% endif %}</td>
<td class="status-{{ r.status }} {{ 'ok' if r.status == 'done' else ('bad' if r.status in ('failed','rejected') else 'warn') }}">{{ r.status }}{% if r.decided_by %}<div class="muted">{{ r.decided_by }}</div>{% endif %}</td>
<td><details><summary class="muted">{{ (r.result or {})|tojson|truncate(80) }}</summary><pre>{{ r.result|pretty }}</pre></details></td></tr>
{% else %}<tr><td colspan="6" class="muted">No requests.</td></tr>{% endfor %}</table></div>
{% endblock %}"""

# ============================ producer site ==================================

P_DASHBOARD = """{% extends "base.html" %}
{% block head %}<meta http-equiv="refresh" content="30">{% endblock %}
{% block title %}Dashboard{% endblock %}{% block body %}
<h1>Producer site <span class="muted sub">last 24 h · refreshes every 30 s</span></h1>
<div class="cards">
 <div class="card"><div class="muted">Producer events</div>
  <div class="n"><span class="ok">{{ producer.ok }}</span> / <span class="{{ 'bad' if producer.failed }}">{{ producer.failed }}</span></div>
  <div class="muted">applied / failed</div></div>
 <div class="card"><div class="muted">AD instructions</div>
  <div class="n">{{ outbox.pending }} <span class="muted n14">pending</span></div>
  <div class="muted">{{ outbox.delivered }} delivered · <span class="{{ 'bad' if outbox.dead }}">{{ outbox.dead }} dead</span></div>
  {% if outbox.last_error %}<div class="bad small">{{ outbox.last_error }}</div>{% endif %}</div>
 <div class="card"><div class="muted">Latest change detection</div>
  {% if runs %}<div class="n {{ 'ok' if runs[0].status in ('ok','baseline') else ('bad' if runs[0].status == 'failed') }}">{{ runs[0].status }}</div>
  <div class="muted">{{ runs[0].started_at|ts }}</div>{% else %}<div class="muted">no runs</div>{% endif %}</div>
</div>
<div class="cards mt">
 <div class="card"><div class="muted">Waiting for approval</div><div class="n {{ 'warn' if approvals.waiting }}">{{ approvals.waiting }}</div>
  <div class="muted">{% if can('admin') %}<a href="/approvals">Approvals →</a>{% endif %}</div></div>
 <div class="card"><div class="muted">Approval turnaround</div>
  <div class="n">{{ '%.1f'|format(approvals.median_hours) if approvals.median_hours is not none else '-' }} <span class="muted n14">h median</span></div>
  <div class="muted">last {{ approvals.decided }} decision(s)</div></div>
 <div class="card"><div class="muted">SoD violations</div><div class="n {{ 'bad' if violations }}">{{ violations }}</div>
  <div class="muted"><a href="/governance">Governance →</a></div></div>
</div>
<h2>Joiners, movers and leavers per week</h2>
<div class="card"><div class="legend">{% for name in series %}<span class="s{{ loop.index }}">{{ name }}</span>{% endfor %}</div>
{{ chart }}
<details><summary class="muted">table view</summary><div class="wrap"><table><tr><th>Week of</th>{% for name in series %}<th>{{ name }}</th>{% endfor %}</tr>
{% for lab in jml.labels %}{% set i = loop.index0 %}<tr><td>{{ lab }}</td>{% for name, vals in series.items() %}<td>{{ vals[i] }}</td>{% endfor %}</tr>{% endfor %}</table></div></details></div>
{% if blocked %}<div class="flash error mt">The latest run was refused as a mass delete: {{ blocked }}.
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
<div class="wrap"><table data-dt data-dt-page="50"><tr><th>When</th><th>Employee</th><th>Event</th><th>Result</th><th>What it did</th></tr>
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
{% if r.last_error and not r.delivered_at %}<div class="bad small">{{ r.last_error }}</div>{% endif %}</td>
</tr>{% else %}<tr><td colspan="5" class="muted">Nothing yet.</td></tr>{% endfor %}</table></div>
{% if next_before %}<div class="pager"><a href="?before={{ next_before }}">Older →</a></div>{% endif %}
{% endblock %}"""

P_OUTBOX_DETAIL = """{% extends "base.html" %}{% block title %}Outbox {{ e.seq }}{% endblock %}{% block body %}
<h1>{{ e.payload.type }} <span class="muted">#{{ e.seq }}</span></h1>
<p>{% if e.delivered_at %}<span class="ok">delivered</span> {{ e.delivered_at|ts }}{% elif e.dead %}<span class="bad">dead</span>{% else %}<span class="warn">pending</span>{% endif %}
· {{ e.attempts }} attempt(s){% if e.last_error %} · <span class="bad">{{ e.last_error }}</span>{% endif %}</p>
{% if e.payload.why %}<h2>Why</h2><pre>{{ e.payload.why|pretty }}</pre>{% endif %}
<h2>Instructions</h2>
<div class="wrap"><table><tr><th>Instruction</th><th>At the consumer sites</th></tr>
{% for i in e.payload.instructions or [] %}<tr><td>{{ i.op }} {{ i.object_class }} <span class="mono">{{ i.key }}</span>{% if i.member %} · member <span class="mono">{{ i.member.key }}</span>{% endif %}</td>
<td>{% for r in receipts.get(i.instruction_id, []) %}<div><b>{{ r.site }}</b>: <span class="{{ 'bad' if r.status in ('failed','rejected','not_applied') else ('ok' if r.status in ('applied','unchanged','covered_by_records') else 'warn') }}">{{ r.status }}</span>
<span class="muted">{{ r.at|ts }}</span>{% if r.detail %}<div class="small muted">{{ r.detail }}</div>{% endif %}</div>
{% else %}<span class="muted">no receipt yet</span>{% endfor %}</td></tr>{% endfor %}</table></div>
<details><summary class="muted">raw</summary><pre>{{ (e.payload.instructions or [])|pretty }}</pre></details>
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
<form class="inline" method="post" action="/admin/apikeys/{{ k.name|urlencode }}/revoke">{{ csrf() }}<button class="danger" data-confirm="Revoke this API key? Callers using it stop working.">revoke</button></form>{% endif %}</td></tr>
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
<h1>Consumer site <span class="muted sub">applies to: <b>{{ 'Active Directory' if target == 'ad' else 'remote OpenIAM' }}</b>
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
{% if can('operator') %}<form method="post" action="/scan" class="row mt">{{ csrf() }}<button>Scan the inbox now</button></form>{% endif %}
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
<h1 class="mono h16">{{ f.name }}</h1>
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
<h1>AD plans <span class="muted sub">mode: {{ ad_mode }}</span></h1>
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
<form class="inline" method="post" action="/ad/plans/{{ p.id }}/reject">{{ csrf() }}<button class="danger" data-confirm="Reject this AD plan?">Reject</button></form>
<p class="muted">Applying re-checks AD first, so only what is still needed is changed.</p>{% endif %}
<div class="wrap"><table><tr><th>#</th><th>Instruction</th><th>LDAP</th><th>Object</th><th>Change</th><th>Why</th></tr>
{% for i in p.get('items') %}<tr><td>{{ i.seq }}</td><td><b>{{ i.op }}</b> {{ i.object_class }} <span class="mono">{{ i.key|tojson }}</span></td>
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

# ============================ directory (producer site) ======================

DIR_MACROS = """{% macro via() %}<select name="via" title="Where this change goes">
<option value="openiam">OpenIAM + AD</option><option value="ad">AD instructions only</option></select>{% endmacro %}
{% macro hidden(kind, op, name, back) %}{{ csrf() }}<input type="hidden" name="kind" value="{{ kind }}">
<input type="hidden" name="op" value="{{ op }}"><input type="hidden" name="name" value="{{ name }}">
<input type="hidden" name="back" value="{{ back }}">{% endmacro %}
{% macro justify() %}<input name="jira_ticket" placeholder="Jira ticket, e.g. IAM-123" required maxlength="20"
pattern="[A-Za-z][A-Za-z0-9_]{1,9}-[1-9][0-9]{0,8}" title="Jira issue key, e.g. IAM-123">
<input name="reason" placeholder="Justification: why is this needed?" required minlength="10" maxlength="1024">{% endmacro %}
{% macro justify_grid() %}<label>Jira ticket *<input name="jira_ticket" placeholder="IAM-123" required maxlength="20"
pattern="[A-Za-z][A-Za-z0-9_]{1,9}-[1-9][0-9]{0,8}" title="Jira issue key, e.g. IAM-123"></label>
<label>Justification *<input name="reason" placeholder="why is this needed? (10+ characters)" required minlength="10" maxlength="1024"></label>{% endmacro %}
{% macro ad(r) %}{% if r.ad %}<div class="small">AD:
{% if not r.ad.reported %}<span class="warn">waiting for the consumer site ({{ r.ad.total }})</span>
{% else %}{% for st, n in r.ad.by_status.items() %}<span class="{{ 'bad' if st in ('failed','rejected','not_applied') else ('ok' if st in ('applied','unchanged','covered_by_records') else 'warn') }}">{{ st }} {{ n }}</span>{{ ' · ' if not loop.last }}{% endfor %}
{% if r.ad.reported < r.ad.total %} · <span class="warn">{{ r.ad.total - r.ad.reported }} not yet reported</span>{% endif %}
<span class="muted">({{ r.ad.sites|join(', ') }})</span>{% endif %}</div>{% endif %}{% endmacro %}
{% macro save() %}<button formaction="/directory/preview">Preview</button>
<button class="primary">Save for approval</button>{% endmacro %}
{% macro domains_list(domains) %}<datalist id="domains">{% for d in domains %}<option value="{{ d }}">{% endfor %}</datalist>{% endmacro %}
{% macro summary(p) %}{% if p.jira_ticket %}{{ p.jira_ticket|jira }} · {% endif %}{% if p.get('items') is not none %}<b>batch</b> {{ p.label }} · {{ p.get('items')|length }} change(s)
{% if p.reason %}<div><b>Justification:</b> {{ p.reason }}</div>{% endif %}
<details><summary class="muted">rows</summary><ol>{% for i in p.get('items') %}<li>{{ i.op }} {{ i.kind }} <span class="mono">{{ i.name }}</span>{% if i.member %} · {{ i.member_kind }} <span class="mono">{{ i.member }}</span>{% endif %}{% if i.expires_on %} · until {{ i.expires_on }}{% endif %} <span class="chip">{{ 'OpenIAM + AD' if i.via == 'openiam' else 'AD only' }}</span></li>{% endfor %}</ol></details>
{% else %}<b>{{ p.op }}</b> {{ p.kind }} <span class="mono">{{ p.name }}</span>
{% if p.member %} · {{ p.member_kind }} <span class="mono">{{ p.member }}</span>{% endif %}
{% if p.new_name %} → <span class="mono">{{ p.new_name }}</span>{% endif %}
<span class="chip">{{ 'OpenIAM + AD' if p.via == 'openiam' else 'AD only' }}</span>
{% if p.domain %}<span class="chip">domain {{ p.domain }}</span>{% endif %}
{% if p.reason %}<div><b>Justification:</b> {{ p.reason }}</div>{% endif %}
{% for k in ['org_type','first_name','last_name','email','login','title','description','expires_on'] %}{% if p[k] %}<div class="muted">{{ k }}: {{ p[k] }}</div>{% endif %}{% endfor %}
{% for k in ['groups','roles','organizations'] %}{% if p[k] %}<div class="muted">{{ k }}: {{ p[k]|join(', ') }}</div>{% endif %}{% endfor %}{% endif %}{% endmacro %}"""

P_DIRECTORY = """{% extends "base.html" %}{% block title %}{{ labels[kind] }}{% endblock %}{% block body %}
<h1>Directory</h1>
<p class="muted">OpenIAM as last seen by change detection. Changes are saved here first and wait for a
manager's approval in <b>Approvals</b>; only then are they written to OpenIAM and/or sent as AD
instructions, which the consumer site applies to its domain controllers.</p>
<div class="tabs">{% for k, l in labels.items() %}<a href="/directory?kind={{ k }}" class="{{ 'on' if k == kind }}">{{ l }}</a>{% endfor %}</div>
<form class="f" method="get"><input type="hidden" name="kind" value="{{ kind }}">
<input name="q" placeholder="Search {{ labels[kind]|lower }}" value="{{ q }}"><button>Search</button>
{% if can('operator') %}<a href="/directory/{{ kind }}/new"><b>+ New {{ single[kind] }}</b></a> · <a href="/directory/import">Bulk import (CSV)</a>{% endif %}
{% if kind == 'organization' %} · <a href="/directory/tree">Tree view</a>{% endif %}</form>
{{ save_search_form() }}
<div class="wrap"><table data-dt>
{% if kind == 'user' %}<tr><th>Employee id</th><th>Name</th><th>Login</th><th>Email</th><th>Domain</th><th>Status</th></tr>
{% for r in rows %}<tr><td><a href="/directory/user/view?name={{ r.name|urlencode }}">{{ r.name or '(no employee id)' }}</a></td>
<td>{{ r.rec.firstName }} {{ r.rec.lastName }}</td><td class="mono">{{ r.rec.login }}</td><td>{{ r.rec.email }}</td>
<td>{{ r.domain }}</td><td>{{ r.rec.userStatus or r.rec.status }}</td></tr>
{% else %}<tr><td colspan="6" class="muted">No users{{ ' match' if q }}. {{ 'Run change detection to load them from OpenIAM.' if not total }}</td></tr>{% endfor %}
{% else %}<tr><th>Name</th>{% if kind == 'organization' %}<th>Type</th>{% endif %}<th>Description</th><th>Domain</th><th>OpenIAM id</th></tr>
{% for r in rows %}<tr><td><a href="/directory/{{ kind }}/view?name={{ r.name|urlencode }}">{{ r.name }}</a></td>
{% if kind == 'organization' %}<td>{{ r.org_type }}</td>{% endif %}
<td>{{ r.rec.description }}</td><td>{{ r.domain }}</td><td class="mono muted">{{ r.rec.id }}</td></tr>
{% else %}<tr><td colspan="5" class="muted">No {{ labels[kind]|lower }}{{ ' match' if q }}. {{ 'Run change detection to load them from OpenIAM.' if not total }}</td></tr>{% endfor %}
{% endif %}</table></div>
<p class="muted">{{ rows|length }} shown of {{ total }} in the snapshot.</p>
{% endblock %}"""

P_DIR_NEW = """{% extends "base.html" %}{% import "dir_macros.html" as m with context %}
{% block title %}New {{ single[kind] }}{% endblock %}{% block body %}
<h1>New {{ single[kind] }}</h1><p><a href="/directory?kind={{ kind }}">← {{ labels[kind] }}</a></p>
<form method="post" action="/directory/request">{{ m.hidden(kind, 'create', '', '/directory?kind=' ~ kind) }}
<div class="grid">
{% if kind == 'user' %}
<label>Employee id *<input name="name" required></label>
<label>First name *<input name="first_name" required maxlength="256" data-suggest></label>
<label>Last name *<input name="last_name" required maxlength="256" data-suggest></label>
<label>Email<input name="email" type="email" maxlength="256"></label>
<label>Login (sAMAccountName)<input name="login" maxlength="20" data-suggest></label>
<label>Title<input name="title"></label>
<label>Domain<input name="domain" list="domains"></label>
<label>Groups (comma separated)<input name="groups"></label>
<label>Organizations / OUs (comma separated)<input name="organizations"></label>
<label>Roles (comma separated)<input name="roles"></label>
{% else %}
<label>Name *<input name="name" required maxlength="256"></label>
{% if kind == 'organization' %}<label>Type *<select name="org_type" required>
{% for k, l in org_types.items() %}<option value="{{ k }}">{{ l }}</option>{% endfor %}</select></label>{% endif %}
<label>Description<input name="description" maxlength="1024"></label>
<label>Domain<input name="domain" list="domains"></label>
{% endif %}
{{ m.justify_grid() }}
<label>Write to{{ m.via() }}</label></div>
{{ m.domains_list(domains) }}
{{ m.save() }}</form>
{% if kind == 'user' %}<p class="muted">The new user is written to OpenIAM through the producer engine (like an HR hire).
AD creates new users disabled; this tool never sets passwords.</p>{% endif %}
{% endblock %}"""

P_DIR_OBJECT = """{% extends "base.html" %}{% import "dir_macros.html" as m with context %}
{% block title %}{{ single[kind] }} {{ name }}{% endblock %}{% block body %}
{% set back = '/directory/' ~ kind ~ '/view?name=' ~ (name|urlencode) %}
<h1>{{ single[kind]|capitalize }} <span class="mono">{{ name }}</span></h1>
<p><a href="/directory?kind={{ kind }}">← {{ labels[kind] }}</a>
{% if not rec %} · <span class="warn">not in the OpenIAM snapshot (new, AD only, or change detection has not run)</span>{% endif %}</p>

<h2>memberOf</h2>
{% if memberships or member_of %}<div class="wrap"><table><tr><th>Kind</th><th>Member of</th><th>Source</th></tr>
{% for k, names in memberships.items() %}<tr><td>{{ k }}</td><td>{% for n in names %}<span class="chip">{{ n }}</span>{% endfor %}</td><td class="muted">granted by the producer</td></tr>{% endfor %}
{% for k, names in member_of.items() %}<tr><td>{{ k }}</td><td>{% for n in names %}<span class="chip">{{ n }}</span>{% endfor %}</td><td class="muted">OpenIAM snapshot</td></tr>{% endfor %}
</table></div>{% else %}<p class="muted">No memberships known here.</p>{% endif %}

{% if can('operator') %}
<h2>Edit</h2>
<form method="post" action="/directory/request">{{ m.hidden(kind, 'update', name, back) }}<div class="grid">
{% if kind == 'user' %}
<label>First name *<input name="first_name" value="{{ rec.firstName if rec else '' }}" required></label>
<label>Last name *<input name="last_name" value="{{ rec.lastName if rec else '' }}" required></label>
<label>Email<input name="email" type="email" value="{{ rec.email if rec and rec.email is string else '' }}"></label>
<label>Login<input name="login" maxlength="20" value="{{ rec.login if rec and rec.login is string else '' }}"></label>
<label>Title<input name="title" value="{{ rec.title if rec and rec.title is string else '' }}"></label>
{% else %}
<label>Rename to (OpenIAM only)<input name="new_name" value="{{ name }}"></label>
{% if kind == 'organization' %}<label>Type<select name="org_type"><option value="">(unchanged)</option>
{% for k, l in org_types.items() %}<option value="{{ k }}" {{ 'selected' if k == org_type }}>{{ l }}</option>{% endfor %}</select></label>{% endif %}
<label>Description<input name="description" value="{{ rec.description if rec and rec.description is string else '' }}"></label>
{% endif %}
<label>Domain<input name="domain" list="domains" value="{{ domain }}"></label>
{{ m.justify_grid() }}
<label>Write to{{ m.via() }}</label></div>
{{ m.save() }}</form>

{% if kind == 'group' or kind == 'role' or kind == 'organization' %}
<h2>Members</h2>
<form method="post" action="/directory/request" class="row">{{ m.hidden(kind, 'add_member', name, back) }}
<select name="op"><option value="add_member">add</option><option value="remove_member">remove</option></select>
<select name="member_kind"><option value="user">user (employee id)</option>{% if kind == 'group' %}<option value="group">group (nested: memberOf)</option>{% endif %}</select>
<input name="member" placeholder="employee id or group name" required>
<input name="domain" list="domains" placeholder="domain" value="{{ domain }}">
<label class="muted">until <input name="expires_on" type="date" title="optional: access ends on this day (add only)"></label>
{{ m.justify() }}{{ m.via() }}{{ m.save() }}</form>
{% if kind == 'organization' %}<p class="muted">AD has no OU membership: these go to OpenIAM; the consumer skips the AD instruction.</p>{% endif %}
{% endif %}
{% if kind == 'user' %}
<p><a href="/directory/user/move?name={{ name|urlencode }}"><b>Mover: change department / branch →</b></a></p>
<h2>Member of</h2>
<form method="post" action="/directory/request" class="row">{{ csrf() }}<input type="hidden" name="back" value="{{ back }}">
<input type="hidden" name="member_kind" value="user"><input type="hidden" name="member" value="{{ name }}">
<select name="op"><option value="add_member">add to</option><option value="remove_member">remove from</option></select>
<select name="kind"><option value="group">group</option><option value="role">role</option><option value="organization">organization</option></select>
<input name="name" placeholder="group / role / organization name" required>
<input name="domain" list="domains" placeholder="domain" value="{{ domain }}">
<label class="muted">until <input name="expires_on" type="date" title="optional: access ends on this day (add only)"></label>
{{ m.justify() }}{{ m.via() }}{{ m.save() }}</form>
{% endif %}

<h2>Account</h2>
{% if kind == 'user' %}
<form method="post" action="/directory/request" class="row">{{ m.hidden(kind, 'disable', name, back) }}
<select name="op"><option value="disable">disable (leave)</option><option value="enable">enable (return)</option></select>
{{ m.justify() }}<input name="domain" list="domains" placeholder="domain" value="{{ domain }}">{{ m.via() }}{{ m.save() }}</form>
{% endif %}
<form method="post" action="/directory/request" class="row">{{ m.hidden(kind, 'delete', name, back) }}
{{ m.justify() }}<input name="domain" list="domains" placeholder="domain" value="{{ domain }}">{{ m.via() }}
<button class="danger" data-confirm="Save this {{ 'offboarding' if kind == 'user' else 'delete' }} of {{ name }} for approval?">{{ 'Offboard (terminate)' if kind == 'user' else 'Delete' }}</button></form>
<p class="muted">{% if kind == 'user' %}Offboarding disables the AD account (deleted only when the consumer allows deletes) and removes producer-granted access.{% else %}The consumer deletes AD objects only when its <span class="mono">allow_delete</span> is on.{% endif %}</p>
{{ m.domains_list(domains) }}
{% endif %}

<h2>Requests about this {{ single[kind] }}</h2>
<div class="wrap"><table data-dt data-dt-page="10"><tr><th>#</th><th>Asked</th><th>By</th><th>Change</th><th>Status</th></tr>
{% for r in history %}<tr><td>{{ r.id }}</td><td>{{ r.at|ts }}</td><td>{{ r.requested_by }}</td><td>{{ m.summary(r.params) }}</td>
<td class="{{ 'ok' if r.status == 'done' else ('bad' if r.status in ('failed','rejected') else 'warn') }}">{{ r.status }}{% if r.decided_by %}<div class="muted">{{ r.decided_by }}</div>{% endif %}{{ m.ad(r) }}</td></tr>
{% else %}<tr><td colspan="5" class="muted">None yet.</td></tr>{% endfor %}</table></div>
{% if rec %}<h2>OpenIAM record</h2><details><summary class="muted">snapshot data</summary><pre>{{ rec|pretty }}</pre></details>{% endif %}
{% if person %}<h2>Producer record</h2><pre>{{ person|pretty }}</pre>{% endif %}
{% endblock %}"""

P_APPROVALS = """{% extends "base.html" %}{% import "dir_macros.html" as m with context %}
{% block title %}Approvals{% endblock %}{% block body %}
<h1>Approvals</h1>
<p class="muted">Directory changes wait here, in the database only. Nothing is written to OpenIAM and no AD
instruction is queued until one is approved, and never by the person who asked. After approval the
consumer site still applies AD changes according to its own mode (dry run / approve / auto).</p>
<div class="wrap"><table><tr><th>#</th><th>Asked</th><th>By</th><th>Change</th><th>Decision</th></tr>
{% for r in waiting %}<tr><td>{{ r.id }}</td><td>{{ r.at|ts }}</td><td>{{ r.requested_by }}</td><td>{{ m.summary(r.params) }}</td>
<td>{% set jc = (r.checks or {}).get('jira') %}{% if jc %}<div class="small">Jira:
{% if jc.ok and jc.status %}<span class="ok">{{ jc.status }}</span>{% elif jc.ok %}<span class="muted">not checked (JIRA_CHECK off)</span>{% else %}<span class="bad">{{ jc.problem }}</span>{% endif %}
<span class="muted">· checked {{ jc.checked_at|ts }}</span></div>{% endif %}
<div class="muted">approvals {{ (r.approvals or [])|length }} of {{ r.required_approvals or 1 }}{% for a in r.approvals or [] %} · {{ a.by }}{% endfor %}</div>
{% if r.requested_by == me %}<span class="muted">your request: someone else must decide</span>
{% elif not r.mine %}<span class="muted">outside your approval scope ({{ scope|join(', ') }})</span>
{% elif r.approved_by_me %}<span class="muted">you approved; waiting for another approver</span>
{% elif not can('admin') %}<span class="muted">waiting for an approver</span>{% else %}
<form method="post" action="/approvals/{{ r.id }}/approve" class="row">{{ csrf() }}<input name="note" placeholder="note"><button class="primary" data-confirm="Approve? It will be written to OpenIAM and/or sent to AD.">approve</button></form>
<form method="post" action="/approvals/{{ r.id }}/reject" class="row">{{ csrf() }}<input name="note" placeholder="why not"><button class="danger" data-confirm="Reject this request?">reject</button></form>{% endif %}</td></tr>
{% else %}<tr><td colspan="5" class="ok">Nothing waiting.</td></tr>{% endfor %}</table></div>
<h2>Recently decided</h2><span data-refresh-while=".status-running,.status-pending"></span>
<div class="wrap"><table data-dt><tr><th>#</th><th>Change</th><th>Decided</th><th>Status</th><th>Result</th></tr>
{% for r in decided %}<tr><td>{{ r.id }}</td><td>{{ m.summary(r.params) }}<div class="muted">asked by {{ r.requested_by }}</div></td>
<td>{{ r.decided_by }}<div class="muted">{{ r.decided_at|ts }}</div>{% if r.decision_note %}<div>{{ r.decision_note }}</div>{% endif %}</td>
<td class="status-{{ r.status }} {{ 'ok' if r.status == 'done' else ('bad' if r.status in ('failed','rejected') else 'warn') }}">{{ r.status }}{{ m.ad(r) }}</td>
<td>{% if r.result %}<details><summary class="muted">{{ (r.result.actions or [r.result.error])|join('; ')|truncate(80) }}</summary><pre>{{ r.result|pretty }}</pre></details>{% endif %}</td></tr>
{% else %}<tr><td colspan="5" class="muted">None.</td></tr>{% endfor %}</table></div>
{% endblock %}"""

# ============================ governance (producer site) =====================

P_GOVERNANCE = """{% extends "base.html" %}{% block title %}Governance{% endblock %}{% block body %}
<h1>Governance</h1>

<h2>Segregation of duties</h2>
<p class="muted">Nobody may hold both sides of an enabled policy. Directory requests that would create a
toxic combination are refused when asked for and again at approval.</p>
<div class="wrap"><table data-dt data-dt-page="10"><tr><th>Policy</th><th>Side A</th><th>Side B</th><th>State</th><th>Added</th></tr>
{% for p in policies %}<tr><td><b>{{ p.name }}</b>{% if p.description %}<div class="muted">{{ p.description }}</div>{% endif %}</td>
<td>{{ p.left_kind }} <span class="mono">{{ p.left_name }}</span></td><td>{{ p.right_kind }} <span class="mono">{{ p.right_name }}</span></td>
<td class="{{ 'ok' if p.enabled else 'muted' }}">{{ 'enabled' if p.enabled else 'disabled' }}
{% if can('admin') %}<form class="inline" method="post" action="/governance/sod/{{ p.id }}/{{ 'disable' if p.enabled else 'enable' }}">{{ csrf() }}
<button {% if p.enabled %}class="danger" data-confirm="Disable this policy? Toxic combinations would no longer be blocked."{% endif %}>{{ 'disable' if p.enabled else 'enable' }}</button></form>{% endif %}</td>
<td>{{ p.created_by }}<div class="muted">{{ p.created_at|ts }}</div></td></tr>
{% else %}<tr><td colspan="5" class="muted">No policies yet.</td></tr>{% endfor %}</table></div>
{% if can('admin') %}<form method="post" action="/governance/sod" class="row mt">{{ csrf() }}
<input name="name" placeholder="policy name" required maxlength="200">
<select name="left_kind">{% for k in kinds %}<option>{{ k }}</option>{% endfor %}</select><input name="left_name" placeholder="side A name" required maxlength="500">
<span class="muted">conflicts with</span>
<select name="right_kind">{% for k in kinds %}<option>{{ k }}</option>{% endfor %}</select><input name="right_name" placeholder="side B name" required maxlength="500">
<input name="description" placeholder="why (e.g. pay vendors + approve vendors)" maxlength="2000">
<button class="primary">Add policy</button></form>{% endif %}

<h2>Current violations</h2>
<div class="wrap"><table data-dt data-dt-page="10"><tr><th>Employee</th><th>Policy</th><th>Holds</th></tr>
{% for v in violations %}<tr><td><a href="/directory/user/view?name={{ v.employee_id|urlencode }}">{{ v.employee_id }}</a></td>
<td class="bad">{{ v.policy }}</td><td class="mono">{{ v.left }} + {{ v.right }}</td></tr>
{% else %}<tr><td colspan="3" class="ok">No toxic combinations.</td></tr>{% endfor %}</table></div>

<h2>Time-limited access</h2>
<div class="wrap"><table data-dt data-dt-page="10"><tr><th>Ends</th><th>Member</th><th>Of</th><th>Ticket</th><th>Granted by</th></tr>
{% for gr in grants %}<tr><td>{{ gr.expires_at|ts }}</td><td>{{ gr.params.member_kind }} <span class="mono">{{ gr.params.member }}</span></td>
<td>{{ gr.params.kind }} <span class="mono">{{ gr.params.name }}</span></td><td>{{ gr.params.jira_ticket|jira }}</td><td>request {{ gr.request_id }}</td></tr>
{% else %}<tr><td colspan="5" class="muted">No time-limited access.</td></tr>{% endfor %}</table></div>

<h2>Access certifications</h2>
<p class="muted">Reviewers certify or revoke each entitlement. A revocation is saved as a directory request
and is applied only after a second person approves it.</p>
<div class="wrap"><table data-dt data-dt-page="10"><tr><th>#</th><th>Campaign</th><th>Scope</th><th>Progress</th><th>Due</th><th>Status</th></tr>
{% for c in campaigns %}<tr><td>{{ c.id }}</td><td>{% if can('operator') %}<a href="/governance/campaigns/{{ c.id }}">{{ c.name }}</a>{% else %}{{ c.name }}{% endif %}
<div class="muted">by {{ c.created_by }} {{ c.created_at|ts }}</div></td>
<td>{{ c.scope_kind or 'all kinds' }}{% if c.scope_name %} <span class="mono">{{ c.scope_name }}</span>{% endif %}</td>
<td>{{ c.certified + c.revoked }} / {{ c.total }}{% if c.revoked %} <span class="warn">({{ c.revoked }} revoked)</span>{% endif %}</td>
<td class="{{ 'bad' if c.due_at and c.due_at < now and c.status == 'open' }}">{{ c.due_at|ts }}</td>
<td class="{{ 'ok' if c.status == 'closed' else 'warn' }}">{{ c.status }}</td></tr>
{% else %}<tr><td colspan="6" class="muted">No campaigns yet.</td></tr>{% endfor %}</table></div>
{% if can('admin') %}<form method="post" action="/governance/campaigns" class="row mt">{{ csrf() }}
<input name="name" placeholder="campaign name, e.g. Q4 access review" required maxlength="200">
<select name="scope_kind"><option value="">every kind</option>{% for k in kinds %}<option>{{ k }}</option>{% endfor %}</select>
<input name="scope_name" placeholder="only this group / role / org (optional)" maxlength="500">
<input name="due_days" type="number" min="1" max="365" placeholder="due in days">
<button class="primary">Start campaign</button></form>{% endif %}
{% endblock %}"""

P_CAMPAIGN = """{% extends "base.html" %}{% block title %}Campaign {{ c.name }}{% endblock %}{% block body %}
<h1>{{ c.name }} <span class="muted sub">#{{ c.id }} · {{ c.status }}</span></h1>
<p><a href="/governance">← Governance</a> · {{ c.certified + c.revoked }} of {{ c.total }} decided
{% if c.due_at %}· due {{ c.due_at|ts }}{% endif %}
{% if c.status == 'open' and can('admin') %}<form class="inline" method="post" action="/governance/campaigns/{{ c.id }}/close">{{ csrf() }}
<button data-confirm="Close the campaign? Undecided items stay undecided.">close campaign</button></form>{% endif %}</p>
<div class="wrap"><table data-dt data-dt-page="50"><tr><th>Employee</th><th>Kind</th><th>Entitlement</th><th>Source</th><th>Decision</th></tr>
{% for i in items %}<tr><td><a href="/directory/user/view?name={{ i.employee_id|urlencode }}">{{ i.employee_id }}</a></td>
<td>{{ i.kind }}</td><td class="mono">{{ i.object_name }}</td><td class="muted">{{ i.source }}</td>
<td>{% if i.decision %}<span class="{{ 'ok' if i.decision == 'certify' else 'warn' }}">{{ i.decision }}</span>
<div class="muted">{{ i.decided_by }} {{ i.decided_at|ts }}{% if i.request_id %} · request {{ i.request_id }}{% endif %}</div>{% if i.note %}<div>{{ i.note }}</div>{% endif %}
{% elif c.status == 'open' and can('operator') %}<form class="row" method="post" action="/governance/items/{{ i.id }}/certify">{{ csrf() }}
<input name="note" placeholder="note (revoke: justification, 10+ characters)" maxlength="1000">
<input name="jira_ticket" placeholder="Jira ticket (revoke)" maxlength="20" pattern="[A-Za-z][A-Za-z0-9_]{1,9}-[1-9][0-9]{0,8}" title="Jira issue key, e.g. IAM-123">
<button class="primary">certify</button>
<button formaction="/governance/items/{{ i.id }}/revoke" class="danger" data-confirm="Revoke this access? A removal request is saved for approval.">revoke</button>
<select name="via"><option value="openiam">OpenIAM + AD</option><option value="ad">AD only</option></select></form>
{% else %}<span class="muted">not decided</span>{% endif %}</td></tr>
{% else %}<tr><td colspan="5" class="muted">No items.</td></tr>{% endfor %}</table></div>
{% endblock %}"""

P_PREVIEW = """{% extends "base.html" %}{% import "dir_macros.html" as m with context %}
{% block title %}{{ title }}{% endblock %}{% block body %}
<h1>{{ title }}</h1><p><a href="{{ back }}">← back</a></p>
{% for p, pl in plans %}<div class="card"><div>{{ m.summary(p) }}</div>
<h2>What will happen</h2><ol>{% for s in pl.steps %}<li>{{ s }}</li>{% endfor %}</ol>
{% for w in pl.warnings %}<div class="warn">{{ w }}</div>{% endfor %}
{% if pl.instructions %}<details><summary class="muted">AD instructions (as sent to the consumer site)</summary><pre>{{ pl.instructions|pretty }}</pre></details>{% endif %}
</div>{% endfor %}
{% if not mapping_known %}<p class="muted">The AD mapping comes from the sync config on the producer service; this preview uses the default mapping.</p>{% endif %}
<p>Needs <b>{{ approvals }}</b> approval(s) before it runs.</p>
{% if sod %}<div class="flash error">Segregation of duties would be broken: {{ sod|join('; ') }}. It cannot be saved.</div>
{% else %}<form method="post" action="{{ action }}">{{ csrf() }}{% for k, v in hidden %}<input type="hidden" name="{{ k }}" value="{{ v }}">{% endfor %}
<button class="primary">Save for approval</button></form>{% endif %}
{% endblock %}"""

P_BATCH_PREVIEW = """{% extends "base.html" %}{% block title %}{{ label }}{% endblock %}{% block body %}
<h1>{{ label }}: preview</h1>
<p>{{ rows|length }} change(s) · needs <b>{{ approvals }}</b> approval(s) · nothing is saved until you press the button.</p>
<div class="wrap"><table data-dt data-dt-page="50"><tr><th>Row</th><th>Change</th><th>What will happen</th><th>Problem</th></tr>
{% for i, p, pl, err in rows %}<tr><td>{{ i }}</td>
<td>{{ p.op }} {{ p.kind }} <span class="mono">{{ p.name }}</span>{% if p.member %} · {{ p.member_kind }} <span class="mono">{{ p.member }}</span>{% endif %}
{% if p.expires_on %} · until {{ p.expires_on }}{% endif %}<span class="chip">{{ 'OpenIAM + AD' if p.via == 'openiam' else 'AD only' }}</span></td>
<td>{% if pl %}{% for s in pl.steps %}<div class="small">{{ s }}</div>{% endfor %}{% endif %}</td>
<td class="bad">{{ err or '' }}</td></tr>{% endfor %}</table></div>
{% if sod %}<div class="flash error mt">Segregation of duties would be broken: {{ sod|join('; ') }}.</div>{% endif %}
{% if ok and not sod %}<form method="post" action="{{ action }}" class="mt">{{ csrf() }}{% for k, v in hidden %}<input type="hidden" name="{{ k }}" value="{{ v }}">{% endfor %}
<button class="primary">Save {{ rows|length }} change(s) for approval</button></form>
{% else %}<p class="bad">Fix the problems above, then upload again.</p>{% endif %}
{% endblock %}"""

P_IMPORT = """{% extends "base.html" %}{% import "dir_macros.html" as m with context %}
{% block title %}Bulk import{% endblock %}{% block body %}
<h1>Bulk import</h1><p><a href="/directory">← Directory</a></p>
<p class="muted">Upload a CSV (UTF-8, first line = header). Every row is checked and previewed; the whole file is
then saved as <b>one request</b> that needs approval (two approvers when it is large or removes anything).</p>
<form method="post" action="/directory/import" enctype="multipart/form-data">{{ csrf() }}
<div class="grid"><label>Format<select name="format">{% for f in formats %}<option>{{ f }}</option>{% endfor %}</select></label>
<label>CSV file<input type="file" name="file" accept=".csv,text/csv"></label>
<label>Write to{{ m.via() }}</label>{{ m.justify_grid() }}</div>
<details><summary class="muted">or paste CSV</summary><textarea name="csv" rows="8" cols="100" maxlength="900000"></textarea></details>
<p><button class="primary">Check and preview</button></p></form>
<h2>Columns</h2><div class="wrap"><table>{% for f, cols in formats.items() %}<tr><td><b>{{ f }}</b></td><td class="mono">{{ cols|join(',') }}</td></tr>{% endfor %}</table></div>
<p class="muted">groups / roles / organizations: several names separated by ";". membership: op is add or remove; member_kind user (employee id) or group (nesting); expires_on YYYY-MM-DD (optional, add only).</p>
{% endblock %}"""

P_MOVE = """{% extends "base.html" %}{% import "dir_macros.html" as m with context %}
{% block title %}Move {{ name }}{% endblock %}{% block body %}
<h1>Mover: <span class="mono">{{ name }}</span></h1>
<p><a href="/directory/user/view?name={{ name|urlencode }}">← user</a>{% if rec %} · {{ rec.firstName }} {{ rec.lastName }}{% if rec.title %} · {{ rec.title }}{% endif %}{% endif %}</p>
<p class="muted">Department / branch change: pick what to remove, add the new access, preview, then save it all as one request.</p>
<form method="post" action="/directory/user/move">{{ csrf() }}<input type="hidden" name="name" value="{{ name }}">
<h2>Remove current access</h2>
<div class="wrap"><table><tr><th>Remove</th><th>Kind</th><th>Name</th></tr>
{% for kind, obj in current %}<tr><td><input type="checkbox" name="remove" value="{{ kind }}:{{ obj }}"></td><td>{{ kind }}</td><td class="mono">{{ obj }}</td></tr>
{% else %}<tr><td colspan="3" class="muted">No access known here.</td></tr>{% endfor %}</table></div>
<h2>New position</h2><div class="grid">
<label>New title<input name="title" placeholder="{{ rec.title if rec and rec.title else '' }}" maxlength="256"></label>
<label>Domain<input name="domain" list="domains" value="{{ domain }}" maxlength="256"></label>
<label>Add groups (comma)<input name="add_groups" maxlength="2000"></label>
<label>Add roles (comma)<input name="add_roles" maxlength="2000"></label>
<label>Add organizations / OUs (comma)<input name="add_organizations" maxlength="2000"></label>
<label>Write to{{ m.via() }}</label>{{ m.justify_grid() }}</div>
{{ m.domains_list(domains) }}
<button class="primary">Preview</button></form>
{% endblock %}"""

P_INSIGHTS = """{% extends "base.html" %}{% block title %}Insights{% endblock %}{% block body %}
<h1>Insights</h1>
<p class="muted">Read-only analysis. Nothing changes here: act on a finding with a normal (approved) request.</p>
<form class="f" method="get"><label class="muted">role candidates shared by at least
<input name="min_users" type="number" min="2" max="50" value="{{ min_users }}"> people</label>
<label class="muted">peers =<select name="peer"><option {{ 'selected' if peer == 'title' }}>title</option><option {{ 'selected' if peer == 'domain' }}>domain</option></select></label>
<button>Apply</button></form>
{{ save_search_form() }}
<h2>Role mining: candidate roles</h2>
<p class="muted">Groups / roles many people hold together. Bundling them as one role makes granting and reviewing simpler.</p>
<div class="wrap"><table data-dt data-dt-page="10"><tr><th>People</th><th>Size</th><th>Held together</th></tr>
{% for c in candidates %}<tr><td>{{ c.users }}</td><td>{{ c.size }}</td><td>{% for e in c.entitlements %}<span class="chip">{{ e }}</span>{% endfor %}</td></tr>
{% else %}<tr><td colspan="3" class="muted">No combination is shared by {{ min_users }}+ people yet.</td></tr>{% endfor %}</table></div>
<h2>Unusual access (peer outliers)</h2>
<p class="muted">Access that at most 20% of a person's peers (same {{ peer }}, 4+ people) have.</p>
<div class="wrap"><table data-dt data-dt-page="10"><tr><th>Employee</th><th>Peers</th><th>Access</th><th>Peers with it</th></tr>
{% for o in outliers %}<tr><td><a href="/directory/user/view?name={{ o.employee_id|urlencode }}">{{ o.employee_id }}</a></td><td>{{ o.peer_group }}</td>
<td>{{ o.kind }} <span class="mono">{{ o.name }}</span></td><td>{{ o.peers_with_it }} of {{ o.peers }}</td></tr>
{% else %}<tr><td colspan="4" class="ok">Nothing unusual.</td></tr>{% endfor %}</table></div>
<h2>Orphan accounts</h2>
<p class="muted">OpenIAM users with no HR record here (meaningful once HR events flow through the producer).</p>
<div class="wrap"><table data-dt data-dt-page="10"><tr><th>Employee id</th><th>Login</th><th>Name</th><th>Status</th><th>Why</th></tr>
{% for o in orphans %}<tr><td>{{ o.employee_id or '' }}</td><td class="mono">{{ o.login or '' }}</td><td>{{ o.name }}</td><td>{{ o.status or '' }}</td><td class="warn">{{ o.reason }}</td></tr>
{% else %}<tr><td colspan="5" class="ok">None.</td></tr>{% endfor %}</table></div>
<h2>Dormant accounts (90 days)</h2>
<div class="wrap"><table data-dt data-dt-page="10"><tr><th>Employee id</th><th>Login</th><th>Name</th><th>Last sign-in</th><th>Days</th></tr>
{% for d in dormant %}<tr><td>{{ d.employee_id or '' }}</td><td class="mono">{{ d.login or '' }}</td><td>{{ d.name }}</td><td>{{ d.last_login or 'never / unknown' }}</td><td>{{ d.days if d.days is not none else '' }}</td></tr>
{% else %}<tr><td colspan="5" class="ok">None.</td></tr>{% endfor %}</table></div>
{% endblock %}"""

P_TREE = """{% extends "base.html" %}{% block title %}Organization tree{% endblock %}{% block body %}
{% macro node(o) %}<li><details open><summary><a href="/directory/organization/view?name={{ o.name|urlencode }}">{{ o.name }}</a>
{% set t = o.organizationTypeName or o.organizationTypeId or o.organizationType %}{% if t %}<span class="chip">{{ t }}</span>{% endif %}
{% if o.children %}<span class="muted small">{{ o.children|length }}</span>{% endif %}</summary>
{% if o.children %}<ul>{% for c in o.children %}{{ node(c) }}{% endfor %}</ul>{% endif %}</details></li>{% endmacro %}
<h1>Organization tree</h1><p><a href="/directory?kind=organization">← Organizations</a></p>
<p class="muted">From the OpenIAM snapshot, nested by each organization's parent (when OpenIAM reports one).</p>
<div class="tree card">{% if roots %}<ul>{% for o in roots %}{{ node(o) }}{% endfor %}</ul>{% else %}<p class="muted">No organizations yet: run change detection.</p>{% endif %}</div>
{% endblock %}"""

P_REQUEST_ACCESS = """{% extends "base.html" %}{% import "dir_macros.html" as m with context %}
{% block title %}Request access{% endblock %}{% block body %}
<h1>Request access</h1>
<p class="muted">Ask for a group or role (or give one back). It needs a Jira ticket and a justification, is checked
against segregation of duties, and is applied only after an approver agrees.</p>
<form method="post" action="/request-access">{{ csrf() }}<div class="grid">
<label>For employee{% if others %}<input name="member" value="{{ own or '' }}" required maxlength="256" placeholder="employee id">
{% else %}<input value="{{ own or 'not linked: ask an admin' }}" disabled>{% endif %}</label>
<label>Request<select name="op"><option value="add">access to</option><option value="remove">removal from</option></select></label>
<label>Kind<select name="kind"><option>group</option><option>role</option></select></label>
<label>Name *<input name="name" list="names" required maxlength="256"></label>
<label>Until (optional)<input name="expires_on" type="date"></label>
{{ m.justify_grid() }}</div>
<datalist id="names">{% for n in names %}<option value="{{ n }}">{% endfor %}</datalist>
<button class="primary">Send request</button></form>
{% endblock %}"""

P_RECEIPTS = """{% extends "base.html" %}{% block title %}AD receipts{% endblock %}{% block body %}
<h1>AD receipts</h1>
<p class="muted">Signed reports from the consumer sites: what happened to each AD instruction (applied, unchanged,
failed, waiting for approval, rejected...). The producer service imports them from the share every 5 minutes.</p>
<h2>Sites</h2>
<div class="wrap"><table><tr><th>Site</th><th>Trusted key</th><th>Last receipt</th></tr>
{% for site in (trusted + last.keys()|list)|unique|sort %}<tr><td>{{ site }}</td><td>{{ 'yes' if site in trusted else '' }}</td>
<td class="{{ 'warn' if site not in last or now - last[site] > 86400 }}">{{ last[site]|ts if site in last else 'never' }}</td></tr>
{% else %}<tr><td colspan="3" class="muted">No sites configured (sync.yaml <span class="mono">receipts:</span>) and no receipts yet.</td></tr>{% endfor %}</table></div>
<h2>Recent receipts</h2>
<div class="wrap"><table data-dt data-dt-page="25"><tr><th>Received</th><th>Site</th><th>Zip</th><th>Domain</th><th>Status</th><th>Instructions</th><th>Signed</th></tr>
{% for r in rows %}{% set items = r.payload.instructions or [] %}<tr><td>{{ r.received_at|ts }}</td><td>{{ r.site }}</td><td class="mono small">{{ r.zip_name or '' }}</td><td>{{ r.domain or '' }}</td>
<td class="{{ 'bad' if r.status in ('failed','rejected','partial') else ('ok' if r.status == 'applied' else 'warn') }}">{{ r.status }}</td>
<td>{{ items|length }}{% set bad = items|selectattr('status', 'equalto', 'failed')|list %}{% if bad %} · <span class="bad">{{ bad|length }} failed</span>{% endif %}
<details><summary class="muted">detail</summary><pre>{{ items|pretty }}</pre></details></td>
<td class="{{ 'ok' if r.signed_by else 'warn' }}">{{ 'by ' ~ r.signed_by if r.signed_by else 'unsigned' }}</td></tr>
{% else %}<tr><td colspan="7" class="muted">No receipts yet.</td></tr>{% endfor %}</table></div>
{% endblock %}"""

P_NOTIFICATIONS = """{% extends "base.html" %}{% block title %}Notifications{% endblock %}{% block body %}
<h1>Notifications</h1>
<p class="muted">Events queued for email and webhooks. This site's service (iam serve / iam consumer watch) delivers them using
<span class="mono">notify.yaml</span> (this UI holds no SMTP passwords or webhook secrets).</p>
<div class="wrap"><table data-dt data-dt-page="25"><tr><th>#</th><th>When</th><th>Event</th><th>Title</th><th>Status</th></tr>
{% for n in rows %}<tr><td>{{ n.id }}</td><td>{{ n.at|ts }}</td><td class="mono">{{ n.event }}</td>
<td>{{ n.title }}<details><summary class="muted">text</summary><pre>{{ n.text }}</pre></details></td>
<td class="{{ 'ok' if n.status == 'sent' else ('bad' if n.status == 'dead' else 'warn') }}">{{ n.status }}
{% if n.attempts %}<div class="muted">{{ n.attempts }} attempt(s)</div>{% endif %}{% if n.last_error %}<div class="bad small">{{ n.last_error }}</div>{% endif %}</td></tr>
{% else %}<tr><td colspan="5" class="muted">Nothing yet.</td></tr>{% endfor %}</table></div>
<h2>Events</h2><div class="wrap"><table>{% for e, d in events.items() %}<tr><td class="mono">{{ e }}</td><td>{{ d }}</td></tr>{% endfor %}</table></div>
{% endblock %}"""

P_REPORTS = """{% extends "base.html" %}{% block title %}Reports{% endblock %}{% block body %}
<h1>Reports</h1>
<p class="muted">CSV downloads, generated now from this site's database. Every download is recorded in the
audit trail. Cells that a spreadsheet would run as a formula are written as text.</p>
<div class="wrap"><table><tr><th>Report</th><th></th></tr>
{% for name, label in reports.items() %}<tr><td>{{ label }}</td><td><a href="/reports/{{ name }}.csv">download CSV</a></td></tr>{% endfor %}
</table></div>
<h2>Scheduled</h2>
<p class="muted">The producer service writes these into <span class="mono">{{ folder }}</span> and sends a <span class="mono">report.scheduled</span> notification.</p>
<div class="wrap"><table><tr><th>Report</th><th>Every</th><th>Last written</th><th></th></tr>
{% for s in schedules %}<tr><td>{{ reports[s.report] }}</td><td>{{ s.every }}</td><td>{{ s.last_run_at|ts }}{% if s.last_file %}<div class="mono small">{{ s.last_file }}</div>{% endif %}</td>
<td>{% if can('admin') %}<form class="inline" method="post" action="/reports/schedules/{{ s.id }}/{{ 'disable' if s.enabled else 'enable' }}">{{ csrf() }}<button>{{ 'disable' if s.enabled else 'enable' }}</button></form>{% endif %}</td></tr>
{% else %}<tr><td colspan="4" class="muted">None.</td></tr>{% endfor %}</table></div>
{% if can('admin') %}<form method="post" action="/reports/schedules" class="row mt">{{ csrf() }}
<select name="report">{% for name, label in reports.items() %}<option value="{{ name }}">{{ label }}</option>{% endfor %}</select>
<select name="every">{% for e in every %}<option>{{ e }}</option>{% endfor %}</select><button class="primary">Schedule</button></form>{% endif %}
{% endblock %}"""

TEMPLATES = {
    "dir_macros.html": DIR_MACROS, "p_directory.html": P_DIRECTORY, "p_dir_new.html": P_DIR_NEW,
    "p_dir_object.html": P_DIR_OBJECT, "p_approvals.html": P_APPROVALS,
    "p_governance.html": P_GOVERNANCE, "p_campaign.html": P_CAMPAIGN, "p_reports.html": P_REPORTS,
    "p_notifications.html": P_NOTIFICATIONS, "p_insights.html": P_INSIGHTS, "p_tree.html": P_TREE,
    "p_request_access.html": P_REQUEST_ACCESS, "p_receipts.html": P_RECEIPTS, "p_preview.html": P_PREVIEW,
    "p_batch_preview.html": P_BATCH_PREVIEW, "p_import.html": P_IMPORT, "p_move.html": P_MOVE,
    "base.html": BASE, "save_search.html": SAVE_SEARCH, "login.html": LOGIN, "account.html": ACCOUNT, "login_mfa.html": LOGIN_MFA,
    "account_mfa.html": ACCOUNT_MFA, "account_mfa_codes.html": ACCOUNT_MFA_CODES,
    "admin_users.html": ADMIN_USERS, "admin_audit.html": ADMIN_AUDIT, "requests.html": REQUESTS,
    "p_dashboard.html": P_DASHBOARD, "p_activity.html": P_ACTIVITY,
    "p_activity_detail.html": P_ACTIVITY_DETAIL, "p_outbox.html": P_OUTBOX,
    "p_outbox_detail.html": P_OUTBOX_DETAIL, "p_runs.html": P_RUNS, "p_apikeys.html": P_APIKEYS,
    "c_dashboard.html": C_DASHBOARD, "c_files.html": C_FILES, "c_file.html": C_FILE,
    "c_actions.html": C_ACTIONS, "c_drift.html": C_DRIFT, "c_drift_detail.html": C_DRIFT_DETAIL,
    "c_plans.html": C_PLANS, "c_plan.html": C_PLAN, "c_alerts.html": C_ALERTS,
}
