# backend-iam

backend-iam moves identity data between a source of truth (HR), OpenIAM and the sites that
consume it.

**Producer site** (with the main OpenIAM)
- Applies HR events (hire, terminate, leave, compliance and training) to OpenIAM.
- Detects changes made directly in OpenIAM, and explains each one (*why*, from the HR event
  or the OpenIAM audit log).
- Writes one signed, encrypted zip per domain. Each zip holds the data plus AD instructions.

**Consumer site**
- Picks the zips up the moment they arrive.
- Applies them to the site's own OpenIAM, or, for a site without OpenIAM, to Active
  Directory, with dry-run and approval.
- Alerts when AD is changed without it.

There are five services, each a systemd unit running a hardened Docker container, deployed by
Ansible. Everything builds and deploys with no internet access.

| Service | Command | Site | What it does |
|---|---|---|---|
| producer | `iam serve` | producer | REST API, producer intake, change detection, per-domain export |
| web | `iam web` | producer | Web UI: producer activity, AD instructions, sync runs, API keys |
| consumer | `iam consumer watch` | consumer | Inbox watchdog; applies zips to OpenIAM or AD; AD change alerts |
| oversight | `iam oversight` | consumer | Web UI: zips, actions, AD plans and approval, AD changes, drift |
| proxy | nginx | both | HTTPS in front of the services (optional mutual TLS for the API) |

## Diagrams

The diagrams are Mermaid source in [docs/](docs/), each with a rendered `.svg` next to it:

| Diagram | Shows |
|---|---|
| [data-flow](docs/data-flow.mmd) | Source of truth and OpenIAM admins → backend → zips → OpenIAM B or AD |
| [hire-sequence](docs/hire-sequence.mmd) | One hire, end to end |
| [deployment](docs/deployment.mmd) | Ansible, hosts, systemd units, containers, proxy |
| [database-er](docs/database-er.mmd) | Every table, as an ER diagram |
| [data-model-messages](docs/data-model-messages.mmd) | Events, AD instructions and their `why`, the contents of a zip |
| [data-model-config](docs/data-model-config.mmd) | The configuration models |
| [person-lifecycle](docs/person-lifecycle.mmd) | Hire, holds, leave and termination |
| [consumer-file-states](docs/consumer-file-states.mmd) | What happens to each zip on the consumer site |

To re-render:
`docker run --rm -v "$PWD/docs:/data" minlag/mermaid-cli:11.4.2 -i /data/<name>.mmd -o /data/<name>.svg`

---

## Producer site

### Producer intake (source of truth → OpenIAM)
`POST /producer/events` takes hire, update, terminate, leave, return and status events,
needing an API key with scope `producer:write`. Each event updates OpenIAM:
- **The user record:** matched by employee id.
- **Account state:** termination (which can be scheduled), leave, and holds from statuses
  such as `compliance=non_compliant`. Holds stack: the account stays disabled until every
  hold is cleared.
- **Groups, roles and organizations:** found by name, through `aliases`, and limited to
  AD-linked objects by `require`. Only what this backend granted is ever removed.

Events are idempotent by `event_id`, applied in order, and recorded in the activity log.
Configure it in [producer.example.yaml](producer.example.yaml).

### Change detection, with why
Every `interval_seconds`, the producer service pulls users, groups, organizations and roles
from OpenIAM and compares them with the last copy. Each difference becomes an event with AD
instructions (`create`, `update`, `enable`, `disable`, `add_member`, `remove_member`,
`delete`) and a `why`:
- **`source-of-truth`:** the change came from an HR event. It includes the event, its id, the
  reason and the statuses. Change detection doesn't send these changes again.
- **`openiam-admin`:** someone edited OpenIAM directly. It records the fields' old and new
  values, and, from the **OpenIAM audit log**, who made the change, the action and when.

**Safety checks**
- **All or nothing:** a run that partly fails records nothing.
- **Mass deletes need approval:** a mass delete is refused until an operator allows it.
- **Paging check:** search endpoints that ignore paging are detected.

### Per-domain zips
A zip is written for each domain whose data changed, and for each new domain:
`<folder>/<domain>/openiam-<domain>-<UTC>.zip[.age]`.
- **Data files:** per entity, as `jsonl` and `csv`. Only the fields in `export.fields` are
  kept (data minimization).
- **`ad_instructions.jsonl`:** what to do, why, and the record payload. Writing an
  instruction into its zip counts as delivering it (`target: {type: zip}`).
- **`manifest.json`:** counts, the SHA-256 of every file and `generated_at`.
- **`manifest.sig`:** an Ed25519 signature that covers every file through their hashes.
- **Encryption:** the whole zip can be encrypted with age (`.zip.age`) to each consumer
  site's recipient. The standard `age -d -i key.txt` tool can open it too.

Files are written atomically (as `.partial`, then renamed) and pruned per domain.

Other delivery targets remain available: `webhook` (HMAC-signed), `file`, or `none` (the
other side pulls `GET /sync/events`). Configure delivery in
[sync.example.yaml](sync.example.yaml).

## Consumer site

`CONSUMER_TARGET` picks where zips are applied:

| `CONSUMER_TARGET` | The site has | What happens |
|---|---|---|
| `openiam` | OpenIAM | Records are upserted (users matched by employee id). Instructions are then carried out in order: enable, disable, membership add or remove, delete → disable. |
| `ad` | no OpenIAM | The zip's AD instructions become a **plan** of exact LDAP changes, reconciled with AD (idempotent). It is applied according to `mode`: `dry_run`, `approve` (an operator approves it in the oversight UI) or `auto` (with a size limit). |

**For every zip**
- **Picked up on arrival:** a watchdog notices new zips; a timed scan is the fallback, and
  network shares use polling. A file is taken only once it has stopped changing.
- **Checked:** the signature, encryption and checksums are verified. A failed zip goes to
  `failed/`.
- **Never older:** a zip older than the last applied one for its domain is marked `stale`.
- **Archived:** the zip is moved to `archive/<domain>/` once handled.

**AD target guard rails**
- **Encrypted connection only:** LDAPS or StartTLS with a validated CA.
- **Stays in its area:** nothing outside `base_dn` is touched.
- **Protected groups are never changed:** Domain Admins, Enterprise Admins and the like.
- **Deletes become disables,** unless `allow_delete` is set.
- **New users are created disabled.** This tool never handles passwords.

**AD change alerts:** the watcher compares the managed OUs and the membership of protected
groups against what it last saw. The consumer's own writes update that state as they're
made, so they never alert; any other change does.
- `critical`: membership of a protected group changed.
- `warning`: an account was enabled or disabled, membership changed, or an object appeared
  or disappeared.
- `info`: any other attribute edit.

Operators acknowledge alerts in the oversight UI. LDAP can't say who made a change; the
domain controllers' security event log can.

**Drift reports:** compare the target with the last zip applied for a domain. This is
read-only.

Configure the consumer in [consumer.example.yaml](consumer.example.yaml).

---

## Security

| Area | Measures |
|---|---|
| Zips | Ed25519 signature (`require_signature`), age encryption (`require_encryption`), SHA-256 per file, stale and duplicate detection, field allowlist |
| API | Named API keys (only a SHA-256 is stored, the key is shown once), scopes per key, CIDR allowlist per key and globally, expiry and revocation, per-key rate limit, body size limit, `X-Forwarded-For` believed only from trusted proxies, audit of every write and refusal |
| Web UIs | Named users with roles (`viewer` < `operator` < `admin`), scrypt hashes, lockout plus per-IP throttling, signed `HttpOnly` / `Secure` / `SameSite=Strict` cookies with idle and absolute timeouts, CSRF token and origin check on every POST, strict Content-Security-Policy with no JavaScript, audit of logins, views and actions. The UIs hold no OpenIAM or AD credentials: buttons queue requests that the services run. |
| Transport | nginx with TLS 1.2 and 1.3 only, HSTS, a login rate limit, `X-Forwarded-For` overwritten with the real client, and optional mutual TLS for the API. Services listen on 127.0.0.1 only. |
| Containers | Read-only root filesystem, every capability dropped, `no-new-privileges`, non-root user (uid 10001), PID limit, secrets in 0600 env files |
| Data | Data minimization (`export.fields`), e-mail and phone redaction in logs, retention purge |
| AD | See the AD target guard rails above, plus alerts on changes made without the consumer |

Keys: `iam keys signing PREFIX` creates the producer's signing key pair, and
`iam keys age FILE` creates a consumer site's identity and prints its recipient.

## Operations

- **Monitoring:**
  - `GET /metrics` on the producer API, with scope `metrics:read`.
  - `127.0.0.1:9102/metrics` on the consumer.
  - Alert rules are in [deploy/prometheus/alerts.yml](deploy/prometheus/alerts.yml): stale
    or failing sync, blocked mass deletes, dead instructions, rejected or partial zips,
    domains not updated, AD plans waiting, drift, AD changed outside the consumer, a changed
    protected group, authentication failures and locked users.
- **Database:** PostgreSQL in production (`DATABASE_URL`, a `backend_iam` schema; SQLite for
  development).
  - **Migrations:** Alembic migrations run at every start. `iam maintenance migrate` runs
    them by hand.
  - **Locks:** advisory locks let several instances share the database.
- **Retention:** the `RETENTION_*_DAYS` settings. The purge runs daily inside the services;
  run it by hand with `iam maintenance purge [--dry-run]`. Pending and dead events and the
  current state are never purged.
- **Logs:** loguru to journald (`journalctl -u backend-iam-<service>`). Set `LOG_JSON=true`
  for log shippers.

## Deploy (Ansible + Docker + systemd)

```bash
cd deploy/ansible
cp -r inventories/example inventories/prod   # hosts.ini, host_vars, files/<host>/<service>/
cp inventories/prod/group_vars/all/vault.example.yml inventories/prod/group_vars/all/vault.yml
ansible-vault encrypt inventories/prod/group_vars/all/vault.yml
ansible-playbook -i inventories/prod/hosts.ini site.yml -K --ask-vault-pass
```

**Choosing services:** a host gets the services of the groups it's in (`producer`, `web`,
`consumer`, `oversight`, `proxy`).

**Config files:** `files/<host>/<service>/` is copied to `/etc/backend-iam/<service>/` and
mounted read-only at `/config`. It holds the YAML configs, the keys and the AD CA
certificate. `files/<host>/proxy/tls/` holds `cert.pem` and `key.pem`, plus `client-ca.pem`
for mutual TLS.

**Tested:** a Debian 12 host with **no network** got all five services installed, started and
health-checked. A second run changed nothing.

**WSL with Docker Desktop:** use [inventories/wsl](deploy/ansible/inventories/wsl/). It needs
`systemd=true` in `/etc/wsl.conf`, and Docker Desktop's WSL integration turned on for Ubuntu.

## No internet

1. **Fetch:** on a machine with internet and Docker, run `deploy/offline/download.sh`.
   - `--debs ubuntu:24.04` fetches Docker packages for the servers' distribution.
   - `--optional` adds the test and diagram images.
   - To fetch by hand, every file is listed with its URL and SHA-256 in
     [deploy/offline/DOWNLOAD-LIST.md](deploy/offline/DOWNLOAD-LIST.md).
2. **Carry:** bring the repository (with `vendor/wheels/`) and `offline-bundle/` across.
3. **Deploy as above.** The image builds with `--network=none` from hash-locked wheels, and
   the base and proxy images load from tarballs.

**To change dependencies:** edit `requirements*.txt`, then run
`docker run --rm -v "$PWD:/src" -w /src python:3.14.7-slim-trixie python deploy/offline/make_lock.py`
and `download.sh` again.

## CLI

```text
iam serve | web | oversight                     run the API / producer UI / consumer UI
iam producer apply FILE.json | person ID        producer events by hand
iam sync run [--baseline] [--allow-mass-delete] | watch | export [--force] | deliver | status
iam consumer scan | watch
iam apikey create NAME --scope S [--cidr C] [--expires-days N] | list | revoke NAME | scopes
iam webuser add NAME --role R | passwd | role | disable | enable | unlock | list
iam keys signing PREFIX | age FILE
iam maintenance migrate | purge [--dry-run]
iam ping | search | export | raw | api-docs | import    OpenIAM tools
```

## Tests

```bash
.venv/Scripts/python -m pytest                       # SQLite
TEST_DATABASE_URL=postgresql+psycopg://user:pass@localhost:5432/test .venv/Scripts/python -m pytest
```

The tests use in-memory fake OpenIAMs and an in-memory LDAP server (ldap3 `MOCK_SYNC` with
an AD schema). They cover both sites end to end: signatures, encryption, tampering, the
watchdog, AD plans, approvals, protected groups, change alerts, the web security (CSRF,
roles, lockout, sessions), API keys and migrations.

## Verify against your OpenIAM first

The OpenIAM docs confirm the token endpoint, user search, `/prov/*` and the audit-log root.
Every other path and field name is a config value, marked "verify in api-docs" in the
examples:
- **Search paths:** for groups, organizations and roles.
- **Group creation:** the endpoint that creates groups.
- **Domain field:** the field that says which domain a record belongs to.
- **Audit log:** its search criteria and field names.

Check each with `iam api-docs` and `iam raw` before going live.
