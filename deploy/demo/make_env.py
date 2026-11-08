"""Write deploy/demo/.env (gitignored) with a random admin password and session keys."""

import secrets
from pathlib import Path

env = Path(__file__).with_name(".env")
if env.exists():
    print(f"{env} exists; delete it to make new secrets")
else:
    password = secrets.token_urlsafe(12)
    env.write_text(f"DEMO_ADMIN_PASSWORD={password}\n"
                   f"DEMO_PRODUCER_SECRET={secrets.token_urlsafe(32)}\n"
                   f"DEMO_CONSUMER_SECRET={secrets.token_urlsafe(32)}\n", encoding="utf-8")
    print(f"wrote {env}\nsign in to both UIs as admin / {password}")
