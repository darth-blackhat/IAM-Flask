import asyncio
from contextlib import asynccontextmanager
from typing import Any

from ..db import LockTimeout
from ..logs import logger
from ..openiam import OpenIAMClient
from .config import SyncConfig
from .engine import SyncError, run_sync
from .export import Source, export_domains
from .store import Store
from .targets import Target

class SyncBusy(SyncError):
    pass


class SyncService:
    """Runs detect-then-deliver cycles, one at a time."""

    def __init__(self, client: OpenIAMClient, store: Store, cfg: SyncConfig,
                 target: Target | None):
        self.client, self.store, self.cfg, self.target = client, store, cfg, target
        # Set when the producer runs on this site: (user_id, since) -> what it changed.
        self.attributor = None
        # Called once per loop iteration (daily retention purge).
        self.housekeeping = None

    @asynccontextmanager
    async def _exclusive(self):
        """One sync cycle at a time across every backend instance sharing the database."""
        try:
            async with self.store.db.lock("sync", timeout=0):
                yield
        except LockTimeout:
            raise SyncBusy("another sync run or delivery is in progress") from None

    async def run(self, *, baseline: bool = False, allow_mass_delete: bool = False,
                  deliver: bool = True) -> dict[str, Any]:
        async with self._exclusive():
            result = await run_sync(self.client, self.store, self.cfg, baseline=baseline,
                                    allow_mass_delete=allow_mass_delete, attributor=self.attributor)
            if deliver:
                result["delivery"] = await self._deliver()
            if self.cfg.export and self.cfg.export.after_sync:
                # The new state is already committed; an export problem must not fail the run.
                try:
                    result["export"] = await export_domains(self.client, self.store, self.cfg,
                                                            run_id=result["run_id"])
                except Exception as e:
                    logger.exception("export after sync run {} failed", result["run_id"])
                    result["export"] = {"error": str(e)}
        return result

    async def export(self, *, source: Source = "live", force: bool = False) -> dict[str, Any]:
        """One zip per changed (or new) domain into export.folder."""
        if self.cfg.export is None:
            raise SyncError("no `export` section in the sync config")
        async with self._exclusive():
            return await export_domains(self.client, self.store, self.cfg, source=source,
                                        force=force)

    async def deliver(self) -> dict[str, Any]:
        async with self._exclusive():
            return await self._deliver()

    async def _deliver(self) -> dict[str, Any]:
        """Send pending events in order; stop at the first failure (it is retried with backoff)."""
        if self.cfg.target.type == "zip":
            return {"mode": "zip", "sent": 0}  # written into the per-domain zips by the export
        if self.target is None:
            return {"mode": "pull", "sent": 0}
        sent = 0
        while batch := self.store.pending(self.cfg.batch_size):
            seqs = [e.pop("seq") for e in batch]
            try:
                await self.target.send(batch)
            except Exception as e:
                self.store.mark_failed(seqs, f"{type(e).__name__}: {e}", self.cfg.max_attempts)
                logger.bind(sent=sent).warning("delivery to target failed after {} events: {}", sent, e)
                return {"sent": sent, "error": str(e)}
            self.store.mark_delivered(seqs)
            sent += len(seqs)
            logger.debug("delivered {} events (seq {}..{})", len(seqs), seqs[0], seqs[-1])
        return {"sent": sent}

    async def loop(self) -> None:
        while True:
            try:
                result = await self.run()
                logger.bind(run_id=result["run_id"], entities=result["entities"],
                            delivery=result.get("delivery")).info(
                    "sync run {} done: {}", result["run_id"], result["entities"])
            except asyncio.CancelledError:
                raise
            except SyncBusy:
                logger.info("sync skipped: another instance is running it")
            except Exception:
                logger.exception("sync run failed")
                # Still retry events from earlier runs.
                try:
                    await self.deliver()
                except Exception:
                    logger.exception("delivery failed")
            if self.housekeeping:
                self.housekeeping()
            await asyncio.sleep(self.cfg.interval_seconds)

    def operator_handlers(self) -> dict:
        """What the web's operator buttons can ask this service to do."""
        async def sync_run(_: dict) -> dict:
            return await self.run()

        async def sync_run_allow(_: dict) -> dict:
            return await self.run(allow_mass_delete=True)

        async def export(_: dict) -> dict:
            return await self.export(source="snapshot")

        async def export_force(_: dict) -> dict:
            return await self.export(source="snapshot", force=True)

        async def deliver(_: dict) -> dict:
            return await self.deliver()
        return {"sync_run": sync_run, "sync_run_allow_mass_delete": sync_run_allow,
                "export": export, "export_force": export_force, "deliver": deliver}

    async def aclose(self) -> None:
        if self.target is not None:
            await self.target.aclose()
