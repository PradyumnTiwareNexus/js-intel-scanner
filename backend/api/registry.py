"""
In-memory scan registry. Each scan gets:
  - a unique scan_id
  - an asyncio.Queue that the orchestrator's on_event pushes into
  - a set of connected websockets that get broadcast the same events
  - a status dict (running/done/error) + final summary once complete

This is intentionally in-memory (single-process) for Phase 2. Swapping to
Redis pub/sub later is a drop-in replacement behind the same interface.
"""
import uuid
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ScanJob:
    scan_id: str
    domain: str
    status: str = "queued"          # queued -> running -> done | error | cancelled
    summary: Optional[dict] = None
    error: Optional[str] = None
    subscribers: set = field(default_factory=set)
    history: list = field(default_factory=list)   # replay buffer for late-joining clients
    cancel_requested: bool = False
    task: Optional[object] = None   # asyncio.Task handle, set once scan starts


class ScanRegistry:
    def __init__(self):
        self._jobs: dict[str, ScanJob] = {}

    def create(self, domain: str) -> ScanJob:
        scan_id = uuid.uuid4().hex[:12]
        job = ScanJob(scan_id=scan_id, domain=domain)
        self._jobs[scan_id] = job
        return job

    def get(self, scan_id: str) -> Optional[ScanJob]:
        return self._jobs.get(scan_id)

    def all(self) -> list[ScanJob]:
        return list(self._jobs.values())

    async def broadcast(self, job: ScanJob, event: dict):
        job.history.append(event)
        if len(job.history) > 500:
            job.history = job.history[-500:]
        dead = []
        for ws in job.subscribers:
            try:
                await ws.send_json(event)
            except Exception:
                dead.append(ws)
        for ws in dead:
            job.subscribers.discard(ws)


registry = ScanRegistry()
