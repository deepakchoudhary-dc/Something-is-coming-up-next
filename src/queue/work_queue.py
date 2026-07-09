"""
In-process async work queue for the AI Security Gateway.

Provides background job processing for HITL reviews, notifications,
and maintenance tasks without requiring an external broker like Celery/Redis.

For multi-node production deployments, swap to a broker-backed
implementation by subclassing ``WorkQueue``.
"""

import asyncio
import logging
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Coroutine, Dict, List, Optional

logger = logging.getLogger(__name__)


class JobStatus(str, Enum):
    queued = "queued"
    running = "running"
    completed = "completed"
    failed = "failed"
    dead_letter = "dead_letter"


@dataclass
class Job:
    id: str
    queue_name: str
    payload: Dict[str, Any]
    handler: str
    status: JobStatus = JobStatus.queued
    attempts: int = 0
    max_retries: int = 3
    created_at: float = field(default_factory=time.time)
    started_at: Optional[float] = None
    finished_at: Optional[float] = None
    error: Optional[str] = None


class WorkQueue:
    """Single-node async work queue backed by ``asyncio.Queue``."""

    def __init__(self, concurrency: int = 4, max_retries: int = 3):
        self._queues: Dict[str, asyncio.Queue] = {}
        self._handlers: Dict[str, Callable] = {}
        self._concurrency = concurrency
        self._max_retries = max_retries
        self._workers: List[asyncio.Task] = []
        self._jobs: Dict[str, Job] = {}
        self._running = False

    def register_handler(self, name: str, handler: Callable[..., Coroutine]) -> None:
        """Register a coroutine handler for a named job type."""
        self._handlers[name] = handler
        logger.info("Registered work-queue handler: %s", name)

    async def enqueue(self, queue_name: str, handler_name: str, payload: Dict[str, Any]) -> str:
        """Enqueue a job and return its ID."""
        if handler_name not in self._handlers:
            raise ValueError(f"No handler registered for {handler_name!r}")

        job_id = f"job_{uuid.uuid4().hex[:16]}"
        job = Job(
            id=job_id,
            queue_name=queue_name,
            payload=payload,
            handler=handler_name,
            max_retries=self._max_retries,
        )
        self._jobs[job_id] = job

        if queue_name not in self._queues:
            self._queues[queue_name] = asyncio.Queue()

        await self._queues[queue_name].put(job)
        logger.debug("Enqueued job %s on queue %s (handler=%s)", job_id, queue_name, handler_name)
        return job_id

    def get_job_status(self, job_id: str) -> Optional[Dict[str, Any]]:
        """Return current status of a job."""
        job = self._jobs.get(job_id)
        if not job:
            return None
        return {
            "id": job.id,
            "status": job.status.value,
            "queue": job.queue_name,
            "handler": job.handler,
            "attempts": job.attempts,
            "created_at": datetime.utcfromtimestamp(job.created_at).isoformat(),
            "error": job.error,
        }

    async def start(self) -> None:
        """Start background worker tasks."""
        if self._running:
            return
        self._running = True
        for queue_name in list(self._queues.keys()):
            for i in range(self._concurrency):
                task = asyncio.create_task(self._worker_loop(queue_name), name=f"wq-{queue_name}-{i}")
                self._workers.append(task)
        logger.info("Work queue started with %d workers per queue", self._concurrency)

    async def stop(self) -> None:
        """Gracefully stop all workers."""
        self._running = False
        for task in self._workers:
            task.cancel()
        await asyncio.gather(*self._workers, return_exceptions=True)
        self._workers.clear()
        logger.info("Work queue stopped")

    async def _worker_loop(self, queue_name: str) -> None:
        """Process jobs from a single queue."""
        queue = self._queues[queue_name]
        while self._running:
            try:
                job = await asyncio.wait_for(queue.get(), timeout=1.0)
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                break

            handler = self._handlers.get(job.handler)
            if not handler:
                job.status = JobStatus.dead_letter
                job.error = f"Handler {job.handler!r} not found"
                logger.error("Dead-letter job %s: handler not found", job.id)
                continue

            job.status = JobStatus.running
            job.started_at = time.time()
            job.attempts += 1

            try:
                await handler(job.payload)
                job.status = JobStatus.completed
                job.finished_at = time.time()
                logger.debug("Job %s completed in %.3fs", job.id, job.finished_at - job.started_at)
            except Exception as exc:
                job.error = str(exc)
                if job.attempts < job.max_retries:
                    job.status = JobStatus.queued
                    await queue.put(job)
                    logger.warning("Job %s failed (attempt %d/%d), re-queuing: %s",
                                   job.id, job.attempts, job.max_retries, exc)
                else:
                    job.status = JobStatus.dead_letter
                    job.finished_at = time.time()
                    logger.error("Job %s dead-lettered after %d attempts: %s",
                                 job.id, job.attempts, exc)

    async def ensure_queue_started(self, queue_name: str) -> None:
        """Lazily create a queue and start workers for it if not already running."""
        if queue_name not in self._queues:
            self._queues[queue_name] = asyncio.Queue()
        if self._running:
            # Check if workers exist for this queue
            existing = [t for t in self._workers if queue_name in (t.get_name() or "")]
            if not existing:
                for i in range(self._concurrency):
                    task = asyncio.create_task(self._worker_loop(queue_name), name=f"wq-{queue_name}-{i}")
                    self._workers.append(task)


# ── Module-level singleton ─────────────────────────────────────────────
_work_queue: Optional[WorkQueue] = None


def get_work_queue() -> WorkQueue:
    global _work_queue
    if _work_queue is None:
        _work_queue = WorkQueue()
    return _work_queue
