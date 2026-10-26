"""
/ws/jobs/{job_id} — live log streaming for a single job, per
11-FRONTEND-IMPLEMENTATION.md. Subscribes to the job runner's in-memory
broadcast (07-DATA-MODEL-AND-MEMORY.md §5: active-job state lives in
memory only while the job is running; everything durable is already in
the DB by the time this socket closes).
"""
import asyncio

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from . import jobs as job_runner

router = APIRouter()


@router.websocket("/ws/jobs/{job_id}")
async def job_log_stream(websocket: WebSocket, job_id: int):
    await websocket.accept()
    loop = asyncio.get_event_loop()
    queue: asyncio.Queue = asyncio.Queue()

    def on_line(line: str) -> None:
        loop.call_soon_threadsafe(queue.put_nowait, line)

    job_runner.subscribe(job_id, on_line)
    try:
        while True:
            line = await queue.get()
            await websocket.send_text(line)
    except WebSocketDisconnect:
        pass
