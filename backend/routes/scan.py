"""Scan endpoint with SSE streaming."""

import asyncio
import json
import time
from fastapi import APIRouter, Query, HTTPException
from fastapi.responses import StreamingResponse

from routes.verify import validate_scan_token
from security import scan_limiter
from osint import ScanOrchestrator
from config import settings

router = APIRouter(tags=["Scan"])


@router.get("/scan")
async def scan(
    token: str = Query(..., min_length=32, max_length=64),
    depth: int = Query(default=1, ge=1, le=3),
):
    """
    Execute OSINT scan and stream results via SSE.

    Events:
    - finding: A new finding discovered
    - log: Audit log entry
    - progress: Scan progress update
    - complete: Scan finished
    - error: Error occurred
    """
    # Validate token
    valid, result = validate_scan_token(token)
    if not valid:
        raise HTTPException(status_code=401, detail={"success": False, "error": result})

    email = result  # Token validation returns email on success

    # Check scan rate limit (1 per email per 24h)
    allowed, retry_after = scan_limiter.is_allowed(
        key=email,
        max_requests=1,
        window_seconds=settings.RATE_LIMIT_SCAN_COOLDOWN_HOURS * 3600,
    )

    if not allowed:
        raise HTTPException(
            status_code=429,
            detail={
                "success": False,
                "error": "Rate limited. One scan per email per 24 hours.",
                "retry_after": retry_after,
            }
        )

    # Stream results via SSE
    async def event_stream():
        orchestrator = ScanOrchestrator()
        finding_count = 0
        start_time = time.time()

        def send_event(event_type: str, data: dict) -> str:
            """Format SSE event."""
            json_data = json.dumps(data, default=str)
            return f"event: {event_type}\ndata: {json_data}\n\n"

        try:
            # Send start event
            yield send_event("start", {
                "type": "start",
                "depth": depth,
                "timestamp": time.time(),
            })

            # Run scan
            async for finding in orchestrator.run(email, depth):
                finding_count += 1

                # Send finding event
                yield send_event("finding", {
                    "type": "finding",
                    "finding": finding.model_dump(),
                })

                # Send progress event
                if depth == 1:
                    expected = 10
                elif depth == 2:
                    expected = 25
                else:
                    expected = 40
                progress = min(95, int((finding_count / expected) * 100))

                yield send_event("progress", {
                    "type": "progress",
                    "progress": progress,
                    "finding_count": finding_count,
                    "elapsed": round(time.time() - start_time, 1),
                })

                # Small delay to prevent overwhelming client
                await asyncio.sleep(0.05)

            # Send completion event
            results = orchestrator.get_results()
            yield send_event("complete", {
                "type": "complete",
                "results": results,
            })

        except asyncio.TimeoutError:
            yield send_event("error", {
                "type": "error",
                "error": "Scan timeout",
            })
        except Exception as e:
            yield send_event("error", {
                "type": "error",
                "error": f"Scan error: {type(e).__name__}",
            })

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",  # Disable nginx buffering
        }
    )


@router.get("/scan/demo")
async def scan_demo():
    """
    Demo scan endpoint - returns simulated findings.
    No authentication required. For testing only.
    """
    demo_email = "demo@example.com"

    async def demo_stream():
        orchestrator = ScanOrchestrator()

        def send_event(event_type: str, data: dict) -> str:
            json_data = json.dumps(data, default=str)
            return f"event: {event_type}\ndata: {json_data}\n\n"

        yield send_event("start", {"type": "start", "depth": 2})

        async for finding in orchestrator.run(demo_email, depth=2):
            yield send_event("finding", {
                "type": "finding",
                "finding": finding.model_dump(),
            })
            await asyncio.sleep(0.3)  # Slower for demo visibility

        results = orchestrator.get_results()
        yield send_event("complete", {
            "type": "complete",
            "results": results,
        })

    return StreamingResponse(
        demo_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
        }
    )
