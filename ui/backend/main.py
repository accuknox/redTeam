"""Knox-RT UI — FastAPI backend.

Exposes the knox-rt toolkit as a REST API so a frontend can:
  1. Browse available plugins, strategies, and compliance frameworks.
  2. Build a config JSON interactively.
  3. Start a scan and stream live progress via SSE.
  4. Retrieve completed scan results.
"""

from __future__ import annotations

import asyncio
import json
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Any, AsyncGenerator

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from sse_starlette.sse import EventSourceResponse

app = FastAPI(title="Knox-RT UI", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

_STATIC = Path(__file__).parent / "static"
if _STATIC.exists():
    app.mount("/static", StaticFiles(directory=str(_STATIC)), name="static")


@app.get("/")
def index():
    return FileResponse(str(_STATIC / "index.html"))

# ── In-memory run store ────────────────────────────────────────────────────────
# run_id → {"status": "running"|"done"|"error", "output": [...], "results": {...}}
_runs: dict[str, dict] = {}

KNOX_RT_DIR = Path(__file__).parent.parent.parent


# ── Plugin / strategy metadata ─────────────────────────────────────────────────

def _load_plugin_meta() -> dict:
    try:
        from plugins import CATEGORIES, _REGISTRY, PLUGIN_FRAMEWORKS, PLUGIN_SEVERITY
        from plugins import COMPLIANCE_FRAMEWORKS

        categories = []
        for cat_key, cat_info in CATEGORIES.items():
            plugins = []
            for pid, cls in _REGISTRY.items():
                if getattr(cls, "_category", None) == cat_key or pid.startswith(f"{cat_key}:") or (
                    hasattr(cls, "id") and cls.id and any(
                        p.id == pid for p in cat_info.get("plugins", [])
                    )
                ):
                    plugins.append({
                        "id": pid,
                        "objective": getattr(cls, "objective", ""),
                        "severity": PLUGIN_SEVERITY.get(pid, "medium"),
                        "frameworks": PLUGIN_FRAMEWORKS.get(pid, []),
                    })
            categories.append({
                "key": cat_key,
                "label": cat_info.get("label", cat_key),
                "description": cat_info.get("description", ""),
                "plugins": plugins,
            })
        return {"categories": categories}
    except Exception as exc:
        return {"categories": [], "error": str(exc)}


def _load_all_plugins() -> list[dict]:
    try:
        from plugins import _REGISTRY, PLUGIN_FRAMEWORKS, PLUGIN_SEVERITY, CATEGORIES
        results = []
        for pid, cls in _REGISTRY.items():
            # determine category
            cat_key = ""
            for ck, cinfo in CATEGORIES.items():
                if pid.startswith(f"{ck}:") or pid == ck:
                    cat_key = ck
                    break
            results.append({
                "id": pid,
                "category": cat_key,
                "objective": getattr(cls, "objective", ""),
                "severity": PLUGIN_SEVERITY.get(pid, "medium"),
                "frameworks": PLUGIN_FRAMEWORKS.get(pid, []),
            })
        return sorted(results, key=lambda x: (x["category"], x["id"]))
    except Exception:
        return []


def _load_strategies() -> list[dict]:
    try:
        from strategies import _REGISTRY
        return [
            {"id": sid, "description": getattr(cls, "description", "")}
            for sid, cls in _REGISTRY.items()
        ]
    except Exception:
        return []


def _load_frameworks() -> list[dict]:
    try:
        from plugins import COMPLIANCE_FRAMEWORKS
        return [
            {"key": k, "label": v.get("label", k), "description": v.get("description", "")}
            for k, v in COMPLIANCE_FRAMEWORKS.items()
        ]
    except Exception as exc:
        print(f"ERROR loading frameworks: {exc}", file=sys.stderr)
        return []


# ── Routes — metadata ──────────────────────────────────────────────────────────

@app.get("/api/plugins")
def get_plugins():
    return _load_all_plugins()


@app.get("/api/categories")
def get_categories():
    try:
        from plugins import CATEGORIES, CATEGORY_LABELS, _REGISTRY, PLUGIN_SEVERITY, PLUGIN_FRAMEWORKS
        out = []
        for cat_key, plugin_ids in CATEGORIES.items():
            out.append({
                "key": cat_key,
                "label": CATEGORY_LABELS.get(cat_key, cat_key),
                "description": "",
                "plugin_count": len(plugin_ids),
                "plugins": [
                    {
                        "id": pid,
                        "objective": getattr(_REGISTRY[pid], "objective", ""),
                        "severity": PLUGIN_SEVERITY.get(pid, "medium"),
                        "frameworks": PLUGIN_FRAMEWORKS.get(pid, []),
                    }
                    for pid in plugin_ids
                ],
            })
        return out
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/api/strategies")
def get_strategies():
    return _load_strategies()


@app.get("/api/frameworks")
def get_frameworks():
    return _load_frameworks()


@app.get("/api/languages")
def get_languages():
    return [
        {"code": "en", "name": "English"},
        {"code": "es", "name": "Spanish"},
        {"code": "zh", "name": "Chinese (Simplified)"},
        {"code": "fr", "name": "French"},
        {"code": "de", "name": "German"},
        {"code": "ar", "name": "Arabic"},
        {"code": "ru", "name": "Russian"},
        {"code": "ja", "name": "Japanese"},
        {"code": "pt", "name": "Portuguese"},
        {"code": "ko", "name": "Korean"},
        {"code": "hi", "name": "Hindi"},
        {"code": "it", "name": "Italian"},
        {"code": "nl", "name": "Dutch"},
        {"code": "tr", "name": "Turkish"},
        {"code": "pl", "name": "Polish"},
        {"code": "vi", "name": "Vietnamese"},
        {"code": "th", "name": "Thai"},
        {"code": "id", "name": "Indonesian"},
    ]


# ── Routes — config ────────────────────────────────────────────────────────────

class ConfigPayload(BaseModel):
    config: dict[str, Any]


@app.post("/api/config/validate")
def validate_config(payload: ConfigPayload):
    try:
        sys.path.insert(0, str(KNOX_RT_DIR))
        from config import load_config
        import tempfile, os
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(payload.config, f)
            tmp = f.name
        try:
            load_config(tmp)
        finally:
            os.unlink(tmp)
        return {"valid": True}
    except Exception as exc:
        return {"valid": False, "error": str(exc)}


# ── Routes — scan ──────────────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    config: dict[str, Any]


@app.post("/api/scan/start")
async def start_scan(req: ScanRequest):
    import time as _time
    run_id = str(uuid.uuid4())
    _runs[run_id] = {
        "status": "running",
        "output": [],
        "results": None,
        "error": None,
        "start_time": _time.time(),
        "total_cases": 0,
        "completed_cases": 0,
    }

    config_path = Path(f"/tmp/knox_rt_run_{run_id}.json")
    config_path.write_text(json.dumps(req.config, indent=2))

    results_path = Path(f"/tmp/knox_rt_results_{run_id}.json")

    async def _run():
        try:
            proc = await asyncio.create_subprocess_exec(
                # -u: stdout is a pipe here, so Python would block-buffer it and
                # the UI would see nothing until ~8KB accrued or the run ended.
                sys.executable, "-u", str(KNOX_RT_DIR / "cli.py"),
                "--config", str(config_path),
                "--output", str(results_path),
                cwd=str(KNOX_RT_DIR),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                env={**__import__("os").environ, "PYTHONPATH": str(KNOX_RT_DIR)},
            )
            async for line in proc.stdout:
                text = line.decode("utf-8", errors="replace").rstrip()
                _runs[run_id]["output"].append(text)

                # Extract total from "[1/20]" pattern
                import re
                match = re.search(r'\[(\d+)/(\d+)\]', text)
                if match:
                    _runs[run_id]["completed_cases"] = int(match.group(1))
                    _runs[run_id]["total_cases"] = int(match.group(2))

            await proc.wait()
            if results_path.exists():
                _runs[run_id]["results"] = json.loads(results_path.read_text())
                _runs[run_id]["status"] = "done"
            else:
                _runs[run_id]["status"] = "error"
                _runs[run_id]["error"] = "Scan completed but no results file was written."
        except Exception as exc:
            _runs[run_id]["status"] = "error"
            _runs[run_id]["error"] = str(exc)
        finally:
            config_path.unlink(missing_ok=True)

    asyncio.create_task(_run())
    return {"run_id": run_id}


@app.get("/api/scan/{run_id}/stream")
async def stream_scan(run_id: str):
    if run_id not in _runs:
        raise HTTPException(status_code=404, detail="Run not found")

    async def _generator() -> AsyncGenerator[dict, None]:
        sent = 0
        last_progress = 0
        while True:
            run = _runs[run_id]
            lines = run["output"]
            while sent < len(lines):
                yield {"event": "log", "data": lines[sent]}
                sent += 1

            # Send progress update
            import time as _time
            total = run["total_cases"] or 1
            completed = run["completed_cases"]
            progress = int((completed / total) * 100) if total > 0 else 0
            elapsed = int(_time.time() - run["start_time"])

            if progress > last_progress or elapsed % 5 == 0:  # Send every % or every 5 sec
                yield {
                    "event": "progress",
                    "data": json.dumps({
                        "percent": progress,
                        "completed": completed,
                        "total": total,
                        "elapsed_seconds": elapsed,
                    }),
                }
                last_progress = progress

            if run["status"] in ("done", "error"):
                yield {"event": "status", "data": run["status"]}
                if run["status"] == "error" and run.get("error"):
                    yield {"event": "error-detail", "data": run["error"]}
                break
            await asyncio.sleep(0.3)

    return EventSourceResponse(_generator())


@app.get("/api/scan/{run_id}/status")
def scan_status(run_id: str):
    if run_id not in _runs:
        raise HTTPException(status_code=404, detail="Run not found")
    run = _runs[run_id]
    return {
        "run_id": run_id,
        "status": run["status"],
        "log_lines": len(run["output"]),
        "error": run.get("error"),
    }


@app.get("/api/scan/{run_id}/results")
def scan_results(run_id: str):
    if run_id not in _runs:
        raise HTTPException(status_code=404, detail="Run not found")
    run = _runs[run_id]
    if run["status"] != "done":
        raise HTTPException(status_code=202, detail="Scan not complete yet")
    return run["results"]


@app.get("/api/scan/{run_id}/log")
def scan_log(run_id: str):
    if run_id not in _runs:
        raise HTTPException(status_code=404, detail="Run not found")
    return {"lines": _runs[run_id]["output"]}


@app.get("/health")
def health():
    return {"status": "ok"}


def run() -> None:
    """Console-script entry point (`knox-rt-ui`) for the installed package."""
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8080, reload=True)
