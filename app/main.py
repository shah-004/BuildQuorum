from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, File, Form, HTTPException, Query, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from app.builder import BuildError, check_gcc_deterministic
from app.chain import BuildQuorumEngine
from app.config import get_settings
from app.security import ValidationError, validate_upload


class LyingToggleRequest(BaseModel):
    lying: bool


def create_app() -> FastAPI:
    settings = get_settings()
    gcc_usable = check_gcc_deterministic(timeout_seconds=min(5, settings.build_timeout_seconds))
    engine = BuildQuorumEngine(settings=settings, gcc_usable=gcc_usable)

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        settings.ensure_dirs()
        yield

    app = FastAPI(title="BuildQuorum API", version="0.1.0", lifespan=lifespan)
    app.state.settings = settings
    app.state.gcc_usable = gcc_usable
    app.state.engine = engine

    if settings.static_dir.exists():
        app.mount("/static", StaticFiles(directory=str(settings.static_dir)), name="static")

    @app.get("/", response_class=HTMLResponse)
    async def index() -> Any:
        index_path = settings.static_dir / "index.html"
        if index_path.exists():
            return FileResponse(str(index_path), media_type="text/html")
        return HTMLResponse(
            "<h1>BuildQuorum</h1><p>Frontend placeholder active. Visit <a href='/docs'>/docs</a> for API.</p>"
        )

    @app.get("/api/health")
    async def health() -> dict[str, Any]:
        return {
            "status": "ok",
            "gcc_usable": engine.gcc_usable,
            "validators": settings.validator_ids,
            "quorum_threshold": settings.quorum_threshold,
            "chain_length": len(engine.chain),
        }

    @app.post("/api/packages/submit", status_code=202)
    async def submit_package(
        file: UploadFile = File(...),
        package_name: str = Form(...),
        version: str = Form(...),
        compromised_publisher: bool = Form(False),
    ) -> JSONResponse:
        content = await file.read()
        try:
            safe_name, ext = validate_upload(
                filename=file.filename,
                content=content,
                package_name=package_name,
                version=version,
                settings=settings,
            )
            result = engine.submit_package_job(
                raw_bytes=content,
                filename=safe_name,
                extension=ext,
                package_name=package_name.strip(),
                version=version.strip(),
                compromised_publisher=compromised_publisher,
                run_async=True,
            )
            status_code = 200 if result.get("duplicate") else 202
            return JSONResponse(status_code=status_code, content=result)
        except ValidationError as exc:
            raise HTTPException(status_code=exc.status_code, detail=exc.message) from exc
        except BuildError as exc:
            raise HTTPException(status_code=exc.status_code, detail=exc.message) from exc

    @app.get("/api/jobs/{job_id}")
    async def get_job(job_id: str) -> dict[str, Any]:
        with engine.lock:
            job = engine.jobs.get(job_id)
            if job is None:
                raise HTTPException(status_code=404, detail=f"Job '{job_id}' not found.")
            return job.to_dict()

    @app.get("/api/chain")
    async def get_chain() -> dict[str, Any]:
        return engine.get_chain_summary()

    @app.get("/api/chain/validate")
    async def validate_chain() -> dict[str, Any]:
        return engine.validate_chain()

    @app.get("/api/blocks/{block_number}")
    async def get_block(block_number: int) -> dict[str, Any]:
        block = engine.get_block(block_number)
        if block is None:
            raise HTTPException(status_code=404, detail=f"Block {block_number} not found.")
        return block

    @app.get("/api/blocks/{block_number}/proof/{validator_id}")
    async def get_merkle_proof(block_number: int, validator_id: str) -> dict[str, Any]:
        try:
            return engine.get_merkle_proof_for_block(block_number=block_number, validator_id=validator_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc).strip("'")) from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get("/api/packages")
    async def list_packages() -> dict[str, Any]:
        packages = engine.list_packages()
        return {"count": len(packages), "packages": packages}

    @app.get("/api/packages/{block_number}/download")
    async def download_package_artifact(block_number: int) -> FileResponse:
        try:
            path = engine.get_artifact_path(block_number)
            return FileResponse(
                path=str(path),
                filename=path.name,
                media_type="application/octet-stream",
            )
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc).strip("'")) from exc
        except FileNotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.post("/api/packages/verify")
    async def verify_package(
        file: UploadFile = File(...),
        block_number: int | None = Query(default=None),
    ) -> dict[str, Any]:
        content = await file.read()
        if len(content) == 0:
            raise HTTPException(status_code=400, detail="Uploaded file is empty.")
        try:
            return engine.verify_uploaded_file(file_bytes=content, block_number=block_number)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc).strip("'")) from exc

    @app.get("/api/validators")
    async def get_validators() -> dict[str, Any]:
        return engine.get_validators_status()

    @app.post("/api/validators/{validator_id}/lying")
    async def set_validator_lying(validator_id: str, payload: LyingToggleRequest) -> dict[str, Any]:
        try:
            return engine.set_validator_lying(validator_id=validator_id, lying=payload.lying)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc).strip("'")) from exc

    @app.post("/api/demo/tamper/{block_number}")
    async def demo_tamper(block_number: int) -> dict[str, Any]:
        try:
            return engine.tamper_block(block_number=block_number)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc).strip("'")) from exc

    @app.post("/api/demo/repair")
    async def demo_repair() -> dict[str, Any]:
        try:
            return engine.repair_from_snapshot()
        except FileNotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.post("/api/demo/reset")
    async def demo_reset() -> dict[str, Any]:
        return engine.reset_to_genesis()

    return app


app = create_app()