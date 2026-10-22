import secrets
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from starlette.middleware.trustedhost import TrustedHostMiddleware

from forensic_app import __version__
from forensic_app.cleanup import Cleanup, cleanup_router
from forensic_app.config_transfer import ConfigurationTransfer, configuration_router
from forensic_app.diagnostics import Diagnostics, diagnostics_router
from forensic_app.feedback import FeedbackStore, feedback_router
from forensic_app.jobs import JobService, jobs_router, results_router
from forensic_app.modes import ModeStore, modes_router
from forensic_app.processing_settings import ProcessingSettings, processing_settings_router
from forensic_app.queue_control import QueueControl, queue_router
from forensic_app.server_control import ServerControl
from forensic_app.storage import Storage
from forensic_app.storage_overview import StorageOverview, storage_overview_router
from forensic_app.tool_settings import settings_router
from forensic_app.windows_access import is_admin
from forensic_app.workspaces import Workspaces, workspace_router


def create_app(storage: Storage, token: str, *, lan: bool = False, processing: bool = False,
               test_no_admin: bool = False, on_shutdown=None, control_id: str = '', runtime: dict | None = None) -> FastAPI:
    mode_store = ModeStore(storage)
    transfer = ConfigurationTransfer(storage)
    jobs = JobService(storage, test_no_admin=test_no_admin)
    limits = ProcessingSettings(storage)
    queue = QueueControl(storage)
    overview = StorageOverview(storage)
    cleaner = Cleanup(storage,overview)
    control = ServerControl(storage,jobs,on_shutdown)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        storage.initialize()
        limits.initialize()
        mode_store.initialize()
        transfer.initialize()
        jobs.store.initialize()
        queue.initialize()
        cleaner.initialize()
        control.reset()
        storage.record_start(__version__)
        if processing:
            jobs.start()
        try:
            yield
        finally:
            control.close()
            if processing:
                jobs.stop()

    app = FastAPI(
        title="Post-Processing-Magic",
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    if not lan:
        app.add_middleware(TrustedHostMiddleware, allowed_hosts=["127.0.0.1", "localhost"])

    @app.middleware("http")
    async def headers(request, call_next):
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers.setdefault("Content-Security-Policy", (
            "default-src 'self'; script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; "
            "base-uri 'none'; form-action 'self'; object-src 'none'"
        ))
        return response

    bearer = HTTPBearer(auto_error=False)

    def authorize(
        credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
    ) -> None:
        value = credentials.credentials if credentials else ""
        if not secrets.compare_digest(value.encode("utf-8"), token.encode("utf-8")):
            raise HTTPException(401, "Zugriffstoken fehlt oder ist ungültig.")

    app.include_router(settings_router(storage, authorize))
    app.include_router(processing_settings_router(limits, authorize))
    app.include_router(storage_overview_router(overview, authorize))
    app.include_router(cleanup_router(cleaner,authorize))
    app.include_router(workspace_router(Workspaces(storage),authorize))
    app.include_router(queue_router(queue, authorize))
    app.include_router(modes_router(mode_store, authorize))
    app.include_router(configuration_router(transfer, authorize))
    app.include_router(jobs_router(jobs, authorize))
    app.include_router(feedback_router(FeedbackStore(storage),authorize))
    app.include_router(diagnostics_router(Diagnostics(storage,lambda:{'server_running':True,'worker_running':jobs.available(),'administrator':is_admin(),**(runtime or {})}),authorize))
    app.include_router(results_router(jobs))

    @app.post("/api/system/stop", dependencies=[Depends(authorize)])
    def stop_server():
        return control.request()

    @app.get('/api/system/control',dependencies=[Depends(authorize)])
    def control_status():
        return control.status()

    @app.get("/", include_in_schema=False)
    def index():
        return FileResponse(Path(__file__).parent / "web" / "index.html")

    @app.get("/health")
    def health():
        return {"status": "ok", "service": "post-processing-magic"}

    @app.get("/api/system", dependencies=[Depends(authorize)])
    def system():
        return {
            "version": __version__,
            "control_id": control_id,
            'runtime':runtime or {},
            "administrator": is_admin(),
            "stage": "ZIP/KAPE-Test" if processing else "Startgerüst – Ausführung nicht aktiviert",
            "storage": str(storage.root),
            "database": "SQLite, Schema 1",
            "mode": "LAN / HTTPS" if lan else "Lokal",
            "token_file": str(storage.root / "config" / "access-token.txt"),
            "profiles": [],
            "capabilities": {
                "upload": processing and jobs.available(),
                "worker": jobs.available(),
                "analysis": processing and jobs.available(),
                "result_download": processing,
            },
        }

    return app

