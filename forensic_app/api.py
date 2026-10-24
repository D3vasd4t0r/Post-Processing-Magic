
import secrets
from contextlib import asynccontextmanager
from contextvars import ContextVar
from pathlib import Path
from typing import Annotated, Literal

from fastapi import Depends, FastAPI, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.trustedhost import TrustedHostMiddleware

from forensic_app import __version__
from forensic_app.api_presentation import present_response
from forensic_app.app_errors import AppValueError, ErrorText, present_detail, request_locale
from forensic_app.cleanup import Cleanup, cleanup_router
from forensic_app.config_transfer import ConfigurationTransfer, configuration_router
from forensic_app.diagnostics import Diagnostics, diagnostics_router
from forensic_app.feedback import FeedbackStore, feedback_router
from forensic_app.interface_preferences import InterfacePatch, InterfacePreferences
from forensic_app.jobs import JobService, jobs_router, results_router
from forensic_app.malware_modes import MalwareModes, malware_router
from forensic_app.modes import ModeStore, modes_router
from forensic_app.onboarding import tool_guidance
from forensic_app.processing_settings import ProcessingSettings, processing_settings_router
from forensic_app.queue_control import QueueControl, queue_router
from forensic_app.result_viewers import viewer_router
from forensic_app.server_control import ServerControl
from forensic_app.storage import Storage
from forensic_app.storage_overview import StorageOverview, storage_overview_router
from forensic_app.tool_settings import settings_router
from forensic_app.windows_access import is_admin
from forensic_app.workspaces import Workspaces, workspace_router

response_path = ContextVar('response_path', default='')


class InterfaceJSONResponse(JSONResponse):
    def render(self, content):
        return super().render(present_response(response_path.get(), content, request_locale.get()))


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
        InterfacePreferences(storage).initialize()
        limits.initialize()
        mode_store.initialize()
        MalwareModes(storage).initialize()
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
        default_response_class=InterfaceJSONResponse,
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    @app.exception_handler(StarletteHTTPException)
    async def localized_http_error(request, exc):
        body = {"detail": present_detail(exc.detail)}
        if isinstance(exc.detail, ErrorText):
            body.update(error_code=exc.detail.code, error_params=exc.detail.params)
        return JSONResponse(body, status_code=exc.status_code, headers=exc.headers)

    @app.exception_handler(RequestValidationError)
    async def localized_validation_error(request, exc):
        from fastapi.encoders import jsonable_encoder
        details = exc.errors()
        for item in details:
            error = item.get('ctx', {}).get('error')
            if isinstance(error, AppValueError):
                item['msg'] = error.text.localized()
                item['error_code'] = error.text.code
        return JSONResponse({'detail': jsonable_encoder(details)}, status_code=422)

    if not lan:
        app.add_middleware(TrustedHostMiddleware, allowed_hosts=["127.0.0.1", "localhost"])

    @app.middleware("http")
    async def headers(request, call_next):
        locale_token = request_locale.set(InterfacePreferences(storage).get()['locale'])
        path_token = response_path.set(request.url.path)
        try:
            response = await call_next(request)
        finally:
            request_locale.reset(locale_token)
            response_path.reset(path_token)
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
            raise HTTPException(401, ErrorText('error.60d41cc15b14'))

    app.include_router(settings_router(storage, authorize))
    app.include_router(processing_settings_router(limits, authorize))
    app.include_router(storage_overview_router(overview, authorize))
    app.include_router(cleanup_router(cleaner,authorize))
    app.include_router(workspace_router(Workspaces(storage),authorize))
    app.include_router(queue_router(queue, authorize))
    app.include_router(modes_router(mode_store, authorize))
    app.include_router(configuration_router(transfer, authorize))
    app.include_router(jobs_router(jobs, authorize))
    app.include_router(viewer_router(jobs, authorize))
    app.include_router(feedback_router(FeedbackStore(storage),authorize))
    app.include_router(diagnostics_router(Diagnostics(storage,lambda:{'server_running':True,'worker_running':jobs.available(),'administrator':is_admin(),**(runtime or {})}),authorize))
    app.include_router(results_router(jobs))
    app.include_router(malware_router(MalwareModes(storage),authorize))

    @app.post("/api/system/stop", dependencies=[Depends(authorize)])
    def stop_server():
        return control.request()

    @app.get('/api/system/control',dependencies=[Depends(authorize)])
    def control_status():
        return control.status()

    @app.get("/", include_in_schema=False)
    def index():
        return FileResponse(Path(__file__).parent / "web" / "index.html")

    @app.get('/malware.js',include_in_schema=False)
    def malware_script():
        return FileResponse(Path(__file__).parent/'web'/'malware.js',media_type='text/javascript')

    @app.get('/i18n.js',include_in_schema=False)
    def i18n_script():
        return FileResponse(Path(__file__).parent/'web'/'i18n.js',media_type='text/javascript')

    @app.get('/locales/web/{locale}.json',include_in_schema=False)
    def web_catalog(locale: Literal['de','en']):
        return FileResponse(Path(__file__).parent/'locales'/('web.'+locale+'.json'),media_type='application/json')

    @app.get('/api/settings/interface',dependencies=[Depends(authorize)])
    def interface_settings():
        return InterfacePreferences(storage).get()

    @app.put('/api/settings/interface',dependencies=[Depends(authorize)])
    def save_interface_settings(patch: InterfacePatch):
        return InterfacePreferences(storage).update(**patch.model_dump(exclude_none=True))

    @app.get('/api/settings/onboarding',dependencies=[Depends(authorize)])
    def onboarding():
        return tool_guidance(storage)

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

