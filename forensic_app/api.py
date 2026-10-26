"""ASGI composition root for authenticated ZIP processing and offline UI assets.

Business services own persistence and execution; this module binds their routes,
request-local presentation and process startup/shutdown hooks.
"""
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
from forensic_app.modes import ModeStore, modes_router
from forensic_app.onboarding import tool_guidance
from forensic_app.processing_settings import ProcessingSettings, processing_settings_router
from forensic_app.queue_control import QueueControl, queue_router
from forensic_app.server_control import ServerControl
from forensic_app.source_access import SourceAccess, source_download_router, source_router
from forensic_app.storage import Storage
from forensic_app.storage_overview import StorageOverview, storage_overview_router
from forensic_app.tool_settings import settings_router
from forensic_app.windows_access import is_admin
from forensic_app.workspaces import Workspaces, workspace_router

response_path = ContextVar('response_path', default='')


class InterfaceJSONResponse(JSONResponse):
    """Project only explicitly supported presentation fields before JSON encoding.

    Request-scoped path and locale are supplied by the HTTP middleware. Raw
    tool output and download bodies are not translated by this response class.
    """
    def render(self, content):
        """Serialize a detached, locale-aware projection for the current request path."""
        return super().render(present_response(response_path.get(), content, request_locale.get()))


def create_app(storage: Storage, token: str, *, lan: bool = False, processing: bool = False,
               test_no_admin: bool = False, on_shutdown=None, control_id: str = '', runtime: dict | None = None) -> FastAPI:
    """Wire the local API, persistence services and optional worker lifecycle.

    Args:
        storage: Writable application data root; initialization occurs at startup.
        token: Shared session bearer secret captured by the authorization dependency.
        lan: Permit non-loopback hostnames; TLS is configured by the launcher.
        processing: Start the separate worker and expose its live availability.
        test_no_admin: Mark explicitly synthetic runs that bypass the UAC test gate.
        on_shutdown: Optional callback invoked after the drain monitor is satisfied.
        control_id: Desktop-session identity returned to the authenticated controller.
        runtime: Optional controller metadata for status and diagnostic snapshots.

    Job execution stays in the worker. Creating this ASGI object does not run a
    workflow; startup initializes the services and may start that worker.
    """
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
        """Initialize persistent services, then close the monitor and optional worker.

            Startup resets the instance drain flag. Queue recovery and worker process
            ownership are delegated to JobService rather than request handlers.
        """
        storage.initialize()
        InterfacePreferences(storage).initialize()
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
        default_response_class=InterfaceJSONResponse,
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    @app.exception_handler(StarletteHTTPException)
    async def localized_http_error(request, exc):
        """Localize structured application errors while retaining canonical error codes."""
        body = {"detail": present_detail(exc.detail)}
        if isinstance(exc.detail, ErrorText):
            body.update(error_code=exc.detail.code, error_params=exc.detail.params)
        return JSONResponse(body, status_code=exc.status_code, headers=exc.headers)

    @app.exception_handler(RequestValidationError)
    async def localized_validation_error(request, exc):
        """Expose structured validation errors without rewriting arbitrary input values."""
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
        """Bind request-local presentation context and apply common response headers.

            ContextVar tokens are reset even if downstream handling raises. Response
            headers also apply to file and streaming bodies, without rewriting them.
        """
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
        """Require this server session bearer token before protected handlers run.

            The application uses one shared session secret, not per-user roles.
        """
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
    app.include_router(feedback_router(FeedbackStore(storage),authorize))
    app.include_router(diagnostics_router(Diagnostics(storage,lambda:{'server_running':True,'worker_running':jobs.available(),'administrator':is_admin(),**(runtime or {})}),authorize))
    app.include_router(results_router(jobs))
    sources = SourceAccess(jobs.store)
    app.include_router(source_router(sources, authorize))
    app.include_router(source_download_router(sources))

    @app.post("/api/system/stop", dependencies=[Depends(authorize)])
    def stop_server():
        """Request admission shutdown and let the persistent-work drain monitor decide when to exit."""
        return control.request()

    @app.get('/api/system/control',dependencies=[Depends(authorize)])
    def control_status():
        """Return the current drain flag and counts of active supported work."""
        return control.status()

    @app.get("/", include_in_schema=False)
    def index():
        """Serve the bundled offline login and processing interface."""
        return FileResponse(Path(__file__).parent / "web" / "index.html")

    @app.get('/i18n.js',include_in_schema=False)
    def i18n_script():
        """Serve the locally bundled localization renderer without a frontend build step."""
        return FileResponse(Path(__file__).parent/'web'/'i18n.js',media_type='text/javascript')

    @app.get('/workspace.js', include_in_schema=False)
    def workspace_script():
        """Serve navigation and ongoing-job presentation helpers."""
        return FileResponse(Path(__file__).parent / 'web' / 'workspace.js',
                            media_type='text/javascript')

    @app.get('/job-views.js', include_in_schema=False)
    def job_views_script():
        """Serve job-bound log and result download interface helpers."""
        return FileResponse(Path(__file__).parent / 'web' / 'job-views.js',
                            media_type='text/javascript')

    @app.get('/locales/web/{locale}.json',include_in_schema=False)
    def web_catalog(locale: Literal['de','en']):
        """Serve one of the two explicit local UI translation catalogs."""
        return FileResponse(Path(__file__).parent/'locales'/('web.'+locale+'.json'),media_type='application/json')

    @app.get('/api/settings/interface',dependencies=[Depends(authorize)])
    def interface_settings():
        """Read the server-local interface preference, outside portable workflow exports."""
        return InterfacePreferences(storage).get()

    @app.put('/api/settings/interface',dependencies=[Depends(authorize)])
    def save_interface_settings(patch: InterfacePatch):
        """Persist only fields explicitly supplied in the validated interface patch."""
        return InterfacePreferences(storage).update(**patch.model_dump(exclude_none=True))

    @app.get('/api/settings/onboarding',dependencies=[Depends(authorize)])
    def onboarding():
        """Describe configured tool references without launching any tool."""
        return tool_guidance(storage)

    @app.get("/health")
    def health():
        """Return anonymous process liveness; this does not certify worker readiness."""
        return {"status": "ok", "service": "post-processing-magic"}

    @app.get("/api/system", dependencies=[Depends(authorize)])
    def system():
        """Return authenticated instance metadata and current worker capability flags.

            Runtime paths and the token-file location remain local status information;
            the secret itself is not returned by this endpoint.
        """
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

