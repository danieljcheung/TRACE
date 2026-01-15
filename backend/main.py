from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from config import settings
from security import SecurityHeadersMiddleware
from routes import health_router, verify_router, scan_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    print(f"""
+======================================================+
|                                                      |
|   TRACE BACKEND                                      |
|   v{settings.VERSION}                                            |
|                                                      |
|   Environment: {settings.ENVIRONMENT:<15}               |
|   Data Retention: NONE                               |
|                                                      |
+======================================================+
    """)
    yield
    print("\n[TRACE] Shutdown. Memory cleared.\n")


app = FastAPI(
    title="TRACE API",
    version=settings.VERSION,
    docs_url="/docs" if settings.DEBUG else None,
    redoc_url=None,
    lifespan=lifespan,
)

app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


@app.exception_handler(Exception)
async def error_handler(request: Request, exc: Exception):
    print(f"[ERROR] {type(exc).__name__}: {exc}")
    return JSONResponse(status_code=500, content={"success": False, "error": "Internal error"})


app.include_router(health_router, prefix="/api")
app.include_router(verify_router, prefix="/api")
app.include_router(scan_router, prefix="/api")


@app.get("/")
async def root():
    return {"name": "TRACE API", "version": settings.VERSION, "status": "ok"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host=settings.HOST, port=settings.PORT, reload=True)
