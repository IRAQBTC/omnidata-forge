from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .database import Base, engine
from .routers import auth, scan, cases, watchlist, rules, audit, integrations

Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="OmniData Forge API",
    version="5.0.0",
    description="Backend for the enterprise data-exposure / secrets & PII detection suite.",
)

# In production, replace "*" with the exact frontend origin(s).
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router)
app.include_router(scan.router)
app.include_router(cases.router)
app.include_router(watchlist.router)
app.include_router(rules.router)
app.include_router(audit.router)
app.include_router(integrations.router)


@app.get("/health")
def health():
    return {"status": "ok"}
