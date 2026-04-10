from dotenv import load_dotenv

load_dotenv()  # loads GEMINI_API_KEY from .env before anything else imports it

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from .ai_devsec.router import router as ai_devsec_router

app = FastAPI(title="AI DevSec Platform", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(ai_devsec_router)


@app.get("/healthz", tags=["health"])
def health_check():
    """Simple liveness probe."""
    return {"status": "ok"}
