from fastapi import FastAPI
from backend.app.ai_devsec.router import router as ai_devsec_router


app = FastAPI(title="AI DevSec Platform", version="0.1.0")

app.include_router(ai_devsec_router)


