from fastapi import FastAPI
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from dependencies import limiter
from routers import users, keypasses
from fastapi.middleware.cors import CORSMiddleware

app= FastAPI(title= "Passphrases Vault API")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows all origins (localhost:1420, tauri://, etc.)
    allow_credentials=True,
    allow_methods=["*"],  # Allows POST, GET, PUT, DELETE, OPTIONS
    allow_headers=["*"],
)
app.state.limiter= limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.include_router(users.router)
app.include_router(keypasses.router)
