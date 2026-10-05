"""FastAPI integration: one dependency per protected route.

    pip install fastapi uvicorn
    uvicorn fastapi_example:app --port 8782
"""

from fastapi import Depends, FastAPI, Header, Request
from typing import Optional

from kiwicaptcha import Settings, VerifyDecision
from kiwicaptcha.middleware import FastApiKiwiDependency

app = FastAPI()

settings = Settings(
    secret="your-32-byte-or-longer-signing-secret",
    store="memory://",
    scopes=("login",),
)
verifier = settings.build_verifier()
guard = FastApiKiwiDependency(verifier, settings.secret, expected_scope="login")


@app.post("/api/submit")
def submit(
    decision: VerifyDecision = Depends(guard),
    x_kiwi_token: Optional[str] = Header(default=None),
):
    return {
        "accepted": True,
        "disposition": decision.disposition,
        "price": decision.price,
    }


@app.get("/health")
def health():
    return {"ok": True}
