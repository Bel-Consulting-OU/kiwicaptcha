"""Flask integration: install the extension and mark protected views.

    pip install flask
    python flask_example.py
"""

from flask import Flask, jsonify, request

from kiwicaptcha import Settings, VerifyDecision
from kiwicaptcha.middleware import FlaskKiwiCaptcha

app = Flask(__name__)

settings = Settings(
    secret="your-32-byte-or-longer-signing-secret",
    store="memory://",
    scopes=("login",),
)
verifier = settings.build_verifier()
captcha = FlaskKiwiCaptcha(app, verifier, settings.secret, expected_scope="login")


@app.post("/api/submit")
@captcha.protected()
def submit():
    decision: VerifyDecision = request.kiwi_decision
    return jsonify(
        accepted=True,
        disposition=decision.disposition,
        solve_duration_ms=decision.outcome.solve_duration_ms,
    )


@app.get("/health")
def health():
    return jsonify(ok=True)  # unprotected: no @captcha.protected mark


if __name__ == "__main__":
    app.run(port=8781)
