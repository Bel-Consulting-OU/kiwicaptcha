"""Django integration: settings, the middleware factory, one view.

Wire it in three steps.

1. Build the verifier once in settings or an app module:

    from kiwicaptcha import Settings
    kiwi_settings = Settings(
        secret="your-32-byte-or-longer-signing-secret",
        store="sqlite:///var/lib/kiwi/challenges.db",
        scopes=("login",),
    )
    kiwi_verifier = kiwi_settings.build_verifier()

2. Reference the gate from the middleware list in settings.py:

    MIDDLEWARE = [
        # ...
        "myapp.kiwi.build_gate",
    ]

3. The gate factory lives at module scope. Django imports the
   middleware by path. A lambda or a nested closure cannot be the
   import target:

    def build_gate(get_response):
        return DjangoMiddleware.from_settings(
            get_response,
            kiwi_verifier,
            kiwi_settings.secret,
            protected_scopes=("api/submit",),
        )

A request that passes the gate carries ``request.kiwi_decision``,
the ``VerifyDecision`` with the disposition and the measured solve
duration.
"""

from kiwicaptcha import Settings
from kiwicaptcha.middleware import DjangoMiddleware

kiwi_settings = Settings(
    secret="your-32-byte-or-longer-signing-secret",
    store="sqlite:///var/lib/kiwi/challenges.db",
    scopes=("login",),
)
kiwi_verifier = kiwi_settings.build_verifier()


def build_gate(get_response):
    """The middleware entry point Django imports by path."""
    return DjangoMiddleware.from_settings(
        get_response,
        kiwi_verifier,
        kiwi_settings.secret,
        protected_scopes=("api/submit",),
        expected_scope="login",
    )
