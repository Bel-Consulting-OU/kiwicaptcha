# dogfood

`dogfood.sh` drives the shipped surfaces against one live deployment,
the way a real integrator would:

1. boots the reference deployment (php -S) on a scratch redis;
2. builds the native solver and the hardened verifier sidecar;
3. solves a deployment challenge with the solver and verifies it
   through the deployment's own verifier;
4. refuses a tampered token and a replayed token;
5. issues, solves and verifies through the sidecar's file store,
   including the replay refusal, metrics and doctor surfaces;
6. gates a request through the compat gateway (json mode) and through
   an nginx auth_request chain in front of the same gate.

Every step asserts; any failure exits non-zero. Ports 8490-8494 belong
to the harness and are torn down on exit. Run it with
`bash tools/dogfood/dogfood.sh`; set `DOGFOOD_KEEP_LOGS=1` to copy the
service logs into `tools/dogfood/last-run/` for debugging.
