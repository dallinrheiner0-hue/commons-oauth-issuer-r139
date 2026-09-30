# Commons synthetic OAuth issuer — R139

Standalone, dormant by default. No model, Commons ledger, MCP execution server, runner or Forge interface. Synthetic subject and grant are enforced in code. This is temporary qualification infrastructure, not permanent hosting or real participant enrollment.

Python: 3.12.14, Linux x86_64.

Build: `python verify_artifact.py && python -m pip install --require-hashes --only-binary=:all: -r requirements.lock && python -m pip check`

Start: `python run.py`

Render health path: `/healthz`. This returns process liveness only; it never initializes or claims database/OAuth readiness. `/ready` requires explicitly activated synthetic configuration and a valid durable trial. Access logs are disabled to avoid logging authorization query strings; provider edge logging must be reviewed before even synthetic secret use.

## Configuration

- `DATABASE_URL`: fresh database internal URL only; secret, never source/log output.
- `DATABASE_BINDING`: JSON object with `resource_id`, `database` (`commons_oauth_state_r139`), `user`, `workspace` (`tea-daulra8473hc73bo7ls0`), and a fresh 32-character lowercase hex `initialization_id`. These are pinned admission facts, not caller inputs.
- `RENDER_EXTERNAL_URL`: provider-supplied exact HTTPS origin; no predicted hostname is used. When RENDER=true, RENDER_SERVICE_NAME must equal commons-oauth-trial-r139. Optional `ISSUER_ORIGIN` must match the provider value exactly; local fixtures require this explicit origin instead. Record the actual assigned hostname before operator requests. Later synthetic OAuth configuration must match it.
- `OPERATOR_DIGEST`: SHA-256 hex of a future randomly generated 32-byte operator secret. It only controls initialize/status/synthetic activate, never messages. Keep the raw value outside the service. No value ships in this artifact.
- `OPERATOR_DEADLINE`: absolute Unix expiry, no more than 24 hours ahead. Expired restarts remain closed; no rolling extension.
- `SYNTHETIC_OAUTH_ENABLED`: `false` for initial provisioning. No signing key or OAuth configuration is required in this mode.
- `PORT`: Render-injected listener port; default 10000.
- Later separately authorized synthetic activation only: `SYNTHETIC_OAUTH_ENABLED=true`, `SYNTHETIC_SIGNING_KEY` (synthetic RSA >=2048 PEM), `SYNTHETIC_OAUTH_CONFIG` matching oauth.Config. Subject must be `synthetic-owner`, grant `synthetic-grant-r139`, scope `commons:send`. Absolute deadline <=24 hours. Client/resource/callback and issuer are exact, with reviewed stable ChatGPT callback syntax but no actual ChatGPT connection in this stage.

## Persistence and initialization

Ordinary process startup creates no connections or schema. POST `/initialize` with the operator bearer and empty body performs identity checks, takes a PostgreSQL transaction advisory lock and refuses any foreign/partial state. It creates exactly public.trial, public.flows, public.codes in one transaction, including an initialization receipt without key, grant or activation. Exact pristine-repeat requests are read-only reconciliation; different receipt, activated state or used state is rejected. No schema migration or repair exists.

GET `/status` authenticates the same operator and reads the durable receipt. An uncertain initialization response requires status/evidence review, never an automatic POST retry. A precommit crash may leave no schema; its retry still requires explicit review. POST `/activate` is separate and one-use; it persists the exact configuration/key pin and absolute deadline. It requires separately supplied synthetic configuration. Initialization alone cannot issue a token.

Authorization-code flow uses S256 PKCE, fixed audience/client/callback, consent passphrase and CSRF, one-use code, one token per trial, <=600-second token lifetime and no refresh token. Lost committed token responses remain consumed. No dynamic registration, arbitrary redirect, participant administration or operational scope.

## Runtime assumptions

Render terminates public TLS and must overwrite X-Forwarded-Proto. App checks exactly one HTTPS header plus exact Host; uvicorn's generic forwarded-header trust is disabled. This is an explicit hosted qualification gate, not proof from local HTTP tests. Only this issuer and its database belong in the workspace. Internal Postgres uses sslmode=require; Render's internal self-signed certificate does not support verify-full. No claim of endpoint certificate verification is made.

Render may sleep/restart the process. Its local filesystem is disposable; only PostgreSQL persists state. Free database expiry does not authorize upgrade, reinitialization or reseeding. `/healthz` can remain healthy after a database failure; status/readiness are separate evidence.

`render.yaml` is a DATABASE-ONLY Blueprint with explicit Free/Ohio and deny-all external access. Web service creation is a separate manual public-repository step. Disable Blueprint Auto Sync and web Auto Deploy; no further repository pushes or deploy hooks are authorized implicitly.
