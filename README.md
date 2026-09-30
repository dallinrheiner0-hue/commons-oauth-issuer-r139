# R139 temporary diagnostic successor

OFFLINE PREPARED. Publication, deployment and one diagnostic request require separate authorization.
This revision replaces the issuer application; it cannot initialize, activate, or issue OAuth tokens.
Only GET /healthz (static liveness) and authenticated GET /diagnostic/state exist.
No Blueprint is included; do not provision resources from this revision.

Python 3.12.14, Linux x86_64. Build:
python verify_artifact.py && python -m pip install --require-hashes --only-binary=:all: -r requirements.lock && python -m pip check
Start: python run.py. Health path: /healthz. Single worker, access logging off, proxy headers off.
Existing internal DATABASE_URL and exact DATABASE_BINDING remain untouched. SYNTHETIC_OAUTH_ENABLED=false.
Add only DIAGNOSTIC_TOKEN_SHA256 and DIAGNOSTIC_DEADLINE matching gate.py.
The raw diagnostic token is never a server setting or release file.

One connection with read-only default; explicit REPEATABLE READ READ ONLY transaction;
4-second connect timeout; 2-second statement, 1-second lock, 12-second transaction,
3-second idle-transaction timeouts. Fixed queries only. End with ROLLBACK then close.
Any cleanup failure suppresses provisional classification. No commits or retries.
TLS uses the existing sslmode=require contract: encrypted, without independent certificate
verification. The exact internal hostname/database/user/binding are checked.

CHECK constraint metadata is compared locally without evaluating it or calling database
introspection functions. Only source location numbers and whitespace are normalized.
Ordinary SQL operators and PostgreSQL internal catalog/type machinery still execute as part
of SELECT; no explicit function calls, user-function execution or function-body retrieval.
Pin and receipt comparisons return booleans only. Flows/codes return presence flags only.
Catalog queries are bounded in rows and time; raw constraint metadata size is not bounded at
SQL transport level. This is a trusted provider/catalog observation, not a hostile SQL sandbox.
No arbitrary caller SQL/identifiers/paths exist. Default read-only does not make the underlying
existing database role read-only, and PostgreSQL may update internal statistics/hint bits.

Response classifications describe only the observed snapshot. historical_outcome always
remains UNKNOWN. expected_receipt_sha256 is an expectation, not a claimed observed receipt
for UNKNOWN or inconsistent/uninitialized results.

The in-process one-use guard resets after a service restart. It is NOT a durable server-side
exactly-once guarantee. The separate local operator consumes an exclusive, fsynced attempt
record before network I/O and refuses subsequent attempts. Never recreate/delete its marker
or bypass it, and never retry uncertain delivery. Global one-use enforcement would require
additional durable server state, which this diagnostic deliberately does not create.

Offline tests use catalog/transport stubs. Native PostgreSQL 18 serialization, Render ingress
and this diagnostic deployment have NOT been executed. Unexpected native behavior fails
closed. Offline passing tests do not reconcile the real initialization state.
