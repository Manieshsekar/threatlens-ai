# Release validation

Public release 2 validated on 13 September 2026.

| Check | Result | Scope |
|---|---|---|
| Hosted D1 workflow | 20 checks passed | Real generated migration on local Miniflare D1; isolation, review/model separation, expiry, delete, input limits, rates and provider failures |
| PhiUSIIL training | Passed | Real downloaded dataset; pinned checksum and explicit label mapping |
| Domain leakage guard | Passed | Zero overlapping registrable domains across four partitions |
| Backend suite | 31 passed | Validation, privacy, roles, origin checks, SQLAlchemy persistence, exports and provider-unavailable behavior |
| Python/TypeScript parity | 308 passed | Sampled dataset URLs and reserved/IDN/IPv6/PSL fixtures |
| TypeScript check | Passed | No type errors |
| Managed hosted build | Passed | Cloudflare-compatible server and client output |
| Next.js portable build | Passed | Standalone server generated for Docker frontend |
| PostgreSQL DDL compilation | Passed | Six tables with foreign keys, indexes and JSONB |
| DOCX rendering | Completed | Every page reviewed; title border removed and references reformatted |
| Real PostgreSQL/Redis services | Not executed | Binaries and Docker unavailable; OS package setup lacks necessary permissions |
| Docker image build and full smoke | Not executed | Run scripts/smoke.py after starting Compose on the target computer |
| Credentialed threat providers | Not executed | No VirusTotal or URLhaus account credentials supplied |
| Direct DNS/TLS | Not operationally validated | Restricted environment; TLS is disabled by default |
| Browser interaction QA | Not performed | Frontend validated through production compilation and logic checks |

The portable Python API suite uses SQLite only as an isolated test adapter. The hosted TypeScript suite separately uses the local Cloudflare D1 emulator, invoking actual route handlers with simulated HTTP requests. It does not establish PostgreSQL concurrency, Redis Lua behavior, Celery broker delivery, container networking, or backup recovery. The production factory rejects a SQLite DATABASE_URL.

Two dependency deprecation warnings occur in FastAPI/Starlette's test-client compatibility path. They did not cause test failures. Dependency vulnerability scanning was not completed; installed and pinned versions are not a claim of vulnerability-free dependencies.

The historical model has strong single-source results, but no cross-source, temporal or real-world security effectiveness validation. The shipped risk score is a triage score and should not be represented as a calibrated probability or a safety certification.
