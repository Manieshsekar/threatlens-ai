# ThreatLens AI

An explainable URL investigation workspace with a trained lexical model, domain intelligence collectors, and a portable FastAPI/PostgreSQL backend. A final-year machine-learning project.

**Public release 2:** open [ThreatLens AI](https://threatlens-steve.appumaniesh.chatgpt.site). Visitors can use the website directly in a browser without installing Docker. It includes model inference, bounded DNS/RDAP lookups, server-saved history, private personal reviews, follow-up flags, review activity, deletion, JSON export, and browser printing. The UI includes accessible motion and a [public guide](https://threatlens-steve.appumaniesh.chatgpt.site/guide).

Public records live in Cloudflare D1 and are separated by a secure anonymous browser cookie. The latest 200 reports are available for 30 days. There is no named account, cross-device recovery, or global verified reputation from public reviews. Cookie clearing or expiry loses access; export important reports. Submitted URL paths and queries are redacted before saving.

The portable team edition includes PostgreSQL, role-protected review, audit logs, Redis/Celery jobs and optional credentialed intelligence. Docker/PostgreSQL/Redis operation still requires the supplied smoke check on the target computer. The research model is not a production-certified security guarantee.

## Domain and search visibility

The existing HTTPS link is publicly accessible. A custom domain is supported but none is attached: domain ownership and DNS control are required. No domain was purchased and no account was connected on the user's behalf. Set the owned domain in Sites custom-domain settings, apply exactly the returned DNS verification/routing records, and wait for active HTTPS. Then update `lib/site.ts` and republish. A bare project name alone is not a public DNS hostname.

The site includes canonical metadata, an indexable public guide, `robots.txt`, and `sitemap.xml`; `/api/` responses are noindex and private/no-store. Submit the sitemap through an owner-verified Google Search Console property. Indexing and search placement are controlled by Google and are not guaranteed.

## Start the full application on Windows

Install Docker Desktop with Linux containers and Python 3.12. Start Docker Desktop. Extract this project into a normal local folder, open PowerShell there, and run:

```powershell
python scripts/configure.py
docker compose up --build -d
docker compose ps
python scripts/smoke.py
```

Open http://localhost:3000. API documentation is at http://localhost:3000/api/docs. Retrieve `API_ADMIN_KEY` from your local `.env` file and use it on the sign-in screen. Keep this file private. USER, ANALYST, and ADMIN keys have different permissions. This release uses one principal per role, intended for a single-owner project; it is not a multi-tenant user-management system.

If `python` is unavailable but the Python launcher is installed, use `py -3.12` instead. No Node installation is required for the Docker path. First image builds need internet access and can take several minutes. Default binding is localhost only.

Stop without deleting records:

```powershell
docker compose down
```

Do not add `-v` unless you intend to delete database and queue volumes.

## What is included

- `app/`, `components/`, `lib/`: responsive React/TypeScript interface and hosted inference routes.
- `db/`, `drizzle/`, `lib/hosted.ts`: D1 schema, generated migrations, visitor isolation and hosted persistence.
- `backend/app/`: FastAPI, PostgreSQL entities, inference, fixed-endpoint intelligence adapters, Celery worker.
- `artifacts/model.json`: real, portable calibrated logistic regression artifact, loaded without pickle.
- `artifacts/evaluation.json`: dataset checksum, domain-disjoint splits, model comparison, test metrics.
- `ml/train.py`: reproducible feature extraction, training, calibration, threshold selection, and evaluation.
- `infra/`: Dockerfiles, gateway config and generated PostgreSQL DDL.
- `tests/`: unit, API, role, privacy, provider and cross-runtime inference checks.
- `docs/PROJECT_HANDBOOK.md`: system design, operating guide, feature rationale, roadmap and viva notes.
- `.github/workflows/ci.yml`: backend and frontend validation.

## Verification performed

20 additional hosted checks passed against the local Cloudflare D1 emulator, including migrations, isolation, expiry, deletion, rates, and failure handling. Run `node scripts/test-hosted.mjs`. The portable backend previously passed 31 pytest cases using SQLite strictly as an isolated test adapter. PostgreSQL schema generation passed. TypeScript checks, frontend builds and Python/TypeScript inference parity are covered separately. See `docs/VALIDATION.md` for the final result and limits. The SQLite adapter is rejected as a production configuration.

## Model results

PhiUSIIL contributed 235,795 rows. After URL deduplication and rejecting 14 unsupported inputs, 235,356 rows remained. Splits use registrable domains including private suffixes; all four partitions have zero overlapping domains. The test partition contains 47,355 rows.

The shipped logistic model achieved 99.16% accuracy, 99.41% precision, 98.65% recall, 99.03% F1, and 0.44% false-positive rate on that test partition. These are single-source historical results, not live detection guarantees. The model is highly sensitive to source-specific URL structure. A low-risk assessment does not prove safety.

The internal positive label is phishing = 1. PhiUSIIL uses phishing = 0, so the training script requires `--phishing-label 0` explicitly.

## Retrain reproducibly

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements-dev.txt
python scripts/download_dataset.py
python ml/train.py --csv ml/data/PhiUSIIL_Phishing_URL_Dataset.csv --phishing-label 0 --out artifacts
python -m pytest tests -q
```

Review any model change and rebuild both applications. The model is never automatically retrained from user feedback. The training script fails on empty-class partitions and enforces group separation. Dataset revisions must retain provenance and a checksum.

## Optional intelligence configuration

Put your own credentials in `.env`: `VIRUSTOTAL_API_KEY`, `URLHAUS_AUTH_KEY`. Then run `docker compose up -d --force-recreate api worker`. Empty keys produce explicit “not configured” evidence. VirusTotal checks only existing root-URL reports; path/query sharing and new URL submissions are disabled. URLhaus looks up the hostname and reports host-level observations separately from an exact URL verdict.

TLS checks are disabled by default. `ENABLE_TLS=1` enables validated public-IP connections on port 443 only; operate this worker behind a reviewed egress policy. No content crawler, sandbox browser, or arbitrary HTTP fetcher is included.

## Portable team edition privacy and security

Submitted URLs can contain secrets. The canonical string is used transiently for feature extraction and HMAC identity; paths and queries are redacted in stored reports and worker payloads. Notes entered by analysts are stored verbatim, so do not put secrets there. No URL is opened in the user interface. Authentication uses HTTP-only same-site cookies or Bearer keys. Cookie writes enforce the configured origin, and Redis applies per-key request limits.

Before internet-facing deployment, configure HTTPS, `COOKIE_SECURE=1`, `PUBLIC_ORIGIN`, backups, individual user identity, outbound network policy, log retention and vulnerability review. The compose gateway is bound to loopback intentionally.

## Sources and attribution

- UCI PhiUSIIL: https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset
- Dataset authors: Arvind Prasad and Shalini Chandra. UCI license: CC BY 4.0. The test fixtures contain a small sample of URLs from that source.
- Public Suffix List: https://publicsuffix.org/list/ (Mozilla Public License 2.0). `lib/psl.json` is generated from tldextract's bundled snapshot, including the private section.
- FastAPI: https://fastapi.tiangolo.com/deployment/docker/
- scikit-learn grouped splitting: https://scikit-learn.org/stable/modules/generated/sklearn.model_selection.GroupShuffleSplit.html
- VirusTotal URL reports: https://docs.virustotal.com/reference/url-info
- URLhaus API: https://urlhaus-api.abuse.ch/

Project-specific source is released under the MIT license. Bundled starter components and third-party libraries retain their respective licenses. No paid accounts or provider subscriptions were created.

