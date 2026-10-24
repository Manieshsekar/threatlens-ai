# ThreatLens AI

An explainable URL investigation workspace with a trained lexical model, domain intelligence collectors, and a portable FastAPI/PostgreSQL backend. A final-year machine-learning project.

**Public release 2:** open [ThreatLens AI](https://threatlens-steve.appumaniesh.chatgpt.site). Visitors can use the website directly in a browser without installing Docker. It includes model inference, bounded DNS/RDAP lookups, server-saved history, private personal reviews, follow-up flags, review activity, deletion, JSON export, and browser printing. The UI includes accessible motion and a [public guide](https://threatlens-steve.appumaniesh.chatgpt.site/guide).

Public records live in Cloudflare D1 and are separated by a secure anonymous browser cookie. The latest 200 reports are available for 30 days. There is no named account, cross-device recovery, or global verified reputation from public reviews. Cookie clearing or expiry loses access; export important reports. Submitted URL paths and queries are redacted before saving.

The portable team edition includes PostgreSQL, role-protected review, audit logs, Redis/Celery jobs and optional credentialed intelligence. Docker/PostgreSQL/Redis operation still requires the supplied smoke check on the target computer. The research model is not a production-certified security guarantee.

## Scoring correction (source update; public deployment pending)

The current source fixes false alarms on ordinary profile, course, and documentation URLs. The original dataset's legitimate examples all used root paths, allowing the old model to learn misleading path/slash-count shortcuts. The new `domain-lr-v2` artifact uses 9 hostname/transport predictors with separate sigmoid calibration; all 30 URL features remain available for lexical warning rules. Platform-imitation warnings are preserved, and no popular domain is automatically certified safe. Deep investigation is the default, and older saved reports are marked as using an earlier model.

The frozen regression set contains 500 curated reference URLs across 37 domains excluded from fitting, calibration, and threshold selection. High-risk warnings decreased from 443 to 0 on that set. This is a benign-reference regression check, not 100% accuracy or an estimate of live phishing recall. Individual endpoint reachability checks were not completed before this source update.

The linked public site has not yet received this correction. Publishing source to GitHub does not deploy the hosted Site. Existing PPTs and handbooks are preserved as historical documentation; their original model description and metrics do not describe `domain-lr-v2`.

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
- `artifacts/evaluation.json`: dataset checksum, domain-disjoint splits, selection criteria, and current test metrics.
- `ml/retrain_robust.py`: current reproducible training, calibration, and threshold selection. `ml/train.py` retains the original historical baseline.
- `tests/data/real-web-2026-10-24.json`: frozen reference URLs and collection provenance.
- `artifacts/scoring-validation.json`: regression-check scope and results.
- `infra/`: Dockerfiles, gateway config and generated PostgreSQL DDL.
- `tests/`: unit, API, role, privacy, provider and cross-runtime inference checks.
- `docs/PROJECT_HANDBOOK.md`: system design, operating guide, feature rationale, roadmap and viva notes.
- `.github/workflows/ci.yml`: backend and frontend validation.

## Verification performed

20 additional hosted checks passed against the local Cloudflare D1 emulator, including migrations, isolation, expiry, deletion, rates, and failure handling. Run `node scripts/test-hosted.mjs`. The portable backend and scoring regressions passed 40 pytest cases using SQLite strictly as an isolated test adapter. PostgreSQL schema generation passed. TypeScript checks, frontend builds and Python/TypeScript inference parity are covered separately. See `docs/VALIDATION.md` for the final result and limits. The SQLite adapter is rejected as a production configuration.

## Model results

The current artifact is `domain-lr-v2`. All reference-web domains are excluded from the historical partitions, and historical partitions are separated by registrable domain. Its historical test partition contains 47,246 URLs. Separate curated reference domains supplement training, calibration, and validation; none of the 500 regression-test URLs are used for fitting or threshold selection.

The current classifier achieved **89.76% accuracy, 95.81% precision, 79.81% recall, 87.08% F1, and 2.66% false-positive rate** on the historical held-out partition. Removing misleading shortcuts reduces false alarms on ordinary real-web paths but lowers historical benchmark recall. It can miss phishing, including compromised or shared-hosting pages. A low-risk result does not establish safety, and DNS/RDAP metadata is contextual evidence rather than a phishing verdict.

The previous 99.16% accuracy / 98.65% recall figures belong to the original model and partition, not this corrected artifact. The two historical test partitions differ because reference domains are now reserved. Current-source results are recorded in `artifacts/evaluation.json`.

The internal positive label is phishing = 1; source PhiUSIIL phishing = 0. The current retraining script applies this mapping explicitly.

## Retrain reproducibly

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements-dev.txt
python scripts/download_dataset.py
python ml/retrain_robust.py --csv ml/data/PhiUSIIL_Phishing_URL_Dataset.csv --web tests/data/real-web-2026-10-24.json --out artifacts
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
