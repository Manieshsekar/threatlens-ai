# ThreatLens AI Project Handbook

System design, implementation plan, operating guide and research evidence

Prepared for Steve • Public release 2 • 13 September 2026

## Project purpose

ThreatLens AI helps a user investigate a URL by combining a trained lexical model, transparent rule indicators, domain context and analyst evidence. Its output answers what was observed, what remains unknown, and which action is reasonable. It does not certify that a website is safe.

### The problem being addressed

A simple classifier can give an impressive probability without showing its evidence, data limitations or operational coverage. Blocklists may miss new destinations. Models may exploit collection shortcuts. This project separates statistical predictions, external observations, human verification and user feedback, so each can be assessed on its own merits.

### Delivered scope

| Component | Release state |
| --- | --- |
| Hosted workspace | Public model inference, DNS/RDAP, online history, personal reviews, flags, deletion, JSON export and print |
| Portable full stack | Implemented React, FastAPI, PostgreSQL, Redis/Celery, analyst review, feedback, audit and PDF export |
| Machine learning | Real PhiUSIIL model trained and evaluated; artifact and reproducible training script included |
| Deployment qualification | 20 D1 workflow checks and both builds pass; portable Docker/PostgreSQL/Redis still needs the smoke check |
| Future research | Temporal and cross-source evaluation, graph/campaign analysis, automated MLOps and content sandbox are not implemented |

The original brief proposes progressive versions. This delivery establishes a usable research application and a portable full-stack release. It does not claim completion of the optional enterprise and research roadmap.



## Use the public website

Open https://threatlens-steve.appumaniesh.chatgpt.site in your browser. The audience is public. Visitors need no Docker installation or provider account to use the hosted scanner and review desk. The site creates a private workspace for the current browser using an essential secure cookie.

### Your first investigation

Paste an HTTP or HTTPS link, select Quick scan, and click Investigate. Read the risk label and recommendation, then inspect Evidence & explanation, Domain & infrastructure, Model evidence, and URL features. Quick scan processes URL text without querying external intelligence providers. Deep investigation also queries DNS and supported registration services.

### What the analyst workbench does

The workbench is a review desk for your own investigations. Select a report, read its evidence, choose Appears legitimate, Appears malicious, or Needs more evidence, and enter at least ten characters of rationale. Click Save my review. The saved assessment and recent review activity remain available after refresh in the same browser.

A public review is a personal opinion with evidence, not a certified analyst verdict. It never changes the model score, affects another visitor, or automatically trains a model. Save follow-up flag records a possible false positive, false negative, or uncertainty for your own follow-up. It does not notify a staffed moderation service.

### History, exports and deletion

History stores up to 200 recent reports online for 30 days. Domain intelligence groups your reports by registrable domain. Export JSON to keep structured evidence; Print report prints the selected report view or saves it as PDF using your browser. Delete report removes one investigation; Clear history removes all your reports, notes and flags after a confirmation.

### Browser identity and recovery

The essential HTTP-only cookie lasts 30 days from creation. Clearing cookies, changing browser or cookie expiry loses access to that workspace; there is no named account, recovery or cross-device sync. Export important reports. On shared computers, delete your history before leaving. Never put passwords or private tokens in hostnames or notes.



## Public backend and visitor privacy

Public release 2 adds a hosted backend using Cloudflare D1. Browser requests go to same-origin TypeScript route handlers, which enforce request format, ownership, expiry and limits. The server computes model features, queries fixed external endpoints when requested, saves a redacted report, and returns it to the browser. No local database or Docker is needed for public visitors.

| D1 table | Purpose |
| --- | --- |
| investigations | Redacted JSON report, hashed visitor identifier, creation/expiry times |
| reviews | Latest personal assessment and rationale per investigation |
| feedback | Latest personal follow-up flag and optional note |
| review_events | Latest 20 review actions and timestamps per report |
| rate_buckets | Temporary request counters for visitors, network groups and the service |

### Request and privacy controls

A cryptographically random 256-bit browser token is stored in a Secure, HttpOnly, SameSite=Strict, host-only cookie. Only its SHA-256 digest is used for database ownership. A token identifies a browser, not a named person. Every report read, review and delete checks ownership. All database queries use prepared statements and schema changes use generated, versioned migrations.

Writes require same-origin JSON requests. Streamed request bodies are capped at 12,000 bytes; URLs at 4,096 characters; notes at 2,000 characters. Public limits permit up to 15 scans per browser per minute, 30 per network address when supplied by the host, and 120 scans per service minute. Separate edit counters apply. Rate buckets store daily network-address hashes, not raw addresses; hashes are not a promise of anonymity.

### Retention and failure behavior

Reports become inaccessible 30 days after creation. New scans remove up to 100 expired reports and 100 expired rate buckets per cleanup batch. Physical deletion can therefore lag expiry during inactivity. Report deletion cascades to reviews, flags and activity. A browser retains at most 200 reports; saving newer reports evicts older ones. Storage failure returns a recoverable error; unavailable providers remain unknown.

The public backend is separate from the portable PostgreSQL team backend. It enables private personal reviews for visitors without giving every anonymous person trusted analyst powers or access to a shared global investigation queue.



## Public link, domain and Google discovery

Public release URL: https://threatlens-steve.appumaniesh.chatgpt.site. The current site access policy is public, so this link can be shared with friends, family and other visitors. No custom domain is attached. The project has not purchased a domain or established access to a registrar account.

### Why the hosting suffix is still present

The hosting suffix belongs to the provider. Replacing it requires a fully qualified domain under the owner’s control, for example a registered project-name domain with a top-level suffix. A bare name such as ThreatLens is not a normal public Internet hostname. Do not assume any project-name domain is available or already owned.

### Custom-domain connection procedure

1. Register a suitable domain or choose one you already own. 2. Add its exact hostname to this existing site’s custom-domain settings. 3. At the DNS provider, copy every returned ownership-validation record and the exact routing target: CNAME for a subdomain or the returned A targets for an apex. 4. Wait until domain and HTTPS status are active. 5. Update lib/site.ts to the active canonical origin and republish. 6. Share the custom URL. Do not guess IP addresses or CNAME targets.

Changing origin creates a different cookie scope. Existing anonymous browser history does not automatically move to the new domain. Export reports from the original site before switching. Keep the old URL available during transition and plan a redirect only after the new hostname is active.

### Search-engine preparation

The application includes page titles, descriptions, canonical links, Open Graph metadata, a public user guide, robots.txt and sitemap.xml. Search engines are allowed to crawl the public pages. API routes return noindex and private/no-store headers, and robots.txt disallows /api/. Report data is not included in the sitemap.

To request indexing, verify ownership of the site in Google Search Console and submit /sitemap.xml. A domain property requires DNS verification; a URL-prefix property can use an applicable supported verification method. The application does not have access to a verified Search Console property. A sitemap is a discovery hint, not a promise of crawling, indexing or ranking [10, 11].

### What changed in this release

The installation notice was replaced by a working review desk; server-backed history survives refresh; visitor records are isolated; personal notes, flags, deletion and activity were added. Scanning indicators, animated scores, panel transitions and hover states now make actions more visible. Reduced-motion preferences disable nonessential motion. Scrollbars, labels and public-facing wording were improved.



## Architecture and tool choices

The normal full-stack flow is browser → same-origin gateway → FastAPI → lexical model and database. Deep investigations enter Celery through Redis. The worker retrieves bounded intelligence and updates the saved investigation. The browser polls its status and renders the report.

| Layer | Choice and reason |
| --- | --- |
| Interface | React, TypeScript and Next.js; shared accessible components and a responsive dark workspace |
| Backend | FastAPI and Pydantic for request validation, typed schemas and OpenAPI |
| Records | PostgreSQL through SQLAlchemy; indexed entities and JSONB evidence snapshots |
| Jobs and cache | Redis and Celery; bounded asynchronous collectors and short-lived results |
| Model | scikit-learn logistic regression, StandardScaler and sigmoid calibration; Extra Trees comparison |
| Intelligence | DNS, allowlisted RDAP, optional TLS, VirusTotal and URLhaus adapters |
| Delivery | Docker Compose, Nginx gateway, pytest and GitHub Actions |
| Documentation | Editable DOCX handbook, Markdown manual, source files, model card and evaluation JSON |

### Two execution environments

The public workspace runs the exported model in TypeScript, fixed-provider lookups and a real D1 backend for visitor-scoped history and personal reviews. The portable application runs PostgreSQL and supports role-protected team workflows. Both use the same model artifact; 308 fixture URLs match across Python and TypeScript. The public backend has 20 passing checks against a local D1 emulator.

### Project layout and service boundaries

app/ and lib/ hold the frontend and hosted routes. backend/app/ holds the API, inference engine, collectors, persistence and worker. ml/ holds training; artifacts/ contains the model and measured results. infra/ supplies deployment configuration. tests/ and scripts/ contain validation and setup commands. docs/ explains design and operation.

No additional account plugin is required for the implemented core. Provider adapters use environment credentials directly. No paid subscription or remote-control application was installed. Python and frontend dependencies were installed in the working environment; the computer installation remains a local action.



## Optional Windows team installation

Public visitors can skip this chapter. It installs the separate portable team edition with role keys, PostgreSQL, Redis and Celery. It is not required to use the published scanner or public review desk.

Use Docker Desktop with Linux containers and Python 3.12. Keep the project outside protected system folders. Extract the source archive, open PowerShell in its root, and ensure Docker Desktop is running. Docker builds install application dependencies inside containers.

```text
python scripts/configure.py
docker compose up --build -d
docker compose ps
python scripts/smoke.py
```

The first command creates distinct access keys, a database password and a URL identity secret in .env. It refuses to overwrite an existing configuration. The second starts six services: gateway, frontend, API, worker, PostgreSQL and Redis. The smoke script checks gateway access, API health, model inference and stored history. A pass prints a single PASS message.

Open http://localhost:3000. Open .env locally and copy API_ADMIN_KEY into the access-key sign-in field. Use the user key when testing scan-only permissions and the analyst key when testing verification. Never commit or send .env. The default gateway binds only to 127.0.0.1.

### First investigation

Scan https://example.com in Quick scan mode. Confirm that the report contains a timestamp, model version, risk score, evidence confidence, feature contributions and export controls. Run a Deep investigation to request DNS and registry metadata. Unknown or unavailable provider evidence must remain explicitly unknown.

### Routine commands

```text
docker compose logs --tail 80 api worker
docker compose restart api worker
docker compose down
```

The final command stops containers while preserving named volumes. Adding -v deletes stored database and queue data. If Python is available through the Windows launcher only, replace python with py -3.12. A connection error usually means Docker is not ready, the first build is still running, or a required service is unhealthy.

### Common configuration mistakes

A blank access key fails startup; rerun configuration in a clean project folder or edit the existing file carefully. An Origin check failure means PUBLIC_ORIGIN does not match the browser origin. If port 3000 is occupied, change the gateway binding and PUBLIC_ORIGIN together. Do not expose database or Redis ports to solve an application routing issue.



## Dataset and experimental design

The source is the UCI PhiUSIIL dataset by Arvind Prasad and Shalini Chandra, published under CC BY 4.0 [1]. Training uses only URL and label, extracting all predictors locally. Existing webpage features, FILENAME, similarity indexes and source-derived probabilities are excluded.

| Preparation | Observed result |
| --- | --- |
| Input rows | 235,795 |
| Unique usable URLs | 235,356 |
| Repeated exact URLs removed | 425 |
| Unsupported inputs rejected | 14 |
| Conflicting URL labels | 0 |
| Training / calibration / validation / test | 139,617 / 26,008 / 22,376 / 47,355 |
| Registrable-domain overlap across partitions | 0 |

The source label 0 means phishing and 1 means legitimate. The pipeline explicitly maps phishing to internal positive class 1. It groups by registrable domain using the Public Suffix List including private suffixes. Training fits the scaler and classifier. A separate domain partition fits sigmoid calibration; another selects the threshold; the final test partition is used for measurement.

### Measured test results

| Metric | Deployed logistic model | Extra Trees comparison |
| --- | --- | --- |
| Accuracy | 99.16% | 98.72% |
| Precision | 99.41% | 99.81% |
| Recall | 98.65% | 97.22% |
| F1 | 99.03% | 98.50% |
| F2 | 98.80% | 97.72% |
| ROC AUC | 99.49% | 99.72% |
| PR AUC | 99.63% | 99.77% |
| False positive rate | 0.44% | 0.14% |
| False negative rate | 1.35% | 2.78% |

The deployed model has Brier score 0.00755 and a 0.40 model threshold. Extra Trees uses a 0.50 comparison threshold. Logistic regression was chosen for portable auditable inference, not because it wins every metric. These comparisons are not a comprehensive hyperparameter search.



## Model reasoning and reproducibility

For each URL, the engine calculates 30 deterministic numeric features. Each is standardized with training-set means and scales. The linear model sums coefficient-weighted features and an intercept. A separately fitted sigmoid maps that raw score to a benchmark-calibrated phishing estimate [2, 3]. Model JSON includes feature order, version, scaling, coefficients, calibration parameters and threshold.

### Risk and confidence are different

The quick-scan risk is the maximum of the model percentage and capped lexical rule points. An exact URL provider hit can raise portable risk to at least 95. A prior malicious analyst decision is exposed through separate reputation evidence. The fused risk is a triage score, not a calibrated probability. Confidence describes evidence coverage; it remains limited when only the model and lexical indicators are available.

### Explanation method

The report lists the largest signed standardized feature contributions to raw model log-odds. Positive contributions raise that raw score; negative contributions lower it. They do not sum to a probability and are not causal explanations. Rule explanations are presented separately. HTTPS is a transport property, never a certificate of legitimacy.

### Reproduce the experiment

```text
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements-dev.txt
python scripts/download_dataset.py
python ml/train.py --csv ml/data/PhiUSIIL_Phishing_URL_Dataset.csv --phishing-label 0 --out artifacts
```

The downloader verifies a pinned CSV SHA256 before accepting the dataset. The original experiment used Python 3.12, scikit-learn 1.8.0, NumPy 2.3.5 and pandas 2.2.3. Splitting seeds are 42, 43 and 44; model random states are fixed. New artifacts require review and a rebuild of both interfaces.

### Research limits

High historical accuracy may reflect how the source was collected, including differences in HTTPS and URL structure. No external-source test, temporal holdout, live analyst trial or ablation study has been completed. Current source timestamps cannot support a defensible temporal split. Before claiming deployment accuracy, obtain timestamped verified data from independent sources and evaluate that held-out distribution.



## Portable API and record design

| Method and endpoint | Purpose and access |
| --- | --- |
| POST /api/v1/login | Create a same-site HTTP-only session from a configured role key |
| POST /api/v1/scan | Quick report or queued deep investigation |
| GET /api/v1/scan/{id} | Read an accessible investigation and its status |
| GET /api/v1/history | Recent accessible investigations with a bounded result count |
| GET /api/v1/domain/{domain} | Find accessible investigations for a registrable domain |
| POST /api/v1/feedback | Store a report of possible false positive or false negative |
| POST /api/v1/scan/{id}/verification | Analyst or administrator review with a required rationale |
| GET /api/v1/scan/{id}/report.pdf | Download a redacted PDF report |
| GET /api/v1/system | Inspect model, role, provider and runtime status |
| GET /api/v1/audit | Administrator view of recent audit events |
| GET /api/v1/health | Check required database and cache availability |

### Six initial database tables

domains uses the registrable domain as its primary key. url_entities uses a secret-key HMAC of the canonical URL and references domains. investigations references url_entities and stores owner role, time, status, mode and immutable-at-scan evidence snapshots. analyst_verifications and user_feedback reference investigations. audit_logs records actor, action, subject and timestamp without URL secrets.

JSONB is used for evidence snapshots because providers return heterogeneous observations. Keys, relationships, statuses and dates remain normal indexed columns. A fully normalized per-provider schema and dedicated model registry are later migrations, not already implemented. The generated infra/schema.sql documents the actual initial PostgreSQL schema.

### Reputation and feedback semantics

Exact-URL history is retrieved by HMAC identity. A previous analyst verdict can be shown as reputation, with its timestamp and source. It is not silently propagated to every URL on the domain. A clean review must not erase conflicting model or provider evidence. User feedback is never treated as ground truth or used for immediate retraining.



## Portable intelligence and security

Collectors receive only sanitized task data. The application never fetches a submitted webpage, follows its redirect chain, executes JavaScript, renders screenshots or downloads payloads. Fixed provider endpoints reduce the SSRF attack surface; a destination string cannot become an arbitrary HTTP endpoint [6].

| Collector | Behavior and limits |
| --- | --- |
| DNS | A, AAAA, MX, NS, TXT and CNAME observations; bounded records and timeouts. No local DNSSEC validation claim. |
| RDAP | Explicit .com and .net registry allowlist. Missing age or unsupported registries stay unknown. |
| TLS | Disabled by default. Optional port-443 worker validates every resolved address as public and connects to a pinned address with hostname validation. |
| VirusTotal | Optional credential. Existing root-URL report lookup only; path/query sharing and submissions disabled [4]. |
| URLhaus | Optional credential. Host-level malware observation; not an exact-URL phishing verdict [5]. |
| Caching | Portable worker caches sanitized intelligence for 60 seconds. This is a conservative application TTL, not an assertion of DNS freshness. |

### Controls implemented

Input validation rejects control characters, backslashes, embedded credentials, invalid ports, encoded hostnames and ambiguous numeric addresses. Private-address targets do not reach network collectors. Queries use SQLAlchemy parameter binding. React escapes displayed text. Cookie-authenticated writes check Origin, keys are compared in constant time, and Redis enforces per-key request limits. The gateway imposes a request-body size cap.

### Privacy design

Both URL paths and queries may contain secrets. Only redacted display strings and numeric features are saved; the full URL is transient. HMAC identity makes offline guessing harder than an ordinary URL hash, provided its secret is protected. Domain names and user-written notes remain sensitive data. The public edition enforces browser-scoped ownership, 30-day access expiry and report deletion. The portable edition still needs an operator-defined retention policy.

### Limits requiring deployment review

The initial role-key system represents one principal per role, not individual accounts. Queue recovery after a hard worker crash, distributed provider quotas, long-term retention, tenant isolation and immutable external audit storage need additional work. A DNS allowlist is not a substitute for a network egress firewall. Do not enable content analysis without an isolated retrieval service.



## Product guide and analyst workflow

### Scanner and evidence

Choose Quick scan for URL-only model analysis. Choose Deep investigation to add network metadata from available collectors. A returned report shows classification, risk score, evidence confidence, recommendation and model version. Evidence tabs separate rule indicators, infrastructure, model contributions and raw features. Missing provider data never becomes a clean verdict.

### History and domain exploration

The public edition saves recent reports in D1 for the same browser, up to 200 reports for 30 days. Refreshing preserves them; clearing cookies or changing devices does not. The portable edition stores history in PostgreSQL: user keys see user-owned investigations, while analyst and administrator keys access the review workspace. Filtering operates on recent investigations.

### Portable team verification

Open the analyst workbench, choose an investigation, inspect its evidence and enter a rationale of at least ten characters. Choose clean, malicious or unsure, then save with an analyst or administrator key. A pending deep investigation must finish before verification. The original model assessment is retained, and conflicting clean verdicts are marked for attention.

A normal user can submit false-positive, false-negative or unsure feedback. That creates a separate feedback record and audit event. It does not change the model or the verified label. For future retraining, an analyst must review the feedback, establish evidence, approve a training candidate and include it in a versioned dataset.

### Reports

JSON export contains the current complete structured report, including observations and model evidence. Browser printing produces the selected web report view. The portable API also provides a concise PDF summary. These are evidence snapshots at a time, not permanent certifications; provider data and the destination itself can change.

### Examples for a demonstration

Use reserved example domains rather than visiting suspected live phishing pages. Compare https://example.com and http://paypal-verify.example/login. Explain which indicators changed without claiming the reserved example is known malware. Follow with a malformed input, a private IP, a missing provider key and a role-denied verification to demonstrate operational behavior.



## Implementation plan and version roadmap

| Phase | Objective and completion gate |
| --- | --- |
| 0  Design | Define users, evidence semantics, safe network boundaries and deployment constraints. Completed in this release. |
| 1  Baseline research | Obtain dataset provenance; extract inference-safe features; use domain-disjoint training, calibration, validation and test. Implemented and run. |
| 2  Product core | Build scanner, reports, FastAPI and PostgreSQL schema. UI and isolated API tests pass; full PostgreSQL startup still needs smoke validation. |
| 3  Intelligence | Implement DNS/RDAP and optional TLS/provider adapters; expose coverage and failures. Credentialed live tests remain pending. |
| 4  Analyst workflow | Implement role checks, history, exact-URL reputation, feedback, review and audit. Tested through an isolated database adapter. |
| 5  Release operations | Public D1 workflows, request isolation and both builds pass. Portable team containers and backup recovery still require the local smoke gate. |
| 6  Production ML | Add MLflow/DVC, model approval, drift telemetry, challenger evaluation and signed model artifacts. Future version. |
| 7  Advanced research | Cross-source and temporal evaluation, graph relationships, campaign clustering and isolated content analysis. Future version. |

### Must have and optional scope

Must-have release features are deterministic validation, reproducible inference, truthful unknown states, evidence explanations, persistent backend design, permission checks, tests, exports and a documented startup path. Optional additions include SHAP for nonlinear models, calibrated ensembles, per-source model fusion, graph databases and neural URL representations. None should be added purely for complexity.

### Research questions

RQ1: How well does lexical inference generalize across unseen domains and collection sources? RQ2: Does current DNS/RDAP/TLS evidence improve precision at a fixed recall? RQ3: Does calibration remain reliable under temporal shift? RQ4: Can shared infrastructure identify campaigns without confusing shared hosting with common control?

### Approximate effort and cost

This is a medium-to-high complexity portfolio system. A student should plan roughly 4–8 weeks to understand, operate and harden the release, with additional weeks for credible research experiments; these are planning estimates, not measured delivery times. Local use needs no paid provider by default. Cloud compute, managed databases, backups and provider plans can create recurring charges; obtain current quotes before provisioning. No domain registration or separately billed provider subscription was purchased. Hosting is supplied through the existing site account; this handbook does not establish its billing terms.



## Operations and release acceptance

### Automated checks

```text
python -m pytest tests -q
node scripts/check-parity.mjs
node scripts/test-hosted.mjs
corepack pnpm exec tsc --noEmit
THREATLENS_LOCAL=1 corepack pnpm exec next build
```

The final command uses POSIX environment syntax; in PowerShell set $env:THREATLENS_LOCAL="1" first and then run the pnpm command. The Docker build sets this variable automatically. GitHub Actions repeats Python tests, TypeScript checks, parity checks, the D1 workflow checks and the portable frontend build.

### Validation achieved

The portable backend previously passed 31 tests. Public release 2 passed 20 D1 checks, 308 Python/TypeScript parity cases, TypeScript checking, the managed hosted build and the standalone Next.js build. D1 checks cover migrations, cookie creation, isolation, review/model separation, deletion cascades, expiry, atomic limits and provider failures. The backend tests use SQLite only as an isolated adapter; production configuration rejects SQLite. PostgreSQL DDL generation succeeds. Docker, Redis and real PostgreSQL execution were not available in this workspace, so the six-service smoke test remains an explicit release gate.

### Portable team deployment path

First run Docker Compose locally and pass scripts/smoke.py. Then deploy the same containers to an appropriate private VM or container host, with persistent volumes and TLS termination. Keep database and queue services private. Set PUBLIC_ORIGIN to the actual HTTPS origin, COOKIE_SECURE=1, distinct strong credentials and the relevant provider keys. Verify the entire workflow before granting other people access.

### Enterprise evolution

Use individual OIDC identities and tenant-aware authorization, managed PostgreSQL with backups, private Redis, isolated worker networks, egress filtering, a secret manager and audited model promotion. Add structured latency and error metrics, provider budgets, queue-depth alerts and credential rotation. External immutable audit storage is stronger than append-only application behavior.

### Recovery and monitoring

Monitor health, scan errors, provider coverage, queue age and feedback rates. Keep PostgreSQL backups and test restoring into a separate environment. Do not delete volumes as a troubleshooting shortcut. A failed or stalled investigation should remain visibly failed or pending; it must not be silently reported complete. Feature-distribution drift and production false positives require new verified labels, not guesses from model confidence.



## Interview explanation and project mastery

### A concise project explanation

ThreatLens AI is a URL investigation platform that combines a calibrated lexical classifier with transparent indicators and optional domain intelligence. I separate machine assessments, provider evidence and analyst verification. The model uses registrable-domain-disjoint evaluation, and the application includes an API, a PostgreSQL design, asynchronous jobs, a React interface and security-focused tests.

### Questions to prepare

| Question | Key explanation |
| --- | --- |
| Why group by domain? | Random URL splits can put related infrastructure in train and test, making generalization look stronger. |
| Why not call 99 percent accuracy production proof? | This benchmark is historical and single-source; collection bias and distribution shift can dominate. |
| Why use calibrated probabilities? | Raw classifier outputs need not match observed event frequencies. Calibration is distribution-dependent. |
| Why is fused risk not probability? | Rules, provider floors and review evidence alter the statistical output without a learned probabilistic fusion model. |
| Why not learn from feedback immediately? | Unverified feedback can be wrong or adversarial and would contaminate future training. |
| Why block arbitrary fetching? | A server-side fetcher can be abused to contact internal systems, metadata endpoints or redirect targets. |
| What remains before enterprise deployment? | Full PostgreSQL/Redis/Docker execution, provider validation, identity hardening, monitoring and cross-source evaluation. |

### Accurate CV wording

Built an explainable URL investigation platform using React, FastAPI and a portable PostgreSQL/Redis architecture, with role-protected analyst review and privacy-aware reporting. Trained a calibrated lexical model on 235k usable URLs and evaluated it on a 47k URL domain-disjoint holdout. Published a visitor-isolated D1-backed review workspace; added 20 hosted workflow checks, 31 portable backend tests and 308 cross-runtime parity cases.

Use these statements only after you have run the application and can explain the implementation. Describe unexecuted infrastructure as designed or implemented, not deployed. Do not claim enterprise readiness, zero-day detection, production accuracy, graph intelligence or automatic MLOps that this release does not implement.



## Feature catalog one

All 30 features are computed from the normalized URL at inference without fetching a webpage. They are statistical indicators, not independent proof of phishing. Features overlap and can be correlated; contribution values should not be interpreted as independent causal effects.

| Feature | Security intuition | False positive caveat |
| --- | --- | --- |
| url_length | Obfuscation or long tracking chains | Legitimate search and tracking URLs can be long. |
| hostname_length | Long hostnames can conceal identity | Hosted services may use descriptive hostnames. |
| path_length | Deep or elaborate endpoint structure | Documentation and commerce paths can be long. |
| query_length | Encoded destinations or many parameters | Search, analytics and signed requests use large queries. |
| subdomain_count | Brand-like labels may obscure the real domain | Large organizations use nested hostnames. |
| dot_count | Extra separators can hide domain boundaries | Versioned filenames and addresses also contain dots. |
| hyphen_count | Repeated separators appear in imitation names | Hyphenated legitimate brands are common. |
| underscore_count | Unusual endpoint naming and generated identifiers | APIs and tracking systems use underscores. |
| slash_count | Depth and scheme/path structure | Routing conventions and dataset collection can dominate. |
| digit_count | Generated strings and lookalike names | Dates, IDs and legitimate account numbers contain digits. |



## Feature catalog two

Reproducibility: every feature below is calculated locally from the submitted URL. Network evidence is kept outside the lexical feature vector; the trained model does not invent DNS, domain-age or TLS values.

| Feature | Security intuition | False positive caveat |
| --- | --- | --- |
| letter_count | Captures URL character composition | Mostly measures structure and length, not intent. |
| digit_ratio | Dense numeric identifiers or substitution | CDNs and generated resources may be numeric. |
| letter_ratio | Nonalphabetic obfuscation density | Ordinary query syntax lowers the ratio. |
| entropy | Random-looking tokens or generated labels | Secure signed URLs intentionally have high entropy. |
| is_ip | Literal address hides familiar domain identity | Device management and infrastructure use IPs. |
| is_https | Transport scheme and collection context | Phishing frequently uses valid HTTPS. |
| nonstandard_port | Atypical web service port | Development and legitimate admin tools use such ports. |
| punycode | Internationalized name may conceal visual imitation | Many languages legitimately use IDN domains. |
| percent_count | Encoding can obscure displayed structure | Ordinary URL escaping requires percent encoding. |
| parameter_count | Multiple query components or tracking chains | Complex applications legitimately have many parameters. |



## Feature catalog three

The initial brand detector is a dictionary-based hostname reference rule. It is not a full typosquatting classifier: edit-distance matching, multilingual confusable detection and brand-domain allowlists require separate evaluation before deployment.

| Feature | Security intuition | False positive caveat |
| --- | --- | --- |
| max_char_run | Repeated characters can suggest generated text | Long separators and encoding can be legitimate. |
| suspicious_extension | Executable or archive-like download path | Trusted software distribution has the same extensions. |
| credential_words | Login, verification or payment themes | Real authentication and financial pages share these words. |
| brand_match | Brand string outside its standard .com domain | Other official domains, references and partners can match. |
| shortener | Destination is hidden behind a short link | Legitimate sharing often uses shorteners. |
| redirect_parameter | A parameter may point to another destination | OAuth and navigation commonly redirect. |
| at_count | An at-sign inside path or query may mislead | Email addresses and resource syntax can contain it. |
| equal_count | Encoded values and key-value complexity | Normal queries use equals signs. |
| question_count | Query boundary and unusual embedded syntax | Encoded or literal question marks can be legitimate. |
| host_digit_ratio | Numeric substitutions or generated hostname | Infrastructure naming often includes digits. |

### Normalization choices

Schemes are restricted to HTTP and HTTPS. Missing schemes default to HTTPS. Hostnames are lowercased and IDNs become ASCII form. Default ports are removed from the canonical representation; fragments are excluded. Query order and path spelling are retained because changing them can alter semantics. Credential-bearing and ambiguous numeric URLs are rejected. The Public Suffix List snapshot is versioned with the source; it must be maintained as suffix rules evolve.



## Public API reference and troubleshooting

Public endpoints use the anonymous secure browser cookie. They do not accept portable role keys. The same-origin browser workflow initializes the cookie with GET /api/v1/system before creating a scan.

| Method and endpoint | Public behavior |
| --- | --- |
| GET /api/v1/system | Model/capability status and essential cookie initialization |
| POST /api/v1/scan | Validate, rate-limit, analyze, optionally collect DNS/RDAP, then save |
| GET /api/v1/history | Read current browser reports, newest first |
| DELETE /api/v1/history | Delete reports owned by the current browser |
| GET /api/v1/scan/{id} | Read an owned report with review, flag and activity |
| DELETE /api/v1/scan/{id} | Delete an owned investigation and its dependent notes |
| POST /api/v1/scan/{id}/verification | Save a personal assessment; preserve model output |
| POST /api/v1/feedback | Save a personal follow-up flag |

### Troubleshooting public use

A 429 response means a request cap was reached; wait one minute. A 401 workspace message means the cookie is missing or invalid; refresh to reconnect. A 404 means the report is expired, deleted or belongs to another browser. A 503 means storage or service failure; retry without discarding the URL or draft note. A DNS/RDAP unavailable observation does not erase the lexical report.

For operator troubleshooting, check native site deployment status, database binding and generated migrations. Do not edit an applied migration: add a new migration for later schema changes. Keep deployment source and package aligned. Real credentialed providers and the portable Docker stack have not been validated in the hosted workflow checks; browser interaction QA was not performed.



## Sources and evidence files

The measurements in this handbook come from artifacts/evaluation.json generated by this project. External documentation below supports the dataset semantics, APIs and design choices; it does not independently validate the project implementation.

[1] Dataset Prasad A and Chandra S, PhiUSIIL Phishing URL Website, UCI Machine Learning Repository, 2024. CC BY 4.0.
https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset
[2] Grouped evaluation scikit-learn GroupShuffleSplit reference.
https://scikit-learn.org/stable/modules/generated/sklearn.model_selection.GroupShuffleSplit.html
[3] Calibration scikit-learn Probability calibration guide.
https://scikit-learn.org/stable/modules/calibration.html
[4] VirusTotal Get a URL report API reference.
https://docs.virustotal.com/reference/url-info
[5] URLhaus Community API documentation and authentication requirements.
https://urlhaus-api.abuse.ch/
[6] SSRF OWASP Server Side Request Forgery Prevention Cheat Sheet.
https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
[7] DNS Google Public DNS JSON API documentation.
https://developers.google.com/speed/public-dns/docs/doh/json
[8] Containers FastAPI in Containers deployment guide.
https://fastapi.tiangolo.com/deployment/docker/
[9] Domain boundaries Public Suffix List, including private suffix rules; MPL 2.0.
https://publicsuffix.org/list/
[10] Google discovery Build and submit a sitemap.
https://developers.google.com/search/docs/crawling-indexing/sitemaps/build-sitemap
[11] Google indexing Ask Google to recrawl your URLs.
https://developers.google.com/search/docs/crawling-indexing/ask-google-to-recrawl
Documentation checked on 13 September 2026. Current provider terms, quotas, package versions and cloud pricing should be reviewed before an externally shared deployment. No external credentials are included in the source package.
