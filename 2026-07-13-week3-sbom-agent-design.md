# Week 3 Design: SBOM/Image Ingestion, Matching Upgrade, Model Comparison, XAI, Agent Triage, Tests

**Date:** 2026-07-13
**Status:** Approved for implementation
**Scope:** Entire remaining architecture from the Week 1 diagram, built in one session (no Week 4 buildout planned — Week 4 is documentation of this work).

## Why

Week 2 delivered a purl→CPE matching engine and a baseline classifier, but:
1. The project brief's actual input (SBOMs / container images) still isn't built — Week 2 ran against `uv.lock` only.
2. The classifier is a toy: 28 hand-labeled pairs, labeled by the same person who wrote the labeling rule, keyword-counting features.
3. Nothing is testable in isolation — all logic lives in notebook cells.
4. The Week 1 architecture diagram's "Parser & Normalizer" and "Local NVD Cache" boxes were never built; matching still uses a raw wildcard-vendor query against live NVD.
5. The project computes a confidence score and stops — no component actually *acts* on it. It's a pipeline, not yet an agent.

This design closes all five gaps in one build.

## Architecture

Mapped against the Week 1 diagram, updated status:

| Stage | Module | This week |
|---|---|---|
| SBOM file / Container image | `sbom.py`, `image_scan.py` | Built |
| Parser & Normalizer | `sbom.py`/`image_scan.py` + `normalize.py` | Built |
| Unified Component List | `schema.py` | Unchanged (exists since Week 1/2) |
| Local NVD Cache + Sync Service | `nvd_cache.py` | Built |
| Matching Engine (CPE + purl→CPE mapping) | `matching.py`, `normalize.py`, `osv.py` | Upgraded — real mapping via CPE Dictionary (not wildcard-only), plus OSV.dev as an evaluation oracle for the matching engine and a PyPI/npm-only supplementary detection path |
| Enrichment (CVSS, CWE, KEV) | `nvd_client.py`, `kev.py` | KEV added; CVSS/CWE unchanged |
| Agent / triage layer | `agent.py` | Built — new |
| Report output | `report.py` | Built — JSON + HTML |
| LLM reporting layer | — | Deferred (local datalab-hosted model, future work; `agent.py`'s `ScanResult` output is designed to feed it later without rework) |

## Package layout

```
it_security_agent/
  __init__.py
  nvd_client.py     # nvd_get, fetch_all_pages — CVE endpoint (from Week 1/2, moved not rewritten)
  nvd_cache.py       # SQLite-backed local cache: sync_full(), sync_incremental(), query helpers
  cpe_dictionary.py  # NVD CPE Dictionary API client + local cache table
  schema.py          # Component dataclass/schema + builders (from Week 1/2)
  sbom.py            # CycloneDX + SPDX parsers -> list[Component]
  image_scan.py      # Syft subprocess wrapper (image -> CycloneDX) -> sbom.py
  normalize.py        # purl/name -> CPE vendor mapping via cpe_dictionary.py
  matching.py         # version_applies, name_variants, candidate matching (from Week 2, using normalize.py + nvd_cache.py instead of live wildcard queries)
  kev.py              # CISA KEV feed fetch + cache + lookup
  osv.py               # OSV.dev client: exact (ecosystem, name, version) -> vulns, cached in nvd_cache.db
  labeling.py          # builds the training-label dataset from cpe_dictionary.py + osv.py (ground truth, not hand labels)
  model.py             # feature engineering + LogisticRegression + RandomForest training/scoring
  explain.py           # SHAP wrappers for both models
  agent.py             # orchestrator: source -> parse -> normalize -> match -> score -> KEV -> triage policy -> ScanResult
  report.py            # ScanResult -> JSON file + HTML file
tests/
  test_schema.py, test_sbom.py, test_image_scan.py, test_normalize.py,
  test_matching.py, test_nvd_cache.py, test_kev.py, test_osv.py, test_labeling.py,
  test_model.py, test_explain.py, test_agent.py, test_report.py
notebooks/
  week3_agent.ipynb   # imports from it_security_agent; presentation surface only
```

`nvd_client.py` and `schema.py` are lifted from the existing notebooks with minimal changes (extracted, not rewritten) — this preserves Week 1/2's validated logic rather than risking regressions by rewriting it.

## Component details

### SBOM ingestion (`sbom.py`)
- **CycloneDX JSON**: read `components[]`, each with a `purl` field directly — parse ecosystem from the purl scheme (`pkg:pypi/...` → PyPI, `pkg:npm/...` → npm, etc.), map straight onto the existing `Component` schema.
- **SPDX JSON**: read `packages[]`. Not all packages carry a purl — only look in `externalRefs` where `referenceType == "purl"`. Packages without a purl external ref are skipped and counted (reported as `unparsed_packages` in the result, not silently dropped) since there's no reliable ecosystem/version-scheme to assume otherwise.
- Both parsers return `list[Component]`, identical output shape regardless of input format — everything downstream is format-agnostic.

### Container image scanning (`image_scan.py`)
- Requires the `syft` CLI (not currently installed — installed as part of this build) and the Docker daemon (confirmed present).
- `scan_image(image_ref: str) -> list[Component]`: runs `syft <image_ref> -o cyclonedx-json`, captures stdout, parses it with `sbom.py`'s CycloneDX parser. No custom image/layer inspection code — Syft is the industry-standard tool for this and reinventing it isn't the point of this project.
- Failure handling: if Syft isn't installed or the image can't be pulled, raises a clear error rather than silently returning an empty component list (an empty scan result must never be mistaken for "no vulnerabilities found").

### Local NVD Cache + Sync (`nvd_cache.py`)
- SQLite file (`nvd_cache.db`, gitignored — same treatment as `.env`), stdlib `sqlite3`, no new dependency.
- Table `cves`: raw NVD CVE JSON blob keyed by CVE ID, plus indexed columns (`published`, `last_modified`) for incremental sync.
- `sync_full()`: paginates the entire NVD CVE catalog using Week 1/2's `fetch_all_pages`, writes to `cves`. ~3 minutes with the API key (measured in Week 1).
- `sync_incremental(since: datetime)`: same, filtered by NVD's `lastModStartDate`/`lastModEndDate` params.
- `query_by_cpe_name(name: str) -> list[dict]`: replaces Week 2's live per-package NVD call — matching now reads from this local cache.
- One-time setup cost (the full sync) happens once per session/demo, not once per component — this is the fix for Week 2's explicitly flagged "doesn't scale" problem.

### CPE Dictionary + normalization (`cpe_dictionary.py`, `normalize.py`)
- `cpe_dictionary.py`: client for NVD's separate CPE Dictionary endpoint (`/rest/json/cpes/2.0`), queried by `keywordSearch=<package name>`. Cached locally in its own SQLite table (same `nvd_cache.db` file), since dictionary entries change far less often than CVEs.
- `normalize.py`: `resolve_vendor(package_name: str, ecosystem: str) -> list[VendorCandidate]`. For a given package, pulls CPE Dictionary candidates and attaches raw signals to each — it does **not** combine them into its own opaque score. Deciding "is this a real match" is `model.py`'s job alone; `normalize.py` only gathers evidence, so there's never a question of which of two competing scores wins.
  - `vendor_equals_package` and ecosystem-consistent keyword signals, reused from Week 2's `PY_KEYWORDS`/`JS_KEYWORDS` approach (as originally spec'd),
  - **`name_similarity`**: `rapidfuzz` token-set ratio between the package name and each candidate's CPE product string — in-process, no network call, negligible cost,
  - **`registry_overlap`**: does the candidate CPE's reference URLs share a domain with the package's PyPI/npm registry homepage or repo URL? Computed the same way at training time and scan time.
  - This is the purl→CPE mapping the architecture always called for — Week 2's wildcard match was a placeholder for this.
- **`registry_overlap` is label-only, never a model feature.** `labeling.py` uses it as the sole rule for ground truth ("real vendor" = registry URL overlap found). If it were also fed into `model.py`'s feature set, the model would trivially learn "predict real match whenever `registry_overlap` is true" — that's memorizing its own label, not learning to match, and would make held-out accuracy look better than the model actually is. So: `registry_overlap` builds the label and is available to `agent.py`'s triage policy as an independent corroboration signal at scan time (see below), but `model.py`'s `FEATURES` list never includes it.
- **Cost control on the registry cross-reference**: the only piece here that's a real network call.
  - *Caching*: results are stored in a `registry_cache` table in `nvd_cache.db`, keyed by `(ecosystem, package_name)`, with a long TTL (registry homepage/repo URLs rarely change) — first lookup ever for a package pays the network cost, every scan after that is a local read.
  - *Dedup*: looked up once per distinct package name per scan, same rule `matching.py` already applies to NVD queries (Week 2), not once per component instance.
  - *Fallback*: only applies to ecosystems with a public registry (PyPI, npm). For ecosystems without one (e.g. Debian/Alpine OS packages), the feature returns "unknown" rather than erroring — consistent with how any other unavailable feature is handled.
- `matching.py` calls `normalize.py` first to narrow candidate vendors *before* querying the cache, instead of pulling every same-named CVE regardless of vendor and filtering after the fact.

### OSV.dev cross-referencing (`osv.py`)
- OSV.dev indexes vulnerabilities directly by `(ecosystem, package name, version)` — no CPE, no vendor guessing, free API, no auth.
- `osv.py`: `query(ecosystem: str, name: str, version: str) -> list[OsvVuln]`, calling OSV's public `POST /v1/query` endpoint. Results cached in an `osv_cache` table in `nvd_cache.db`, same pattern as the NVD/registry caches, keyed by `(ecosystem, name, version)`. **Only called for `ecosystem in {"PyPI", "npm"}`** — OSV has no coverage for OS-level ecosystems (Debian, Alpine), which is exactly what container image scans mostly surface, so calling it there would just be a wasted network call with a guaranteed-empty result. `osv.py` returns `[]` immediately for any other ecosystem, no request made.
- **Two roles, reordered by which one actually earns its keep:**
  1. **Evaluation oracle for the matching engine (primary role)**: after `model.py` produces confirmed findings for PyPI/npm components, a separate evaluation step checks what fraction OSV also reports for the exact same `(package, version)`. This agreement rate is a genuine, independent accuracy measurement for the whole CPE+ML matching pipeline — not just "we added a database," but "X% of our PyPI/npm findings are corroborated by an independent ecosystem-native source." Disagreements (matching-engine finding with no OSV corroboration, or vice versa) get folded into Section 7/8's risk and fairness analysis as concrete cases, the same way Week 2 used the `babel`/`jupyter`/`json5`/`jsonpointer` collisions.
  2. **Live corroboration signal (secondary role, PyPI/npm only)**: at scan time, `agent.py` also checks OSV for the component being scanned and uses agreement as a triage input (see below) — but this is a bonus on top of role 1, not the reason OSV is in the design, and it contributes nothing for OS-ecosystem components (documented, not silently glossed over).

### KEV enrichment (`kev.py`)
- Downloads CISA's public KEV JSON feed (no auth), caches locally, refreshed on each `sync_full()`/`sync_incremental()` call.
- `is_kev(cve_id: str) -> KevEntry | None` — used by `agent.py`'s triage policy to escalate findings.

### Training data + models (`labeling.py`, `model.py`)
- **Ground truth, not hand labels**: for each package name in the component universe, `labeling.py` pulls CPE Dictionary candidates (via `cpe_dictionary.py`) and cross-references each candidate's reference URLs against the package's registry metadata (PyPI `project_urls`/`home_page` for PyPI packages, npm registry `repository`/`homepage` for npm) — a URL/domain match is a documented, auditable rule for "real vendor," not a manual judgment call, and it's the **sole** label rule (see the leakage note in `normalize.py` above for why OSV isn't also used to define the label — it's used downstream instead, as the evaluation oracle described in the OSV section). This removes Week 2's circularity problem (the same person writing the labeling rule and applying it by eye) and scales far beyond 20 hand-vetted packages, since it runs automatically over every component.
- **Features** (`model.py`'s `FEATURES` list): `vendor_equals_package`, `name_similarity`, `py_keyword_score`, `js_keyword_score`, `keyword_alignment`, `ecosystem_pypi` — everything from `normalize.py`'s signals *except* `registry_overlap`, which is label-only.
- **Two models**, both trained on the same scaled-up dataset, both evaluated with Week 2's risk-weighted metric (FN×10 + FP×1) and fairness split (PyPI vs. npm):
  - `LogisticRegression` — kept as the interpretable baseline, direct continuation of Week 2.
  - `RandomForestClassifier` — comparison model, satisfies "analyze your models" (plural).
- **Training is an offline step, not part of a live scan.** `model.py` exposes a `train_and_compare(dataset) -> (results, winning_model_name)` entrypoint that pulls CPE Dictionary + registry data once, trains both models, and picks the risk-weighted winner. The winning model is persisted to disk (`joblib`) so `agent.scan()` just loads and scores — it never retrains or re-pulls training data mid-scan. This matters for the same reason the local NVD cache does: a scan needs to be fast and demo-safe, not dependent on a fresh multi-minute training run every time.
- **Confidence threshold**: rather than a hardcoded cutoff, the threshold `agent.py` uses to call a match "high confidence" is chosen during training by sweeping candidate thresholds on the held-out test set and picking the one that minimizes the same FN×10 + FP×1 risk score used to pick the winning model — computed once, persisted alongside the model, not a magic number. This directly extends Week 2's risk-analysis framing instead of introducing an unrelated ad hoc value.

### XAI (`explain.py`)
- `LogisticRegression` → SHAP `LinearExplainer` (extends Week 2's coefficient plot to per-instance explanations).
- `RandomForestClassifier` → SHAP `TreeExplainer` (exact, fast, no sampling approximation needed).
- `explain_match(model, features) -> Explanation` returns per-feature SHAP values; `agent.py` attaches this to every review-queue finding so a human reviewer sees *why* the agent is unsure, not just a bare confidence number.

### Agent orchestration (`agent.py`)
- `scan(source: SBOMSource | ImageSource | LockfileSource) -> ScanResult`.
- Pipeline: parse → normalize → match against the local cache via `matching.py`/`normalize.py`, scored for confidence by the persisted winning model → for PyPI/npm components only, also check `osv.py` as a corroboration signal → check KEV → apply triage policy.
- Every NVD/CPE-path finding carries a `corroboration: "osv_agrees" | "osv_disagrees" | "not_checked"` field (`"not_checked"` for non-PyPI/npm components, where OSV was never queried — distinct from `"osv_disagrees"`, which means OSV *was* checked and found nothing).
- Triage policy:
  - High model confidence (≥ the persisted, risk-minimizing threshold) → confirmed, regardless of corroboration (the model is the decision-maker; corroboration is reported alongside, not a gate)
  - Low model confidence, `corroboration == "osv_agrees"` → confirmed — independent ecosystem-native agreement overrides a shaky CPE-vendor match
  - Low model confidence, `corroboration` is `"osv_disagrees"` or `"not_checked"` → review-queue finding with SHAP explanation attached, noting the corroboration status so the reviewer knows whether "no OSV support" means OSV actively disagrees or was simply never in a position to help
  - Any confirmed finding with a KEV hit → moved to escalated instead of confirmed, placed at the top of the report
  - NVD/CPE candidate whose version range doesn't apply → rejected. **Rejected findings are still included in the report**, in a collapsed/appendix section — a security tool that silently discards evidence, even low-value evidence, is worse than one that shows it deprioritized.
- `ScanResult` is a plain structured object (confirmed / escalated / review-queue / rejected, each with full finding + explanation + corroboration data) — the seam a future LLM reporting layer consumes without needing `agent.py` reworked.

### Report output (`report.py`)
- `write_report(result: ScanResult, out_dir: Path) -> None` emits:
  - `findings.json` — full structured `ScanResult`, machine-readable.
  - `report.html` — severity-colour-coded table (plain `pandas.DataFrame.style`/`to_html`, no new templating dependency): escalated (KEV) at the very top, then confirmed findings, then the human-review queue with its SHAP explanations and corroboration status, then rejected matches in a collapsed/appendix section (not omitted).
  - An **OSV agreement summary** (from the evaluation-oracle role above): for PyPI/npm confirmed findings, what fraction are OSV-corroborated — the accuracy evidence for the matching engine, surfaced in the report rather than buried in a notebook cell.

## Testing (target: 80% coverage on `it_security_agent/`)

- `pytest` + `pytest-cov`, added to `pyproject.toml` as dev dependencies.
- Network calls (`nvd_client`, `cpe_dictionary`, `kev`, `osv`, and the registry lookups in `normalize.py`) mocked via `unittest.mock` / `responses` — no live NVD/CISA/OSV/registry calls in the test suite, so tests are fast and don't burn rate limit.
- `test_osv.py` asserts: caching/dedup behavior (second lookup for the same key hits the cache, not the network), and that non-PyPI/npm ecosystems short-circuit to `[]` with zero network calls.
- The registry-cache tests in `test_normalize.py` assert caching/dedup and the fallback for registry-less ecosystems, and assert `registry_overlap` never appears in `model.py`'s `FEATURES` (a regression test for the leakage fix).
- `test_model.py` includes a dedicated leakage-regression test: train on a synthetic dataset where `registry_overlap` would trivially predict the label, confirm the trained model's feature set excludes it and accuracy isn't suspiciously perfect as a result.
- `test_model.py` also asserts `train_and_compare` persists a model file and that `agent.py` loads it rather than calling `train_and_compare` itself (a regression test for the offline-training fix).
- `test_agent.py` covers all four `corroboration` states (`osv_agrees`, `osv_disagrees`, `not_checked` for both non-PyPI/npm and OSV-checked-but-empty cases) against fully mocked lower layers, in addition to the KEV-escalation and rejected-version-range branches, and asserts rejected findings are present in `ScanResult.rejected` (not dropped).
- `nvd_cache.py` tested against an in-memory SQLite (`:memory:`), not the real cache file.
- `image_scan.py` tested by mocking the `syft` subprocess call (patch `subprocess.run`), plus one fixture CycloneDX JSON blob representing real Syft output, so the parsing path is exercised without requiring Docker/Syft in CI.
- `sbom.py` tested against small hand-written CycloneDX and SPDX fixture files, including the SPDX no-purl skip case.
- `matching.py`/`normalize.py` reuse Week 2's known collision cases (`babel`, `jupyter`, `json5`, `jsonpointer`) as regression tests — they must still be identified as collisions, not silently "fixed" by the new normalization layer without evidence.
- `model.py`/`explain.py` tested on a small synthetic labeled set (not live CPE Dictionary calls) to keep tests deterministic.
- `agent.py` tested end-to-end against fully mocked lower layers, asserting the triage policy's four buckets (confirmed / escalated / review-queue / rejected) each fire correctly given controlled inputs.

## Explicitly out of scope

- LLM-assisted reporting layer (deferred to the future local datalab-hosted model; `ScanResult` is the designed integration seam).
- Any change to the EU regulatory analysis from Week 1 (still accurate; the AI Act discussion already anticipated this deferral).
