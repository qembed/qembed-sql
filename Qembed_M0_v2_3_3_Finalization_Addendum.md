# Qembed Object Runtime — M0 v2.3.3
## Finalization Addendum / Normative Consolidation (r3)

**Статус:** архитектурная база заморожена для начала M1a. SQL (r3) — clean-install candidate, не production-certified до прохождения T-01…T-64 на матрице PostgreSQL 15/16 + pgvector ≥0.8.0. Редакция r3 исправляет шесть дефектов SQL, найденных поведенческим прогоном (§10); архитектура не менялась.

### 1. Приоритет документов
1. Настоящий addendum v2.3.3 — нормативные уточнения и решения RT-039…RT-047.
2. `qembed_m0_v2_3_3_clean_schema.sql` — clean install only; не upgrade migration.
3. `ADR_RT-039_to_RT-047.md` — rationale и release gates.
4. `acceptance_T-01_to_T-64.md` — обязательные acceptance assertions.
5. Исходная Specification M0 v2.2 — сохраняет неизменённые доменные/API/roadmap разделы. При конфликте применять addendum.
6. v2.3.2 errata и correction pack — исходные предложения/контекст, не более приоритетные, чем этот addendum.

### 2. Архитектура — freeze
Модульный монолит Rust, stateless workers, Actix Web, SQLx, PostgreSQL 15+, pgvector ≥0.8.0. Ровно шесть crates: `qembed-domain`, `qembed-store`, `qembed-llm`, `qembed-tools`, `qembed-runtime`, `qembed-api`. `qembed-eval` — bin-target внутри `qembed-runtime`.

- `qembed-domain`: IDs, domain entities, `Scope`, `Principal`, `ModelCapabilities`, `ChatModelRef`, `TokenizerKind`, ports (`PrincipalAuthenticator`, `ExecutionStore`), policy contracts, `AllowedCommand` mint boundary.
- `qembed-store`: SQLx repositories, transaction boundaries, tenant context, CAS/fencing, migrations.
- `qembed-llm`: provider adapters, capability negotiation, structured output.
- `qembed-tools`: registry adapter, SSRF resolver, pinned endpoint, executor/reconciler.
- `qembed-runtime`: orchestration, budget, retrieval/context assembly, verification, worker lifecycle, eval binary.
- `qembed-api`: Actix handlers, auth, DTO/OpenAPI; depends only on domain + runtime. Composition root wires concrete adapters.

Dependency direction: adapters depend on domain ports; domain depends on no adapter. Runtime coordinates domain and ports; API calls runtime. No seventh crate without ADR.

### 3. Capability and command identity
`AllowedCommand` fields private; it is `!Clone`, `!Serialize`, `!Deserialize`, `!Default`; only Authorizer can mint it. `ToolExecutor` accepts capability + `ExecutionLease` + `PinnedEndpoint`, never `ProposedAction`, arbitrary JSON, `tool_id` alone, or a raw URL. `command_id = UUIDv5(invocation_id, step_index, action_hash)`; uniqueness `(tenant_id, command_id)`. Stable upstream idempotency key survives process crash.

### 4. Transactional invariants
- All repositories accept `&Scope`; set `SET LOCAL app.tenant_id` inside each transaction. Missing/empty scope fails closed.
- Critical event insert and domain state transition share one DB transaction. Outbox is written atomically; delivery is at-least-once and consumers deduplicate. `EventSink::emit` is for non-critical events only.
- Invocation and tool execution use independent leases/fencing tokens. All writes use CAS on tenant/id/token/version. External network calls never occur inside SQL transactions.
- `Unknown` is not retryable. Reconciliation is required unless upstream idempotency is contractually proven and stable key reused.
- Effective budget is `min(snapshot limit, live object budget)`. Reservation settlement is atomic. Reserve estimate is `ceil(bytes/3)*1.3` with final rounding; provider-reported usage and safety margin remain authoritative.
- PII-safe event payloads use allowlisted schemas; `pii_class='none'` alone is insufficient. Low-entropy immutable-log hashes use tenant-scoped HMAC, subject to LGPD/GDPR review.

### 5. Snapshot, knowledge, vector
Snapshot `canonical_json BYTEA` is source of truth; hash is SHA-256 of bytes. Rust verifies RFC 8785 JCS, duplicate keys, NaN/Infinity, UTF-8 and schema version. JSONB columns are derived projections and DB guard enforces equality. Dynamic usage/reservations/kill-switch state are not part of immutable content hash and are rechecked at execution.

Knowledge commit locks `knowledge_revisions`, checks staged docs are fully indexed for required models, increments revision, closes previous doc interval, opens new doc+chunk intervals, writes knowledge event/outbox and commits atomically. Candidate revision filter is applied before vector top-k. Retrieval must pin revision. GC respects active invocation pins and reproducibility window.

pgvector: similarity for IP metric is `-dist`; `1-dist` is cosine-only. L2 uses explicit normalization. For dimensions >2000 use `halfvec` where supported by selected index config. HNSW partial indexes are created by migrator using `CREATE INDEX CONCURRENTLY` outside transaction. `cargo sqlx prepare --check` precedes `SQLX_OFFLINE=true cargo check`.

### 6. Security and lifecycle
`qembed_definer` NOLOGIN/NOSUPERUSER/NOBYPASSRLS, fixed search_path, revoked PUBLIC execute, narrow function surface and grants. Dispatcher only accesses outbox/events. Runtime cannot mutate platform kill switch. RLS audit classifies every table as tenant-owned, restricted-global, global registry, or privileged-only and fails closed on omissions.

Verified memory is a new Owner-authored row superseding candidate; candidate UPDATE promotion is forbidden. Normal retention does not purge append-only events, decisions, snapshots. Tenant offboarding/erasure is a separate audited privileged workflow (RT-046).

SSRF: resolve complete A+AAAA set; reject mixed/forbidden answers; pinned connect to checked IP; preserve original TLS SNI/hostname validation; disable automatic redirects or fully revalidate each redirect; ignore proxy environment variables; enforce egress deny rules.

### 7. M1a implementation boundary
**Build now (walking skeleton, RT-047):** workspace + six crates; IDs/Scope/Principal; SQLx transaction wrapper and RLS scope; auth/principal (session token); object/version/snapshot repositories (create → publish); migration audit; event/outbox (write only, dispatcher is M1b); **begin invocation** (idempotency key reserved first, then atomically invocation + pinned snapshot + knowledge_revision + event + outbox); **mock ChatProvider** with deterministic response and reserve heuristic; GET invocation and cancellation contract; minimal OwnerAPI (create object/version, publish, invoke, inspect invocation); structured error mapping; health/readiness. CI: all tests marked M1a in `acceptance_T-01_to_T-64.md`.

**Do not enable yet:** external write tools, public tenant onboarding at scale, production retention/offboarding, knowledge ingestion/retrieval until their stage gates pass. Tool enablement additionally requires T-07, T-22, T-38, T-46, T-47, T-52, T-59, T-64.

### 8. M1a Definition of Done
1. `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace` pass.
2. SQLx offline metadata current; `cargo sqlx prepare --check` passes.
3. Clean migrations apply on PostgreSQL 15 and 16 with pgvector ≥0.8.0.
4. Runtime role cannot bypass RLS; missing tenant scope fails closed; tenant/object/caller composite FK tests pass.
5. `AllowedCommand` compile-fail tests pass.
6. Event+outbox atomicity and idempotent delivery tests pass.
7. Walking-skeleton scenario passes on PostgreSQL with the mock provider: create → publish → invoke → retrieve result; repeated idempotency key creates exactly one invocation; cross-tenant access denied; published versions and snapshots immutable.
8. All tests marked M1a in the acceptance plan pass: T-01, T-02, T-04, T-06, T-09, T-11, T-12, T-14, T-19, T-20, T-21, T-27, T-29, T-30, T-36, T-37, T-41, T-42, T-49, T-50, T-51, T-53, T-54, T-55, T-57, T-60, T-61, T-63. (DB-level parts only where the stage says so.)
9. No unresolved critical/high security findings; all waivers carry owner, rationale, expiry and ADR.

### 9. Known limits of this package
Execution evidence (r3): clean schema r3 applied **without** the smoke flag on PostgreSQL 16 + pgvector 0.8.0 (собран из тега v0.8.0). Поведенческий smoke-набор (`tests/`, 103 проверки под ролями `qembed_runtime` / `qembed_retention` / `qembed_dispatcher` / `qembed_admin` через `SET ROLE`, плюс реальный логин для проверки `SET ROLE qembed_definer`) проходит 103/103; тот же набор на SQL r1 даёт 12 падений (6 дефектов R3-01…R3-06). Это smoke evidence, не сертификация совместимости и не замена T-01…T-64 в CI.

Not executed: PostgreSQL 15; pgvector gate на версии <0.8.0 без флага (в r3 не повторялся); остальные тесты T-01…T-64 (в т.ч. реальная конкурентность/fencing, T-05/T-16 параллельные резервы, T-44 GC), Rust JCS corpus, SSRF corpus, failure-injection matrix, upgrade migration. Это явные release gates.

Known schema gaps (не исправлялись в r3, нужны решения):
- RT-046: у `tenants` нет lifecycle-состояния и legal hold (Offboarding/Erased, T-62) — pre-production deliverable.
- GC знаний (M2): ни одна роль не имеет `DELETE` на `knowledge_documents`/`knowledge_chunks`; GC с учётом pinned revisions (T-44) требует отдельной привилегированной функции. Зафиксировано в smoke-наборе как `KNOWN GAP`.
- Инвариант «Verified immutable» в БД допускает единственное изменение — `supersedes_id → NULL` как референциальное действие при удалении исходного candidate (R3-02); ссылка «Verified → candidate» после удаления candidate утрачивается by design.
- Нет DB-guard на переходы `object_invocations` (terminal immutability / монотонность `fencing_token`): остаётся обязанностью репозитория (CAS) по RT-040; рекомендуется добавить guard до M1b.

### 10. Changes in r3
1. **R3-01 (critical).** Повторная публикация версии была невозможна: немедленная проверка «нельзя supersede текущую опубликованную» плюс уникальный индекс `uq_ov_one_published` не оставляли допустимого порядка UPDATE. Проверка перенесена в deferred constraint trigger (COMMIT). Порядок: supersede старой → publish новой → перенос `published_version_id`.
2. **R3-02.** Удаление candidate, на который ссылается Verified-запись (`ON DELETE SET NULL (supersedes_id)`), падало на «verified memory is immutable» (в т.ч. `retention_purge('memories')`). Разрешено только `supersedes_id → NULL` внутри RI-триггера (`pg_trigger_depth() > 1`); прямой UPDATE остаётся запрещён.
3. **R3-03.** `retention_purge('tool_executions')` падал на терминальных строках. Разрешено только обнуление `output`/`output_expires_at` и только от `qembed_definer`; runtime не может.
4. **R3-04.** `sweep_expired_reservations` не освобождал `caller_usage_counters.reserved_tokens` (утечка per-caller лимита). Добавлено освобождение; definer получил `UPDATE` на эту таблицу.
5. **R3-05 (security).** `Unknown → Succeeded/Failed` обходил reconciliation при `reconciliation_state = NULL` (`NULL NOT IN (...)` даёт NULL). Исправлено; дополнительно статус обязан соответствовать `confirmed_succeeded`/`confirmed_failed`.
6. **R3-06.** `qembed_admin` не мог создать объект: триггер `objects_init_knowledge` пишет в `knowledge_revisions` с правами вызывающего. Добавлены `SELECT, INSERT` и узкие политики для admin (INSERT только `current_revision = 0`).
7. Добавлены каталог `tests/` (smoke-набор + `run_smoke.sh`), раздел «R3 regression» в acceptance-плане, ADR RT-048.
8. **Статус B-01…B-09:** список замечаний B-01…B-09 и отчёт r2 в присланный архив не входили; соответствие R3-01…R3-06 этим номерам не установлено, закрытие B-01…B-09 r3 **не заявляет**.

### 11. Changes in r1
1. pgvector ≥0.8.0 gate added to the SQL (fail-fast).
2. M1a scope aligned with v2.3.1 walking-skeleton DoD (RT-047); M1a DoD test list now equals the set of M1a-stage tests in the acceptance plan.
3. Acceptance stages corrected: T-03→M3, T-06/T-14→M1a, T-24→M1b; T-04/T-21/T-27 split DB-level/app path.
4. Tool-enablement gate list deduplicated.
5. README manifest and validation status aligned with actual files; consolidated PDF re-rendered (Cyrillic and markdown were not rendered on pages 1–2).
