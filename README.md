# Qembed M0 v2.3.3 (r4) Finalization Pack

## Files
- `qembed_m0_v2_3_3_clean_schema.sql` — clean-install candidate r4 (PG 15+, pgvector ≥0.8.0 gate). NOT an upgrade migration. (r4 adds T-27 Caller-level memory RLS; r4 validation pending).
- `Qembed_M0_v2_3_3_Finalization_Addendum.md` — нормативный addendum (r3); §10 — изменения r3.
- `ADR_RT-039_to_RT-047.md` — ADR RT-039…RT-048 (including r3 corrections).\n- `ADR_RT-049_Caller_Memory_RLS.md` — Caller-level episodic memory isolation decision (r4).
- `ADR_RUST-044_Identical_Content_Version_Deduplication.md` — approved application contract for identical canonical content; no DDL change.
- `acceptance_T-01_to_T-64.md` — T-01…T-64 + раздел «R3 regression» (R3-01…R3-06) + «Smoke evidence r3».
- `tests/` — поведенческий smoke-набор (`run_smoke.sh`, SQL 00–40, включая 17_tenant_rls.sql и 24_caller_memory_rls.sql; `05_rust_physical_contract.sql` — контракт физических имён/ключей Rust). Нужны PostgreSQL superuser, pgvector ≥0.8.0, роль `qembed_migrator`.
- `Qembed_Object_Runtime_M0_v2_3_3_FINAL_TZ.pdf`, `Qembed_M0_v2_3_3_Diagrams.pdf` — **не пересобирались, содержимое r1**. Нормативны `.md` (addendum r3 имеет приоритет по §1); PDF с addendum r1 устарел в части §9–§10.

## Что исправлено в r3 (SQL)
1. R3-01 — повторная публикация версии была невозможна (deferred-проверка pointer).
2. R3-02 — удаление candidate, заменённого Verified, падало на immutability.
3. R3-03 — `retention_purge('tool_executions')` падал на терминальных строках.
4. R3-04 — sweeper не освобождал `caller_usage_counters`.
5. R3-05 — обход reconciliation `Unknown → терминал` через NULL.
6. R3-06 — `qembed_admin` не мог создать объект (нет доступа к `knowledge_revisions`).

## Validation status
- r3 baseline: PostgreSQL 16 + pgvector 0.8.0, smoke-набор 103/103 (r1 на том же наборе: 12 падений).\n- r4: caller-level RLS и regression tests добавлены; PostgreSQL execution ещё не выполнен. r3 evidence не подтверждает r4.
- NOT executed: PostgreSQL 15, большинство T-01…T-64, конкурентность/fencing, Rust JCS, SSRF, failure-injection, upgrade. Заявления о production-готовности нет.
- **B-01…B-09:** список замечаний и отчёт r2 в присланный архив не входили; r3 не утверждает закрытие B-01…B-09 и не сопоставляет с ними R3-01…R3-06. Пришлите список — сверю.

## Open items (r4 candidate)
- RT-046 tenant lifecycle / legal hold (T-62).
- GC знаний: нет `DELETE`-пути (M2, T-44).
- T-27 SQL implementation is in r4; its PostgreSQL smoke execution is pending.\n- Concurrent multi-session tests for Invocation fencing remain outstanding.

## Start coding
Архитектура заморожена для M1a (addendum §7–§8, RT-047). SQL — candidate до прохождения T-01…T-64 на PG 15/16 × pgvector ≥0.8.0. Внешние write-tools не включать до T-07, T-22, T-38, T-46, T-47, T-52, T-59, T-64.
Порядок публикации версии в репозитории: supersede старой → publish новой → перенос `published_version_id` в одной транзакции.

## Rust-compat remediation (backlog `sql_remediation_backlog_rust_compatibility.md`)
Rust-репозиторий — неизменяемый источник контрактов; адаптируется только SQL.

| Audit | Статус |
|---|---|
| AUDIT-001 физические имена/ключи | **применён** (этот патч) |
| AUDIT-002 owner authentication | **применён** (`owner_principals`, `owner_credentials`) |
| AUDIT-003 object state / Draft versions | **применён** (lowercase state, multiple Draft versions) |
| AUDIT-004 snapshots | **применён** (canonical bytes, hash, JSONB projection, immutability) |
| AUDIT-005 events/outbox | **применён** (Rust columns, append-only events, delivery timestamp) |
| AUDIT-006 tenant RLS | **применён** (ENABLE/FORCE, actual-table isolation tests, pre-auth exception) |
| AUDIT-007 ObjectVersion / object lifecycle | **применён** (строгие переходы статусов и неизменяемая identity) |
| AUDIT-008 composite tenant FKs | **применён** (каталожная проверка и cross-tenant negative tests) |
| AUDIT-009 Invocation lifecycle/fencing | **применён** (state machine, optimistic version и lease reclaim guard) |
| AUDIT-010 SECURITY DEFINER hardening | **применён** (safe search_path, grants и injection regression tests) |

### AUDIT-001: единый путь установки (миграционная линия)
- Единственный источник DDL — `qembed_m0_v2_3_3_clean_schema.sql` (fresh install, один раз, под `qembed_migrator`).
- Rust SQLx-миграции `20261118000000…03_*.sql` **не применяются поверх** этой схемы: они создают те же таблицы
  (`objects`, `object_versions`, `snapshots`, `events`, `outbox_messages`) и дали бы конфликт. Rust migration runner
  явный (не запускается при подключении), поэтому на базе, установленной этим скриптом, его просто не вызывают.
- Физические имена и ключи пяти таблиц совпадают с Rust (проверяется `tests/05_rust_physical_contract.sql`):
  `objects(tenant_id, object_id)`, `object_versions(tenant_id, object_id, object_version_id)`,
  `snapshots(tenant_id, snapshot_id)`, `events(tenant_id, event_id)`, `outbox_messages(tenant_id, delivery_id)`.
- `objects.tenant_id` без FK на `tenants`: Rust-путь не создаёт строк `tenants`.
- Поля r3 в `object_versions` (`config`, `chat_model_ref`, `embedding_model_id`, `published_at`) — nullable-расширения.
- `retention_purge` принимает `'outbox_messages'` вместо `'outbox'`.

Основные Rust-compatibility аудиты AUDIT-001…010 завершены. Дальнейшие работы перечислены в разделе **Future work** ниже; они не меняют Rust-контракты без отдельного архитектурного решения.


### AUDIT-002: owner authentication
- Rust auth path использует таблицы `owner_principals` и `owner_credentials` (колонки/PK/FK/CHECK как в Rust-миграции).
  r3 `principals`/`callers`/`authenticate_principal` остаются отдельным будущим расширением и Rust-путём не используются.
- Pre-auth lookup идёт без tenant Scope, поэтому tenant-RLS на этих таблицах нет; доступ ограничен column-level grants:
  роль приложения (`qembed_runtime`) имеет только SELECT на колонки, которые читает Rust-запрос. Создание и отзыв
  credentials — `qembed_admin` (INSERT; для `owner_principals` UPDATE разрешён только по `disabled_at`, для `owner_credentials` — только отзыв через защищённый триггер; без DELETE). Revisit в AUDIT-006.
- `owner_credentials_active_lookup` — UNIQUE по `(tenant_id, token_hash) WHERE revoked_at IS NULL`: два активных
  credentials с одним digest в tenant невозможны. Digest и идентичность неизменяемы, отзыв необратим.


### AUDIT-003: object state and draft versions
- `objects.state` uses the Rust lowercase vocabulary (`draft`, `validating`, `active`, `suspended`, `archived`) and defaults to `draft`.
- The one-Draft-per-object partial unique index is removed. Multiple Draft versions may coexist; publication remains protected by the published-version uniqueness/pointer rules and the Rust repository's transactional publication path.
- Regression coverage checks the default, rejects the legacy uppercase state, and inserts two Draft versions for one object.


### AUDIT-004: immutable snapshots
- The physical columns now match the Rust migration: `canonical_json BYTEA NOT NULL`, `content_hash BYTEA NOT NULL` (32 bytes), and `json_projection JSONB NOT NULL`; r3-only projection payload columns are removed.
- `canonical_json` remains the exact RFC 8785 byte sequence and source of truth. `json_projection` is derived from those bytes and checked by a trigger (`23514`) on insert/update; it is never used to reconstruct the source.
- Snapshot UPDATE and DELETE are rejected with SQLSTATE `55000`, matching Rust integration tests.
- The database checks hash length, while Rust recomputes SHA-256 and validates JCS when reconstructing a snapshot. A database digest-equality CHECK is deliberately absent so corrupted persisted hashes are detected at the Rust read boundary, as tested by `snapshot_repository.rs`.
- Regression coverage is in `tests/15_snapshots.sql`, wired into `tests/run_smoke.sh`.


### AUDIT-005: events and outbox
- `events` and `outbox_messages` now use the exact Rust migration columns, defaults, primary/unique keys and tenant-consistent outbox FK.
- Event ordering uses `events_aggregate_order_idx`; events reject UPDATE/DELETE with SQLSTATE `55000`.
- Outbox delivery state is represented only by nullable `delivered_at`. The dispatcher can update that column, not event identity or payload.
- The pending index is `(created_at, delivery_id) WHERE delivered_at IS NULL`. Retention removes only delivered rows older than the cutoff; undelivered messages are retained.
- Regression coverage is in `tests/16_events_outbox.sql`; the Rust physical contract assertions and smoke runner include AUDIT-005.


### AUDIT-006: tenant RLS
- Every table with a required `tenant_id` is checked for ENABLE + FORCE ROW LEVEL SECURITY and the `qembed_runtime` tenant policy.
- Two-tenant regression tests exercise the actual Rust repository tables: `objects`, `object_versions`, `snapshots`, `events`, and `outbox_messages`. They verify reciprocal isolation, missing-scope behavior, and rejected cross-tenant writes.
- `owner_principals` and `owner_credentials` remain outside tenant RLS intentionally: Rust performs the credential lookup before a `Scope` exists. Their access remains limited to the exact pre-auth columns.
- Removed an obsolete r3 snapshot trigger that referenced projection columns no longer present in the Rust snapshot schema. The AUDIT-004 `snapshots_projection_guard` is the sole projection guard.
- Rust's `TenantTransaction` establishes `app.tenant_id` transaction-locally using a bound parameter. RLS enforces that trusted transaction context; it is not an independent defense against arbitrary SQL executed with the runtime database role, which must remain application-internal.
- Regression coverage is in `tests/17_tenant_rls.sql`, wired into `tests/run_smoke.sh`.


### AUDIT-007: ObjectVersion и object lifecycle guards
- ObjectVersion transitions соответствуют Rust domain: `draft → published → superseded`; обратные переходы и выход из terminal `superseded` запрещены.
- Version identity, `version_number` и `created_at` неизменяемы; Published content нельзя менять при supersede. Удалять можно только Draft.
- Object state transitions соответствуют `ObjectState::can_transition_to`: Draft→Validating, Validating→Draft/Active, Active↔Suspended, Active/Suspended→Archived. Archived terminal.
- Pointer-only updates остаются допустимыми для атомарной публикации/замены; существующий pointer guard проверяет принадлежность и Published status целевой версии.
- Regression coverage: `tests/18_object_lifecycle.sql`, подключён в smoke runner.


### AUDIT-008: composite tenant foreign keys
- Проверяется каталогом, что любой FK на таблицу с `tenant_id NOT NULL` одновременно связывает `tenant_id` дочерней и родительской строк.
- Negative tests доказывают отказ cross-tenant ссылок для `object_versions`, `snapshots`, `outbox_messages`, `owner_credentials` и `objects.published_version_id`.
- Rust migrations уже определяют соответствующие composite FKs; AUDIT-008 закрепляет этот контракт в SQL smoke suite и защищает расширенные таблицы от регрессии.
- Rust-код и Rust migrations не изменяются.


### AUDIT-009: Invocation lifecycle and fencing
- PostgreSQL state transitions mirror `InvocationStatus::can_transition_to`: Received→ContextLoading→Processing; Processing↔ExecutingTool; Processing→Verifying; Verifying→Completed/CompletedDegraded; any nonterminal state may transition to Failed/Cancelled. Terminal states cannot transition again.
- New invocations start at Received with version/fencing token zero. Identity is immutable.
- Each accepted state transition and each successful expired-lease reclaim increments optimistic `version` exactly once; heartbeat/initial claim do not. Reclaim must strictly advance the fencing token and install a lease. State transition and reclaim are separate CAS operations.
- Active leases cannot be stolen. A stale worker cannot write using a lower fencing token. Regression coverage: `tests/21_invocation_lifecycle.sql`, wired into the smoke runner.
- ToolExecution remains outside this audit: the Rust repository currently has no ToolExecution domain/repository contract. Its existing Unknown/reconciliation SQL guard is unchanged.
- Rust source, migrations, and roadmap are not modified.


### T-27: Caller-level episodic memory isolation
- `resolve_delegated_caller(p_caller_id)` installs `app.caller_id` transaction-locally only after the active tenant/Principal/Caller delegation and lifecycle rows have been validated and locked.
- `memories` RLS keeps semantic memory tenant-scoped and restricts episodic memory to the resolved Caller. Missing Caller context exposes no episodic rows and rejects episodic writes.
- `memory_embeddings` and `memory_conflicts` inherit visibility from their parent memory rows, preventing child-table and conflict-edge side channels.
- The caller context must be established by `resolve_delegated_caller` in the same transaction as memory access. It is not taken from a request DTO. As with the existing tenant/principal GUC contract, this assumes application-internal SQL execution under `qembed_runtime`; RLS is not a defense against arbitrary SQL executed with that role.
- Regression coverage: `tests/24_caller_memory_rls.sql`, included in `tests/run_smoke.sh`.

### AUDIT-010: SECURITY DEFINER hardening
- Revoke `CREATE` on schema `public` from `PUBLIC` and all application roles. Pin every SECURITY DEFINER function search path to `pg_catalog, public, pg_temp`, placing the temporary schema last so caller-created temporary relations cannot shadow trusted objects.
- Add regression checks for the definer role attributes and membership isolation; function ownership, SECURITY DEFINER flag, fixed `pg_catalog, public, pg_temp` search_path and PUBLIC execute revocation; and the intended runtime/retention/admin/dispatcher EXECUTE matrix.
- Assert the narrow table privileges held by `qembed_definer`.
- Exercise the retention whitelist with a hostile table argument and a SQL-looking reason string, proving that the former is rejected and the latter is stored as literal data.
- Coverage: `tests/22_definer_security.sql`, wired into `tests/run_smoke.sh`.
- No Rust source, migrations, or roadmap changes.


## Future work (после AUDIT-001…010)

Аудиты Rust-совместимости завершены. Следующие этапы — это отдельные проверки готовности и развитие SQL-эксплуатации; они не являются поводом менять Rust-контракты. При расхождении реализация SQL по-прежнему адаптируется к действующему Rust.

### F-01. Полная матрица PostgreSQL и acceptance
- Прогнать clean install и полный `tests/run_smoke.sh` на PostgreSQL 15 и 16 с pgvector ≥0.8.0.
- Пройти T-01…T-64, фиксируя результат каждого acceptance-пункта: команда/сценарий, ожидаемый результат, фактический результат и ссылку на лог.
- Отдельно подтвердить повторяемость установки с нуля и проверить schema SHA-256 после любых DDL-изменений.
- Не объявлять SQL production-ready до закрытия обязательных acceptance-пунктов и документирования оставшихся ограничений.

### F-02. Конкурентность и Invocation fencing
- Добавить multi-session PostgreSQL tests с двумя и более независимыми соединениями: одновременный CAS одного Invocation, гонка heartbeat/reclaim, reclaim после истечения lease и попытка записи старым worker.
- Проверить, что ровно один конкурентный переход/reclaim выигрывает, version и fencing token не теряются, а проигравший получает однозначный конфликт без частичного изменения строки.
- Проверить поведение при rollback, разрыве соединения и повторной отправке операции.
- Сверить наблюдаемое поведение с существующим Rust `ExecutionStore` CAS contract; Rust не менять.

### F-03. Tenant lifecycle и legal hold (RT-046 / T-62)
- Уточнить и зафиксировать SQL-модель жизненного цикла tenant: допустимые состояния, блокировка новых операций, сроки и условия окончательного удаления.
- Определить legal hold как явный запрет удаления/очистки с проверкой во всех затрагиваемых retention/GC путях.
- Добавить tenant-scoped negative tests: удерживаемые данные не удаляются, другой tenant не влияет на результат, снятие hold разрешает только предусмотренный lifecycle-переход.
- Сначала согласовать точную семантику с RT-046 и T-62; не вводить новые состояния или поля по предположению.

### F-04. Knowledge garbage collection (M2 / T-44)
- Спроектировать отсутствующий DELETE/GC-путь для устаревших knowledge revisions и связанных данных.
- До реализации определить зависимости, правила сохранения данных, retention cutoff, поведение при активных ссылках и транзакционные границы.
- Учитывать tenant isolation, legal hold из F-03 и FK/immutability guards; удаление не должно затрагивать snapshots, events или другие данные вне согласованного GC scope.
- Добавить dry-run/preview и проверяемую статистику кандидатов до разрешения фактического удаления.

### F-05. Разбор B-01…B-09 и эксплуатационный rollout
- Получить исходный перечень B-01…B-09 и сопоставить каждый пункт с текущей схемой, AUDIT-001…010 и T-01…T-64. Не считать их закрытыми без исходных формулировок и проверяемых доказательств.
- Подготовить отдельный rollout/runbook: роли и секреты, порядок clean install, backup/restore, проверка RLS и grants, контроль schema checksum, мониторинг retention/outbox и процедура отката.
- Если потребуется upgrade существующих баз, разработать отдельную upgrade migration line и тестировать её на копии реальной предыдущей схемы. Clean-install SQL не использовать как upgrade migration.

### Рекомендуемый порядок
1. **F-01** — получить воспроизводимую базовую валидацию схемы.
2. **F-02** — закрыть конкурентные риски Invocation/CAS.
3. **F-03** — согласовать tenant lifecycle и legal hold.
4. **F-04** — реализовать knowledge GC на основе согласованных правил.
5. **F-05** — сверить B-01…B-09 и подготовить rollout/upgrade документацию.

Каждый этап оформлять отдельным SQL-only PR с тестами и явным evidence. До получения результатов не приписывать smoke suite, acceptance matrix или concurrency tests статус «пройдены».


## SQL-011 — Principal / Caller delegation

The schema now keeps the authenticated owner Principal (owner_principals) separate from the effective invocation Caller (callers). The tenant-scoped principal_caller_delegations relation supports multiple explicit Caller identities per Principal, including the existing Anonymous, Authenticated, and Service kinds. Grants are auditable and revocation is final; re-granting creates a new history row.

Runtime resolves the selected Caller through resolve_delegated_caller(uuid), which checks Principal and Caller lifecycle state and locks the relevant rows until the begin-invocation transaction commits. The runtime role cannot write delegation rows directly: it uses narrow SECURITY DEFINER grant/revoke functions with trusted app.tenant_id and app.principal_id transaction context. See ADR_RT-049_Principal_Caller_Delegation.md and tests/07_principal_caller_delegation.sql.

SQL-011 is a schema extension, not a change to the existing Rust owner-authentication contract. Rust integration must set trusted Principal context and lock the active delegation row FOR SHARE in the same begin-invocation transaction, so revocation and invocation start are serialized.


## RUST-041d — provider call outcome and reservation safety

The canonical schema now records a provider-call attempt for every committed token reservation. The durable `NotStarted → MayHaveBeenSent` boundary prevents the expiry sweeper from releasing a reservation after a request may have reached a provider. Unknown outcomes remain reserved; only a pre-send cancellation or explicit provider confirmation of non-acceptance is eligible for expiry. See the RUST-041d policy in the finalization addendum and `tests/23_provider_call_reconciliation.sql`.


## RUST-044 — identical-content version creation

Approved contract: for the same tenant/object, an exact canonical-byte match returns `identical_content` with the existing version and snapshot IDs and creates no rows. A matching SHA-256 with different bytes fails closed as an integrity/hash-collision error. Different bytes create a Draft version and snapshot atomically in one tenant-scoped transaction. This preserves the snapshot's exact version binding and the existing unique constraint; no DDL change is made. See `ADR_RUST-044_Identical_Content_Version_Deduplication.md` and the application-level test requirements in that ADR.
