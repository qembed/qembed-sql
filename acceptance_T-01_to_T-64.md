# Qembed M0 v2.3.3 (r3) — Acceptance Test Plan T-01…T-64 + R3 regression

**r1 stage corrections (ADR RT-047):** T-06 and T-14 moved to M1a (walking-skeleton invoke slice restored); T-24 moved to M1b (dispatcher is M1b); T-03 moved to M3 (Policy/tools are M3); T-04/T-21/T-27 split into DB-level (M1a) and application path (M2).

**Правило:** security assertions запускаются только под непривилегированными DB-ролями; не под superuser/table owner. CI: Testcontainers, PostgreSQL 15 и 16; pgvector не ниже 0.8.0 (минимум выбранная production minor + актуальная поддерживаемая minor). Каждый тест фиксирует версию extension, миграции, роль, tenant scope и SQLSTATE.

## T-01…T-40 — наследуются из Specification M0 v2.2 (с уточнениями ниже)

| ID | Проверка | Ожидаемый результат | Этап |
|---|---|---|---|
| T-01 | Tenant A не видит данные B | SELECT под Scope A не возвращает ни одной строки B; попытка write в B отклонена | M1a |
| T-02 | Изоляция объектов | Запросы/связи object A не пересекаются с object B внутри tenant | M1a |
| T-03 | Prompt injection из документа | Документ не может повысить policy verdict или вызвать неразрешённый tool | M3 |
| T-04 | Provenance memory | User/ThirdParty не создаёт Verified/Observed; Verified создаётся отдельной Owner-записью | M1a (DB-level) / M2 (app path) |
| T-05 | Budget cap | Snapshot `limits.max_tokens_per_invocation` is required and positive; effective limit is min(snapshot cap, live object budget); parallel reservations and settlement never exceed it | M1b |
| T-06 | Invocation idempotency | Один tenant/object/caller/key даёт один invocation и один reserve | M1a |
| T-07 | SSRF basics | Запрещённые IP и redirect блокируются до connect | M3 |
| T-08 | Kill-switch race | После активации kill switch новый side effect не стартует | M1b |
| T-09 | Append-only | UPDATE/DELETE snapshots/events/policy decisions и published versions запрещены | M1a |
| T-10 | Caller erasure | Удаляются caller-derived messages/episodic memory/tool output по ledger | M1b |
| T-11 | Restart durability | Состояния и незавершённые jobs переживают рестарт | M1a |
| T-12 | Secret hygiene | Секреты отсутствуют в prompt, event, API и логах | M1a |
| T-13 | Embedding coexistence | Две модели сосуществуют без простоя и смешения embedding | M2 |
| T-14 | Structured output modes | JsonOnly/None проходят общий контракт provider | M1a |
| T-15 | Distributed rate limit | Несколько workers соблюдают общий rate limit | M1b |
| T-16 | Concurrent reservations | Параллельные резервы атомарно ограничены бюджетом | M1b |
| T-17 | Command idempotency | Дубликат tenant-scoped command_id не вызывает второй side effect | M1b |
| T-18 | Unknown execution | Unknown не повторяется автоматически до reconciliation | M1b / tool gate |
| T-19 | Snapshot immutability | Изменение config не меняет уже созданный snapshot/hash | M1a |
| T-20 | Tool version snapshot | Старый snapshot продолжает ссылаться на прежнюю ToolVersion | M1a |
| T-21 | Provenance validation | Невалидный source/provenance отклоняется | M1a (DB-level) / M2 (app path) |
| T-22 | DNS rebinding | Проверенный IP именно тот, к которому выполняется connect | M3 |
| T-23 | Kill-switch hierarchy | Platform/Tenant/Object/Tool precedence применяется корректно | M1b |
| T-24 | Outbox redelivery | Повторная доставка дедуплицируется потребителем | M1b |
| T-25 | Cancellation | После принятой отмены новые tool calls не стартуют | M1b |
| T-26 | Task/checkpoint durability | Task и checkpoint переживают рестарт | M4 |
| T-27 | Caller memory isolation | Caller A не видит Episodic Memory Caller B | M1a (DB-level RLS) / M2 (retrieval path) |
| T-28 | Embedding dimensions | Несовпадающая размерность отклоняется БД | M2 |
| T-29 | Event stream concurrency | Параллельные invocation не конфликтуют на независимом stream_version | M1a |
| T-30 | Snapshot dedup | 1000 invocation одной конфигурации переиспользуют snapshot; смена binding даёт новый | M1a |
| T-31 | Knowledge revision visibility | Retrieval в R исключает future/closed/staged документы | M2 |
| T-32 | Verifier V1–V7 | Фальшивые chunk_id/числа/ссылки и контрактно обязательные отсутствующие цитаты отклоняются | M2 |
| T-33 | Budget degradation | С источниками исчерпание бюджета даёт CompletedDegraded; без источников — Failed | M1b |
| T-34 | Pool isolation | Anonymous не исчерпывает долю Authenticated/Owner | M1b |
| T-35 | Deletion restore | После restore ledger проигрывается до открытия трафика; erased data не возвращаются | M1b |
| T-36 | RLS global roles | Platform kill switch читаем, но не изменяем runtime; dispatcher видит только delivery data | M1a |
| T-37 | AllowedCommand compile-fail | Вне qembed-domain::policy нельзя сконструировать/клонировать/сериализовать capability | M1a |
| T-38 | SSRF extended | Pinned connect, mapped IPv6, NAT64, CGNAT, metadata блокируются | M3 |
| T-39 | HNSW plan | EXPLAIN использует правильный partial index для шаблонов dimension/metric | M2 |
| T-40 | Reservation sweeper | Повторный sweeper идемпотентен и не меняет counters второй раз | M1b |

## T-41…T-52 — correction-pack acceptance (ID сохранены)

| ID | Проверка / шаг | Ожидаемый результат | Этап |
|---|---|---|---|
| T-41 | Outbox tenant A с event tenant B | Composite FK violation; транзакция откатывается | M1a |
| T-42 | interaction_message caller_id отличается от invocation caller_id | Composite FK violation | M1a |
| T-43 | Revision commit и chunk intervals | Все chunks получают единый revision interval в одной транзакции | M2 |
| T-44 | GC при активном invocation, pinned revision R | Документы/chunks, нужные R, не удаляются | M2 |
| T-45 | Worker A теряет lease; Worker B получает token N+1; A пытается finish | A отклонён; состояние B не перезаписано | M1b |
| T-46 | Timeout после возможного внешнего side effect | Execution=Unknown; авто-повтора нет | До включения tools |
| T-47 | DNS mixed public/private A/AAAA RRset | Весь запрос отклонён | M3 |
| T-48 | Caller deletion и restore backup | Ledger повторно удаляет caller-derived data до открытия трафика | M1b |
| T-49 | Runtime без app.tenant_id | Ноль строк / write denied; fail-closed | M1a |
| T-50 | Runtime пытается изменить platform kill switch | Permission/RLS denied | M1a |
| T-51 | Dispatcher читает outbox/events и пробует messages/callers | Delivery read разрешён; прочее запрещено | M1a |
| T-52 | Binding меняется после mint AllowedCommand | Executor отклоняет stale capability до network call | M1b / tool gate |

## T-53…T-64 — v2.3.2 errata / finalization gates

| ID | Проверка / шаг | Ожидаемый результат | Этап |
|---|---|---|---|
| T-53 | Полный RLS audit: все tenant-owned таблицы | Каждая таблица имеет ENABLE+FORCE RLS; migration abort при пропуске/неверной классификации | M1a |
| T-54 | Role matrix runtime/dispatcher/admin/retention/definer | Роли имеют только заявленные grants; runtime не владеет таблицами, не SUPERUSER/BYPASSRLS и не наследует definer | M1a |
| T-55 | Composite FK caller/invocation/decision/event/execution | Все tenant/object/caller/snapshot/tool claims согласованы; чужие claims отклоняются | M1a |
| T-56 | Deterministic command_id | UUIDv5(invocation_id, step_index, action_hash) повторяется после crash/restart и tenant-scoped unique | M1b |
| T-57 | SECURITY DEFINER attack surface | PUBLIC EXECUTE revoked, fixed search_path, qembed_definer NOLOGIN/NOSUPERUSER/NOBYPASSRLS; нет произвольного cross-tenant read/write канала | M1a |
| T-58 | Invocation lease expiry/reclaim | Старый worker не фиксирует terminal result; reclaim выдаёт больший fencing token | M1b |
| T-59 | Tool execution fencing/reconciliation | Expired Executing → Unknown; Unknown terminal только reconciliation; stale token отклонён | До включения tools |
| T-60 | Verified memory promotion | UPDATE candidate→Verified отклонён; новая Owner row с supersedes_id и TenantOwner принимается; TenantAdmin отклонён | M1a |
| T-61 | Retention whitelist | Обычный purge не удаляет events/decisions/snapshots; append-only сохраняется | M1a |
| T-62 | Tenant offboarding | Traffic/tool calls blocked; principals revoked; legal hold honored; controlled erasure audited; tombstone remains | Перед production |
| T-63 | JCS and canonical JSON corpus | Rust rejects duplicate keys, NaN/Infinity, invalid UTF-8/noncanonical bytes; DB hash matches canonical bytes and JSONB projections | M1a |
| T-64 | Encrypted payload lifecycle | Payload encrypted; hash verified before tool; no raw payload in events/logs; terminal cleanup; Unknown retained until reconciliation/TTL | До включения tools |

## Mandatory failure-injection matrix

Crash points: (1) после execution claim до connect; (2) после отправки запроса до ответа; (3) после ответа до DB commit; (4) после event insert до outbox ack; (5) revision commit до COMMIT; (6) binding change после mint до execute. В каждом случае side effect не повторяется без подтверждённой внешней idempotency/reconciliation.

## Compatibility matrix и release evidence

| PostgreSQL | pgvector | Статус в этом пакете |
|---|---|---|
| 15.x | >=0.8.0 | Требуется CI run; не заявляется пройденным |
| 16.x | >=0.8.0 | Полный CI run T-01…T-64 требуется; smoke r3 (103 проверки) на pgvector 0.8.0 пройден — см. «Smoke evidence r3» |

Каждый CI run сохраняет: `SELECT version()`, `extversion`, применённый SQL SHA-256, `pg_roles`/grants audit, T-01…T-64 report, concurrency logs. Upgrade v2.2→v2.3.x — отдельный migration project (T-51 из старой нумерации не путать с correction-pack T-51); clean schema не применять к существующей БД.

## Smoke evidence r1 (не сертификация; заменено evidence r3 ниже)

Окружение: PostgreSQL 16, pgvector 0.6.0 (ниже минимума; применено с `qembed.allow_old_pgvector=on`). Без флага схема корректно отклоняется (pgvector gate). Проверено под реальными логинами `qembed_runtime` / `qembed_retention` / `qembed_dispatcher`, не под superuser:

| Область | Результат |
|---|---|
| T-01/T-49 | без `app.tenant_id` — 0 строк; tenant B не видит A |
| T-09 | UPDATE/DELETE append-only отклонены (permission denied / trigger) |
| T-36/T-51 | dispatcher читает `outbox_messages`; `callers`, `interaction_messages` — denied |
| T-47 (binding, DB часть) | `binding_version` монотонна; DELETE binding запрещён |
| T-54/T-57 | runtime не делает `SET ROLE qembed_definer` и не вызывает `retention_purge`; definer-функции принадлежат `qembed_definer`, `PUBLIC EXECUTE` отозван, членств нет |
| T-60 | UPDATE candidate→Verified отклонён; Owner-строка (TenantOwner) принята; TenantAdmin отклонён; verified immutable |
| T-61 | `retention_purge('events')` → `table not allowed` |
| T-63 (DB часть) | неверный хэш и расхождение JSONB-проекций отклоняются; Rust-JCS не проверялся |

Не выполнено: PG15, pgvector ≥0.8, остальные тесты, failure-injection matrix, конкурентность.

## R3 regression (DB-level, добавлено в r3; нумерация T-01…T-64 не менялась)

| ID | Проверка | Ожидаемый результат | Связь | Этап |
|---|---|---|---|---|
| R3-01 | Повторная публикация: supersede v1 → publish v2 → перенос pointer в одной транзакции | Успех; без переноса pointer COMMIT отклоняется; pointer на superseded-версию отклоняется | T-09, T-19 | M1a |
| R3-02 | Удаление candidate, заменённого Verified-записью | Успех; Verified-запись сохраняется, `supersedes_id = NULL`; прямой UPDATE Verified запрещён | T-60 | M1a |
| R3-03 | `retention_purge('tool_executions')` на терминальной строке | Обнуляются только `output`/`output_expires_at`; runtime выполнить то же напрямую не может | T-61 | M1a |
| R3-04 | `sweep_expired_reservations` | Освобождает `usage_counters` и `caller_usage_counters`; повторный вызов даёт 0 | T-40 | M1b |
| R3-05 | `Unknown → Succeeded/Failed` с `reconciliation_state` NULL / pending / не соответствующим статусу | Отклонено; корректная reconciliation принимается | T-59 | До включения tools |
| R3-06 | Создание объекта ролью `qembed_admin` | Успех (инициализация `knowledge_revisions` проходит) | T-54 | M1a |

## Smoke evidence r3 (не сертификация)

Окружение: PostgreSQL 16, pgvector 0.8.0 (сборка из тега v0.8.0); схема применена без `qembed.allow_old_pgvector`. Запуск: `tests/run_smoke.sh` (SQL-файлы 00–40). Роли — `SET ROLE` под суперпользовательской сессией плюс один реальный логин (`SET ROLE qembed_definer` из runtime отклонён).

Результат: **103 проверки, 103 пройдено**; тот же набор на SQL r1: 91 пройдено, 12 не пройдено (R3-01…R3-06). Покрытие — только DB-уровень: T-01, T-04, T-06, T-09, T-28, T-29 (уникальность stream_version, не конкурентность), T-36, T-40, T-42, T-43 (синхронизация интервалов), T-47 (DB), T-49, T-50, T-51, T-54, T-57, T-59 (guard), T-60, T-61, T-63 (DB), HNSW partial index (`CREATE INDEX CONCURRENTLY`) строится. `KNOWN GAP`: у runtime нет `DELETE` на `knowledge_documents` (GC, M2).

Не выполнено: PostgreSQL 15, остальные T-xx, реальная конкурентность/fencing, failure-injection matrix, Rust JCS, SSRF, upgrade.
