# Qembed Object Runtime — ADR RT-039…RT-048

Статус документа: принятые архитектурные решения; реализация/проверка отмечены отдельно.

## RT-039 — Canonical snapshot bytes
**Решение.** `canonical_json BYTEA` — единственный source of truth; SHA-256 считается над точными UTF-8 байтами через `pgcrypto.digest`. JSONB-поля — производные проекции и сверяются с декодированным JSON в DB guard. RFC 8785/JCS canonicality, duplicate-key rejection, запрет NaN/Infinity и нормализация чисел выполняются Rust-кодом до INSERT.
**Причина.** PostgreSQL JSONB не сохраняет исходное представление и не является источником JCS-байтов. Один совпадающий hash не доказывает корректность JCS.
**Гейт.** T-48 + cross-version PG test.

## RT-040 — Independent leases and fencing
**Решение.** Invocation и ToolExecution имеют независимые lease/fencing tokens. Каждое изменение состояния выполняется условным UPDATE по tenant, ID, ожидаемому token и версии. Истёкший Executing переводится в Unknown; автоматический повтор запрещён. Unknown становится Succeeded/Failed только после reconciliation с актуальным token.
**Гейт.** T-45, T-46, T-58, T-59. DB trigger — дополнительный guard, не замена CAS-операциям репозитория.

## RT-041 — Monotonic binding version
**Решение.** `qembed_objects.binding_counter` — монотонный счётчик на объект. Любое изменение tool version, permissions, enabled или scope атомарно увеличивает counter и присваивает новое `binding_version`. Физический DELETE/TRUNCATE binding запрещён; отключение — soft-disable.
**Гейт.** T-47.

## RT-042 — Definer role
**Решение.** `qembed_definer` — NOLOGIN, NOSUPERUSER, NOBYPASSRLS; только владелец узких SECURITY DEFINER функций, fixed `search_path`, `PUBLIC EXECUTE` revoked, минимальные grants. Воркеры получают только идентификаторы через функции discovery и затем действуют под tenant Scope. Нельзя выдавать членство runtime/dispatcher в definer.
**Оговорка.** Текущие definer RLS policies являются технически широкими по строкам; безопасность зависит от ограниченного набора функций и невозможности SET ROLE. До production нужен role/grant audit и тест на произвольный SQL через функции.
**Гейт.** T-41, T-42, T-57.

## RT-043 — Encrypted command payload store
**Решение.** Полный аргументный payload хранится отдельно от event/decision log, только envelope-encrypted; `key_id` поддерживает ротацию. `arguments_hash` совпадает с Allow decision. Проверка hash выполняется до вызова инструмента. Terminal payload удаляется; Unknown payload сохраняется до reconciliation/TTL policy. Raw payload и secrets не попадают в events/API/logs.
**Гейт.** T-52, T-64.

## RT-044 — Owner verification creates a new memory
**Решение.** Verified — только новая запись `source_kind='Owner'`, `verification='Verified'`, `verified_by` — TenantOwner, `supersedes_id` — исходный candidate. UPDATE существующей User/ThirdParty/RuntimeInference записи до Verified запрещён; verified row immutable. TenantAdmin не может подтверждать, пока отдельная политика явно не разрешит это.
**Гейт.** T-04 и T-60.

## RT-045 — Retention vs append-only
**Решение.** Обычный `retention_purge` не удаляет `object_events`, `policy_decisions`, `runtime_snapshots`. Удаление TTL-данных выполняется whitelist-функцией с записью retention_log.
**Гейт.** T-09, T-61.

## RT-046 — Tenant offboarding and erasure
**Решение.** Offboarding — отдельный privileged workflow: (1) Tenant=Offboarding, блок новых invocation/tool calls; (2) revoke principals/callers/credentials; (3) остановить workers/jobs; (4) проверить legal holds; (5) удалить или криптографически стереть содержимое по retention/legal policy; (6) append-only данные удаляются только отдельной контролируемой erasure-процедурой с независимым audit; (7) оставить минимальный tombstone без пользовательского контента; (8) Tenant=Erased.
**Оговорка.** Append-only означает неизменяемость при обычном runtime, а не абсолютный запрет законного erasure. Tenant-specific encryption keys нужны для erasable sensitive payloads. Обычный `retention_purge` не является offboarding.
**Schema gap (r1).** Текущая clean schema не содержит состояния жизненного цикла tenant и legal hold (`tenants` = `id`, `created_at`). Состояния Offboarding/Erased, блокировка новых invocation/tool calls и учёт legal hold — обязательный deliverable до production (ADR + миграция), не заявляются реализованными.
**Гейт.** T-62; юридическая проверка LGPD/GDPR до production.

## RT-047 — M1a is a walking skeleton (r1)
**Решение.** M1a включает сквозной срез create → publish → invoke → retrieve result на mock provider (begin invocation с idempotency первым шагом, pinned snapshot, event+outbox, GET invocation, cancellation contract, минимальный OwnerAPI). Тесты T-06 и T-14 относятся к M1a; T-24 (outbox redelivery) — к M1b вместе с dispatcher; T-03 — к M3 вместе с Policy/tools; T-04/T-21/T-27 в M1a проверяются на уровне БД, прикладной путь — M2.
**Причина.** Addendum v2.3.3 (первая редакция) исключил invoke из M1a, что противоречило DoD v2.3.1 §11 и «walking skeleton»; список тестов в DoD не совпадал со стадиями в acceptance-плане.
**Гейт.** M1a DoD (addendum §8).

## RT-048 — r3 SQL corrections (behavioural findings)
**Решение.** (1) Инвариант «опубликованная версия не может быть superseded, пока на неё указывает объект» проверяется deferred constraint trigger на COMMIT, а не немедленно; порядок публикации: supersede старой → publish новой → перенос указателя. (2) RT-044 уточнён: Verified-запись неизменяема, кроме референциального действия `ON DELETE SET NULL (supersedes_id)` (допускается только при `pg_trigger_depth() > 1`). (3) RT-045 уточнён: `retention_purge` для `tool_executions` обнуляет только `output`/`output_expires_at` терминальной строки; право ограничено `current_user = 'qembed_definer'`. (4) RT-040 уточнён: `Unknown → Succeeded/Failed` требует `reconciliation_state` ∈ {confirmed_succeeded, confirmed_failed}, согласованного с итоговым статусом; NULL запрещён. (5) Sweeper освобождает per-caller reserved tokens. (6) `qembed_admin` получает минимальный доступ к `knowledge_revisions` для провижининга объектов.
**Причина.** Дефекты найдены выполнением схемы на PG16 + pgvector 0.8.0 под непривилегированными ролями; статическая проверка r1 их не выявила.
**Остаточный риск.** Исключение для RI-действия ослабляет иммутабельность Verified до потери ссылки `supersedes_id`; GC знаний и lifecycle tenant не решены (см. addendum §9).
**Гейт.** R3-01…R3-06 (acceptance «R3 regression»), T-04, T-09, T-59, T-60, T-61.
