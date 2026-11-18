# Qembed M0 v2.3.3 (r3) Finalization Pack

## Files
- `qembed_m0_v2_3_3_clean_schema.sql` — clean-install candidate r3 (PG 15+, pgvector ≥0.8.0 gate). NOT an upgrade migration. SHA-256: `aa58b1d327877f7c642a1f78942725b3dd345dd2f19a262895b48504e558e482`.
- `Qembed_M0_v2_3_3_Finalization_Addendum.md` — нормативный addendum (r3); §10 — изменения r3.
- `ADR_RT-039_to_RT-047.md` — ADR RT-039…RT-047 + новый RT-048 (r3 corrections).
- `acceptance_T-01_to_T-64.md` — T-01…T-64 + раздел «R3 regression» (R3-01…R3-06) + «Smoke evidence r3».
- `tests/` — поведенческий smoke-набор (`run_smoke.sh`, SQL 00–40). Нужны PostgreSQL superuser, pgvector ≥0.8.0, роль `qembed_migrator`.
- `Qembed_Object_Runtime_M0_v2_3_3_FINAL_TZ.pdf`, `Qembed_M0_v2_3_3_Diagrams.pdf` — **не пересобирались, содержимое r1**. Нормативны `.md` (addendum r3 имеет приоритет по §1); PDF с addendum r1 устарел в части §9–§10.

## Что исправлено в r3 (SQL)
1. R3-01 — повторная публикация версии была невозможна (deferred-проверка pointer).
2. R3-02 — удаление candidate, заменённого Verified, падало на immutability.
3. R3-03 — `retention_purge('tool_executions')` падал на терминальных строках.
4. R3-04 — sweeper не освобождал `caller_usage_counters`.
5. R3-05 — обход reconciliation `Unknown → терминал` через NULL.
6. R3-06 — `qembed_admin` не мог создать объект (нет доступа к `knowledge_revisions`).

## Validation status
- PostgreSQL 16 + pgvector 0.8.0: схема применяется без флага; smoke-набор 103/103 (r1 на том же наборе: 12 падений).
- NOT executed: PostgreSQL 15, большинство T-01…T-64, конкурентность/fencing, Rust JCS, SSRF, failure-injection, upgrade. Заявления о production-готовности нет.
- **B-01…B-09:** список замечаний и отчёт r2 в присланный архив не входили; r3 не утверждает закрытие B-01…B-09 и не сопоставляет с ними R3-01…R3-06. Пришлите список — сверю.

## Open items (не закрыты в r3)
- RT-046 tenant lifecycle / legal hold (T-62).
- GC знаний: нет `DELETE`-пути (M2, T-44).
- Нет DB-guard на переходы `object_invocations` (рекомендуется до M1b).
- Review `qembed_definer` grants/policies, тест на произвольный SQL через функции.

## Start coding
Архитектура заморожена для M1a (addendum §7–§8, RT-047). SQL — candidate до прохождения T-01…T-64 на PG 15/16 × pgvector ≥0.8.0. Внешние write-tools не включать до T-07, T-22, T-38, T-46, T-47, T-52, T-59, T-64.
Порядок публикации версии в репозитории: supersede старой → publish новой → перенос `published_version_id` в одной транзакции.
