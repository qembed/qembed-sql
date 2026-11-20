# ADR RT-049 — Caller-level RLS for episodic memory

**Статус:** принято; SQL implementation added to clean-install candidate r4. PostgreSQL execution evidence is pending.

## Контекст

T-27 требует, чтобы Caller A не мог читать Episodic Memory Caller B, даже если оба Caller принадлежат одному Tenant. Tenant-only RLS этого не обеспечивает: обе строки имеют один `tenant_id`, поэтому обе видны runtime-роли в рамках tenant scope.

## Решение

1. `memories` сохраняет tenant isolation для всех строк. Дополнительно semantic memory остаётся tenant-scoped, а episodic memory доступна только при совпадении `caller_id` строки с транзакционным `app.caller_id`.
2. Отсутствующий или пустой `app.caller_id` закрывает доступ ко всем episodic rows и запрещает их INSERT/UPDATE.
3. `resolve_delegated_caller(p_caller_id)` после успешной проверки и блокировки активной delegation, Principal и Caller устанавливает `app.caller_id` через transaction-local `set_config(..., true)`. Поэтому caller identity не переносится на следующее использование соединения пула после COMMIT/ROLLBACK.
4. `memory_embeddings` и `memory_conflicts` наследуют доступность от родительских строк `memories`: embedding виден только если видна его memory; conflict edge виден только если видны обе связанные memory. Это закрывает обход Caller RLS через дочерние таблицы.
5. Контекст устанавливается не из DTO/header. Runtime вызывает resolver в той же транзакции, в которой читает или изменяет caller-scoped memory.

## Граница доверия

Как и существующие `app.tenant_id` и `app.principal_id`, `app.caller_id` — доверенный transaction context, устанавливаемый внутренним application SQL path. PostgreSQL custom GUC сам по себе не защищает от произвольного SQL, уже выполняемого с ролью `qembed_runtime`; runtime credentials и SQL execution остаются application-internal. RLS здесь гарантирует fail-closed поведение и изоляцию при штатном использовании репозитория, а не защиту от компрометации самой runtime-роли.

Привилегированный `qembed_definer` сохраняет существующую узкую SECURITY DEFINER модель; этот ADR не расширяет его grants или функцию-поверхность.

## Проверки

Добавлен `tests/24_caller_memory_rls.sql` в `tests/run_smoke.sh`. Тесты покрывают:
- отсутствие Caller context;
- Caller A видит собственные episodic rows, но не Caller B;
- тот же Principal может разрешить Caller B и увидеть только его rows;
- semantic memory остаётся tenant-scoped;
- embeddings и conflict edges не раскрывают чужие episodic rows;
- INSERT/UPDATE/DELETE не позволяют Caller A создавать или изменять Caller B memory;
- Caller context не переживает завершение транзакции.

**Статус гейта:** тесты добавлены, но должны быть выполнены на PostgreSQL 16 + pgvector ≥0.8.0; r3 smoke evidence не считается доказательством для r4.
