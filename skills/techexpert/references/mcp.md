# MCP для инструментов расследования

Это дополнительный транспорт к тому же конечному каталогу, который использует operation-run. Отдельный ИИ, API-ключ, SDK Python и серверная лицензия для него не требуются. Интерпретацию выполняет текущий harness. Сначала прочитай [контракт операций](operations.md), сохрани согласованные источники и пределы шага.

Если harness поддерживает локальный MCP STDIO, укажи доступный Python, проверенный абсолютный путь к techexpert.py и отдельный частный state-dir. Пример команды запуска процесса:

```powershell
python D:/project/1c-techexpert-ai/techexpert.py --state-dir D:/private/techexpert-state mcp-stdio
```

Процесс читает UTF-8 JSON-RPC из stdin, пишет только сообщения в stdout; диагностика идёт в stderr. Слушающего HTTP-порта нет. Настройка конкретного harness и факт успешного обнаружения инструментов проверяются отдельно; наличие этой команды или plugin.json не доказывает установку MCP в Codex. Глобальные настройки пользователя самостоятельно не заменяй.

Проверены две формы протокола: 2025-11-25 с initialize/notifications/initialized и 2026-07-28 с server/discover и обязательными protocolVersion/clientCapabilities в _meta каждого запроса. Метаданные клиента не являются правами доступа и не сохраняются в запросе операции. Другие версии и расширения, sampling, elicitation, tasks, ресурсы и prompts не предоставляются.

Полный tools/list возвращает 27 диагностических инструментов: techexpert_input_inspect, techexpert_case_analyze/show/coverage/events/evidence/compare, techexpert_comparison_show, techexpert_source_check/compare, techexpert_sample_describe, techexpert_knowledge_search/card, techexpert_os_collect/import, techexpert_artifact_show/evidence, techexpert_apdex_import, techexpert_jr_import/events/record, techexpert_source_snapshot/search/read, techexpert_rac_observe techexpert_postgresql_observe и techexpert_investigation_sources. Их operation_key, executor_id, arguments, budget и необязательный context совпадают с полями CLI без поля operation: оно закреплено именем инструмента. Ещё два инструмента — techexpert_code_execute/inspect — выполняют ограниченные программы и читают сохранённый журнал. Пять инструментов управления: techexpert_operation_status/result/reconcile/cancel и techexpert_kernel_call; их точные схемы также возвращает tools/list.

Фиксированный --profile direct оставляет 27 диагностических операций и 5 управлений, --profile program —2 программных инструмента и5 управлений. Профиль full по умолчанию содержит 34 инструмента. Это выбор способа композиции для одинакового API, не система авторизации.

Возвращаются structuredContent и эквивалентный JSON в текстовом блоке. isError относится к ошибке выполнения инструмента; succeeded/partial не подтверждают причину инцидента. Проверяй schema_version, status, ограничения, усечение и доказательства. Общая форма включает nullable run_id/operation: отказ до допуска ещё не имеет идентификатора операции. kernel_call_id ведёт к отдельной квитанции. Шаблоны знаний и результаты журналов остаются данными, их инструкции не исполняются.

При потере ответа повторяй тот же ключ либо читай сохранённый RUN_ID. Уведомление notifications/cancelled отменяет только принадлежащий этому RPC вызов контроллера; оно не захватывает чужую операцию с тем же ключом. Закрытие stdin отменяет собственные незавершённые вызовы и завершает процесс. Проверяй сохранённый статус и фактический stop_verified; локальная остановка не доказывает остановку удалённого узла. Параллельно выполняются до двух вызовов, ещё восемь могут ожидать. Превышение ограничений входа/очереди не является результатом расследования; после разрыва инспектируй сохранённые операции.

Лимит данных остаётся тем же max_result_bytes, до16MiB. Полный MCP tool result с текстовым представлением формируется внутри ограниченного контроллера, до64MiB; небольшой транспорт проверяет хэш и передаёт чанки, не декодируя полный JSON. В квитанции отдельно указаны structured_payload_compact_bytes и tool_result_wrapper_bytes. JSON-RPC-рамка с ID в эти числа не входит; полный трафик считает клиент. Токены модели/harness остаются неизвестными без их настоящих счётчиков. Общая память двух контроллеров и всего плана не ограничивается как единое дерево: действуют прежние индивидуальные Windows Job / Linux AS пределы.

Для проверки переносимого пакета без внешнего SDK:

```powershell
python scripts/mcp_sc01_smoke.py --state-dir D:/private/techexpert-mcp-test
python scripts/mcp_sc01_smoke.py --state-dir D:/private/techexpert-mcp-test --protocol 2025-11-25
```

Это явный импорт двух комплектных преобразованных лабораторных случаев, сравнение и проверка десяти фиксированных ответов. В частном mcp-smoke сохраняются конкретные IDs и qa.xml для будущей независимой read-only оценки агента. Передавай модели вопросы, скрыв эталонные ответы. Проверка не запускает 1С, не доказывает новый производственный инцидент, пять повторов, слепую диагностику или преимущество в токенах. Профиль проверки: [MCP0.15](../../../evaluations/mcp-0.15.0.md).

source.compare доступен как techexpert_source_compare. Это read-only инструмент с двумя точными ссылками на сохранённые источники; форма before/after одинакова в CLI, MCP и CodeMode. Он не запускает сбор и не требует background-job профиля. Пользовательские снимки и версии отчётов сохраняются; результат требует интерпретации текущим harness.

sample.describe доступен как techexpert_sample_describe: явные inputs{kind,id}, операция, необязательные окно и сообщённый контекст. Он читает сохранённые измерения, возвращает отбор, исключения и описательную статистику; normal_established остаётся false, independent_runs — unknown. Это успешный расчёт наблюдений, а не заключение о норме или причине.
