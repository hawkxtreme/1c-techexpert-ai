# MCP для инструментов расследования

Это дополнительный транспорт к тому же конечному каталогу, который использует operation-run. Отдельный ИИ, API-ключ, SDK Python и серверная лицензия для него не требуются. Интерпретацию выполняет текущий harness. Сначала прочитай [контракт операций](operations.md), сохрани согласованные источники и пределы шага.

Если harness поддерживает локальный MCP STDIO, укажи доступный Python, проверенный абсолютный путь к techexpert.py и отдельный частный state-dir. Пример команды запуска процесса:

```powershell
python D:/project/1c-techexpert-ai/techexpert.py --state-dir D:/private/techexpert-state mcp-stdio
```

Процесс читает UTF-8 JSON-RPC из stdin, пишет только сообщения в stdout; диагностика идёт в stderr. Слушающего HTTP-порта нет. Настройка конкретного harness и факт успешного обнаружения инструментов проверяются отдельно; наличие этой команды или plugin.json не доказывает установку MCP в Codex. Глобальные настройки пользователя самостоятельно не заменяй.

Проверены две формы протокола: 2025-11-25 с initialize/notifications/initialized и 2026-07-28 с server/discover и обязательными protocolVersion/clientCapabilities в _meta каждого запроса. Метаданные клиента не являются правами доступа и не сохраняются в запросе операции. Другие версии и расширения, sampling, elicitation, tasks, ресурсы и prompts не предоставляются.

Полный tools/list возвращает 37 диагностических инструментов: techexpert_input_inspect, techexpert_case_analyze/show/coverage/events/evidence/compare, techexpert_comparison_show, techexpert_source_check/compare, techexpert_sample_describe, techexpert_logcfg_prepare/rollback_plan, techexpert_remote_plan/profile_plan/inspect/capture/parse, techexpert_knowledge_search/card, techexpert_os_collect/import, techexpert_artifact_show/evidence, techexpert_apdex_import, techexpert_jr_import/events/record, techexpert_source_snapshot/search/read, techexpert_rac_observe, techexpert_postgresql_observe, techexpert_sqlserver_observe, techexpert_client_import/observe и techexpert_investigation_sources. Их operation_key, executor_id, arguments, budget и необязательный context совпадают с полями CLI без поля operation: оно закреплено именем инструмента. Ещё два инструмента — techexpert_code_execute/inspect — выполняют ограниченные программы и читают сохранённый журнал. Пять инструментов управления: techexpert_operation_status/result/reconcile/cancel и techexpert_kernel_call; их точные схемы также возвращает tools/list.

Фиксированный `--profile direct` оставляет 37 диагностических операций и 6 операций управления. `--profile program` предоставляет 2 инструмента для программ и те же 6 операций управления. Полный профиль содержит 49 инструментов, включая 4 инструмента для согласованного контекста. `techexpert_investigation_progress` доступен во всех профилях и принимает `investigation_id`.

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

## Первичный приём ТЖ и ЖР

`context-intake REQUEST.json` использует поля управляемого запроса. Укажи `context.investigation_id` и `context.expected_revision`, полученные через `investigation --handle` или `investigation-create --handle`. В MCP используй `techexpert_context_intake` с теми же полями запроса, кроме `schema_version`. Агент готовит запрос из выбранных пользователем источников.

Для `input.inspect` ответ даёт ID членов, размеры и подсказки по суффиксу. Суффикс сам по себе не устанавливает формат. Если для выбора нужно увидеть имена, пользователь может локально открыть сохранённый каталог по его ID. Для внешнего окна `source.check` с `reference_preview=true` выдаёт окно, объём чтения и сохранения и `plan_sha256`. После согласия укажи этот хэш как `reference_sha256` в `case.analyze`.

После `case.analyze` или `jr.import` вернись к сохранённой привязке из `attachment`. Повтор исходного ключа использует прежний результат. При конфликте выбери актуальную ревизию того же окружения и вызови `context-attach RUN_ID --revision N` или `techexpert_context_attach`. Для чтения содержимого применяй согласованную политику. `intake_receipt` фиксирует состав компактной метаинформации, подготовленной для выдачи.

## Выдача сохранённых данных модели

`context-policy INVESTIGATION --revision N` возвращает допустимые категории и метки прикреплённых материалов без адресов окружения. Предложи только категории, которые нужны для текущей проверки. `context-policy-plan INVESTIGATION --revision N --allow tj --allow case` показывает добавление категорий и предел байтов компактного результата. После согласия пользователя повтори тот же выбор в `context-policy-save INVESTIGATION --revision N --allow tj --allow case --expected-sha256 HASH`. Список `--allow` заменяет текущий выбор. Прежний хэш устаревает после изменения политики. Категория `jr` относится к нативному ЖР, `comparison` к сохранённому сравнению.

`context-read INVESTIGATION --revision N tj-events --attachment A-1 --limit 20` читает выбранную страницу. MCP-инструмент `techexpert_context_read` принимает `investigation_id`, `revision`, `attachment`, `kind` и параметры из его схемы. Используй `next_offset` для продолжения. Для `tj-evidence` и `jr-evidence` укажи `--record` или `record` с ID записи. Координаты позволяют найти исходное доказательство локально. Псевдонимы обозначают повтор значения в выбранном расследовании. Границы сеанса и совпадение сущностей между источниками требуют отдельных доказательств.

`techexpert_code_context` читает те же представления внутри ограниченной программы. В `context` укажи идентификатор и ревизию расследования, в `arguments.scope.views` — выбранные пары материала и представления. Сводку ограничивает текущая политика. Для повторного получения используй тот же ключ программы. Проверка опирается на сохранённые квитанции и снимки. [Навык CodeMode](../../code-mode-analysis/SKILL.md)

Если для проверки нужен текст исходника, выбери только относящиеся к выводу строки. `context-excerpt-prepare INVESTIGATION --revision N --attachment A-src --member file:1 --start 120 --lines 12` сохраняет локальный предпросмотр. Для исходника в материалах случая `--member` принимает ID вида `s8`. Открой пользователю `preview_path` для просмотра конкретного текста. По его согласию вызови `context-excerpt-approve ARTIFACT --expected-sha256 HASH`, где `HASH` взят из `review_sha256` этого предпросмотра. Добавь полученный `attachment` к материалам того же расследования и прочитай `reviewed-excerpt` через CLI, MCP или CodeMode. `context-excerpt-revoke` с теми же ID и хэшем отзывает согласие на этот фрагмент. Каждый фрагмент подчиняется текущей политике и пределу ответа. Сохранённые исходники дают статические свидетельства, соответствие рабочей версии проверяется отдельно.

`context-history INVESTIGATION --revision N` показывает источник, категорию, версию, размер и правила очистки подготовленной выдачи. История относится к инструментам проекта. Доставку и сетевую активность самого harness она не измеряет.

`mcp-stdio --profile context` открывает первичный приём ТЖ и ЖР, чтение согласованных представлений по одному или программой, поиск знаний и чтение карточек. Полный профиль также предоставляет эти инструменты.

sample.describe доступен как techexpert_sample_describe: явные inputs{kind,id}, операция, необязательные окно и сообщённый контекст. Он читает сохранённые измерения, возвращает отбор, исключения и описательную статистику; normal_established остаётся false, independent_runs — unknown. Это успешный расчёт наблюдений, а не заключение о норме или причине.
