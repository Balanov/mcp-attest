<div align="center">
  <img src="docs/readme/hero.png" alt="MCP-ATTEST — инструмент проверки соответствия для контроля доступа агентов MCP. Политика запрещает, шлюз разрешил: девять проверок переигрывают ваш журнал по вашим же правилам." width="100%">
  <p><strong>Докажите, что ваша политика MCP действительно применяется.</strong></p>
  <p>Два входных файла · девять проверок · ноль зависимостей · MIT</p>
  <p>
    <a href="#установка">Установка</a> ·
    <a href="#запуск">Запуск</a> ·
    <a href="#девять-проверок">Девять проверок</a> ·
    <a href="#использование-в-ci">CI</a> ·
    <a href="SPEC.md">Спецификация</a> ·
    <a href="https://balanov.pro/mcp-attest/">Сайт</a> ·
    <a href="README.md">English</a>
  </p>
  <p>
    <a href="https://github.com/Balanov/mcp-attest/actions/workflows/ci.yml"><img src="https://github.com/Balanov/mcp-attest/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
    <a href="https://github.com/Balanov/mcp-attest/releases/latest"><img src="https://img.shields.io/github/v/release/Balanov/mcp-attest" alt="Последний релиз"></a>
    <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-green.svg" alt="MIT license"></a>
    <a href="https://pypi.org/project/mcp-attest/"><img src="https://img.shields.io/pypi/v/mcp-attest.svg?color=2fd9a6" alt="Версия на PyPI"></a>
    <a href="https://pypi.org/project/mcp-attest/"><img src="https://img.shields.io/pypi/pyversions/mcp-attest.svg" alt="Python 3.10+"></a>
  </p>
</div>

<div align="center">
  <img src="docs/readme/demo.gif" alt="Вывод mcp-attest check на записанном журнале: C6 — политика запретила вызов, а шлюз разрешил; C9 — описание инструмента изменилось после одобрения; summary critical=7 high=6" width="100%">
  <p><sub>Реальный вывод на <code>examples/session.jsonl</code>. Код возврата 1 означает блокирующую находку. <a href="examples/">Примеры</a> · <a href="docs/RESEARCH.md">Почему это нужно</a>.</sub>
</div>

`mcp-attest` — инструмент проверки соответствия для контроля доступа агентов MCP. Он берёт политику, которую вы написали, и журнал того, что действительно произошло, и показывает каждое место, где они расходятся.

Это не шлюз. Он не стоит в рабочем пути запроса и никогда не держит учётные данные вышестоящего сервера. Он читает улики, которые уже существуют.

## Почему mcp-attest

- **Находит правило, которое приняли, но не применили.** C6 заново вычисляет вашу политику локально по каждому записанному вызову. Вызов, который политика запрещает, а шлюз разрешил, не виден ни в одной панели: панели показывают то, во что поверил шлюз.
- **Улики, а не мнение.** Каждая находка содержит точный инструмент, аргументы и решение, из которых она получилась, и способ исправления.
- **Офлайн по построению.** Ни сетевых вызовов, ни телеметрии, ни аккаунта. Журналы содержат полезную нагрузку и остаются там, где лежат.
- **Коды возврата, а не ощущения.** `0` — чисто, `1` — блокирующая находка, `2` — плохие входные данные. Работает как ворота в CI без обёртки.
- **Ноль зависимостей.** Python 3.10+ и стандартная библиотека.
- **Квитанции, которые не подделать.** Необязательная хеш-цепочка с подписью HMAC для каждого разрешённого вызова.

<div align="center">
  <img src="docs/readme/architecture.png" alt="Поток mcp-attest: политика и журнал переигрываются локально и сравниваются, на выходе — находки, код возврата и цепочка квитанций" width="100%">
  <p><sub>Ничего не проксируется. Улика — это журнал. <a href="SPEC.md">Полная спецификация</a>.</sub>
</div>

**[Сайт](https://balanov.pro/mcp-attest/) · [Спецификация](SPEC.md) · [Исследование](docs/RESEARCH.md) · [MIT](LICENSE)**

## Установка

```sh
pipx install mcp-attest          # изолированный CLI
uvx mcp-attest check --help      # разовый запуск
pip install mcp-attest           # в виртуальное окружение
```

Из исходников:

```sh
git clone https://github.com/Balanov/mcp-attest.git
cd mcp-attest
python -m pip install -e ".[dev]"
python -m unittest discover -s tests -v
```

## Запуск

```sh
attest init                                            # создать заготовку политики
attest check --policy examples/policy.json --trace examples/session.jsonl
```

```text
!! [CRITICAL] C6 Policy denies 'shell__exec' but the gateway allowed it
          Local evaluation of the policy says deny (tool is on the deny list); the trace
          records allow ('argument-conditioned rule matched'). This is the 'policy accepted
          but not enforced' failure mode — a rule that is registered but never applied.
          fix: Replay the call against the gateway with the same arguments and fix
               the rule binding, then add this call as a regression case in CI.

summary: critical=7, high=6
```

Код возврата `1` означает блокирующую находку. `--json` печатает находки в машинном виде, `--strict` считает блокирующими и высокие.

| Команда | Что делает |
|---|---|
| `attest init` | Пишет заготовку политики |
| `attest check` | Сверяет журнал с политикой |
| `attest receipts` | Строит и проверяет хеш-цепочку квитанций |
| `attest shadow` | Показывает серверы, доступные агенту в обход шлюза |
| `attest rules` | Печатает список применяемых правил |

## Девять проверок

| ID | Правило | Что ловит |
|---|---|---|
| C1 | default-deny | Незаданный список разрешений, молча означающий «разрешить всё» |
| C2 | list/call parity | Инструмент скрыт из `tools/list`, но вызывается по имени |
| C3 | narrowing only | Покомпонентный контроль, расширяющий права клиента |
| C4 | credential separation | Токен клиента, дословно переданный вышестоящему серверу |
| C5 | fail closed | Вызов разрешён из-за ошибки при проверке политики |
| C6 | enforcement parity | Политика запрещает, шлюз разрешил |
| C7 | shadow MCP | Сервер, доступный агенту в обход шлюза |
| C8 | receipt chain | Разрешённые вызовы без проверяемой квитанции или с разорванной цепочкой |
| C9 | description integrity | Описание инструмента изменилось после одобрения (rug pull) |

## Входные файлы

### Политика

```json
{
  "version": 1,
  "default_decision": "deny",
  "clients": {
    "ci-bot": {
      "tools": {
        "allow": ["fs__read_file", "fs__list_directory"],
        "deny": ["fs__write_file", "fs__delete_everything"],
        "conditional": [
          {
            "tool": "fs__write_file",
            "allow_when": { "path": { "starts_with": "./out/" } },
            "action": "allow",
            "reason": "writes are allowed only inside ./out/"
          }
        ]
      },
      "egress_hosts": ["api.internal.example.com"]
    }
  },
  "gateway": { "mode": "routed", "fail_closed": true, "passthrough_credentials": false },
  "receipts": { "required": true, "key_env": "MCP_ATTEST_KEY" }
}
```

Операторы условий: `eq`, `not_eq`, `starts_with`, `ends_with`, `contains`, `in`, `not_in`, `gt`, `gte`, `lt`, `lte`, `glob`, `regex`. Строка, оканчивающаяся на `/`, — это префикс; строка с `*` — это glob.

### Журнал

Новые строки JSON, по событию на строку. Такой файл может писать любой прокси, агентный каркас или шаг CI.

```jsonl
{"type":"tools_list","actor":"ci-bot","tools":[{"name":"fs__read_file","description_sha256":"a1b2…"}]}
{"type":"tool_call","actor":"ci-bot","tool":"fs__read_file","args":{"path":"/srv/README.md"},"decision":"allow","upstream":true,"reason":"tool is on the allow list"}
{"type":"client_servers","client":"claude-code","servers":["fs","git"]}
{"type":"gateway_route","server":"fs","tools":["read_file","list_directory"]}
```

Полная спецификация: [SPEC.md](SPEC.md).

## Квитанции

```sh
export MCP_ATTEST_KEY=…
attest receipts --trace examples/session.jsonl --out receipts.jsonl
# chain: ok (6 receipts, key=yes)
```

Каждая квитанция фиксирует предыдущую, поэтому удаление или перестановка квитанции рвёт цепочку. С заданным `MCP_ATTEST_KEY` каждая квитанция дополнительно подписывается HMAC-SHA256, и проверяющий может заметить правку, не имея доступа к шлюзу.

Это намеренно не PKI. Инструмент отвечает на вопрос, который действительно задаёт расследователь: *были ли в этой сессии именно эти вызовы, именно в этом порядке, и не менялось ли что-то с тех пор?*

## Использование в CI

```yaml
- uses: Balanov/mcp-attest@v0
  with:
    policy: .attest/policy.json
    trace: .attest/trace.jsonl
```

Экшен валит джобу при любой критичной или высокой находке, поэтому «наша политика для агентов применяется» — это то, что доказывает пайплайн, а не то, о чём спрашивает анкета по безопасности.

## Чем mcp-attest не является

- Не шлюз, не прокси и не точка enforcement: он не может заблокировать вызов.
- Не сканер: он не подключается к вашему MCP-серверу и не шлёт пробных запросов.
- Не PKI: хеш-цепочка и HMAC доказывают порядок и целостность, но не личность.
- Не редактор политик: он читает ту политику, которая уже есть.
- Не облачный сервис: без аккаунта, без сетевых вызовов, без телеметрии.

## Разработка

```sh
python -m pip install -e ".[dev]"
python -m unittest discover -s tests -v
```

CI гоняет тесты на Python 3.10–3.13 и публикует пакет на PyPI из тегированного релиза через trusted publishing: токена API в репозитории нет.

## Лицензия

[MIT](LICENSE). Копируйте, меняйте, встраивайте, публикуйте.
