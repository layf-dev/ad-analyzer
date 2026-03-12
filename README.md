# AD Analyzer

`AD Analyzer` — локальная CLI-утилита для Blue Team, которая анализирует выгрузки `SharpHound/BloodHound` и формирует практический отчёт по рискам AD.

Проект не заменяет BloodHound. Он работает как надстройка для защитной команды: нормализует данные, запускает правила, считает приоритеты исправления, делает отчёт и diff между запусками.

## Что это за проект и для кого

Проект предназначен для:

- Blue Team / SOC
- AD/Windows администраторов
- пентест-команд при формате purple team
- инженеров, которым нужен локальный rules-based аудит AD без веб-сервера

Основная цель:

- быстро получить из `SharpHound.zip` структурированные findings
- понять, что критично и что чинить первым
- сравнивать состояние между запусками (новые/исчезнувшие/изменившиеся риски)

## Что делает AD Analyzer

Пайплайн работы:

1. Принимает `SharpHound.zip`.
2. Безопасно распаковывает архив в рабочую папку.
3. Загружает и классифицирует JSON-файлы (`users/groups/computers/domains/sessions/acls`).
4. Нормализует данные в единую модель `Node`/`Edge`.
5. Строит ориентированный граф AD (`networkx.MultiDiGraph`).
6. Запускает анализаторы (rules).
7. Обогащает findings:
- MITRE ATT&CK mapping
- risk score (0-100)
- remediation priority (`P1`..`P4`)
8. Опционально применяет allowlist (исключения).
9. Генерирует артефакты отчёта (`json/csv/md/html`).
10. По команде `diff` сравнивает два запуска.

## Что проект НЕ делает

- Не поднимает веб-сервер.
- Не сканирует сеть/AD напрямую.
- Не заменяет BloodHound UI/граф.
- Не “ищет магически всё” через LLM.
- Не изменяет AD, только анализирует выгрузку.

## Входные данные

Базовый вход:

- ZIP-архив SharpHound (`*.zip`) с JSON внутри.

Ожидаемые типы данных:

- `users.json`
- `groups.json`
- `computers.json`
- `domains.json`
- `sessions.json`
- `acls.json` / `acl.json` и похожие варианты имени (по имени файла с `acl`)

Если часть файлов отсутствует, анализ не останавливается: выводятся предупреждения, и отчёт строится по доступным данным.

## Безопасность обработки ZIP

Реализована строгая проверка архива перед распаковкой:

- защита от `zip-slip` (path traversal)
- лимит размера архива: `200 MB` (по умолчанию)
- лимит числа файлов: `2000`
- лимит суммарного распакованного объёма: `1 GB`
- разрешённые расширения внутри архива: `.json`, `.txt`

При нарушении лимитов утилита завершает работу с понятной ошибкой.

## Что происходит с данными

Обработка полностью локальная:

- архив распаковывается в `--out/unpacked`
- итоговые артефакты пишутся в `--out/artifacts`
- исходные данные не отправляются во внешние сервисы

Исключение:

- при флаге `--ollama` finding-контекст отправляется на локальный HTTP endpoint Ollama (`http://127.0.0.1:11434` по умолчанию)

## Внутренняя модель данных

Нормализация приводит данные к двум типам:

- `Node`: `id`, `type`, `name`, `attrs`
- `Edge`: `src_id`, `rel_type`, `dst_id`, `attrs`

Поддерживаемые типы узлов:

- `USER`
- `GROUP`
- `COMPUTER`
- `DOMAIN`

Ключевые типы связей:

- `MEMBER_OF`
- `HAS_SESSION`
- `ACL_RIGHT`

## Формат finding

Каждый finding содержит:

- `id` (стабильный детерминированный UUID на основе fingerprint)
- `title`
- `severity` (`CRITICAL/HIGH/MEDIUM/LOW`)
- `category`
- `affected_objects`
- `evidence` (`edges/path/raw_refs`)
- `why_risky`
- `how_to_verify`
- `fix_plan`
- `mitre_attack` (список tactic/technique)
- `risk_score` (0-100)
- `remediation_priority` (`P1..P4`)
- `notes` (опционально)
- `llm_explanation` (опционально)

## Реализованные анализаторы

1. `GROUP_PRIVILEGE`
- Поиск путей пользователя к привилегированным группам через вложенность `MEMBER_OF`.

2. `ADMINCOUNT`
- Поиск объектов с `adminCount=true`.

3. `ACL`
- Поиск опасных прав: `GenericAll`, `GenericWrite`, `WriteDacl`, `WriteOwner`, `AllExtendedRights`.

4. `DCSYNC`
- Поиск прав репликации каталога (`Replicating Directory Changes*`) на доменных объектах.

## MITRE ATT&CK mapping

Текущее соответствие по категориям:

- `DCSYNC` -> `TA0006 / T1003.006`
- `ACL` -> `TA0003 / T1098` и `TA0004 / T1098`
- `GROUP_PRIVILEGE` -> `TA0004 / T1078`
- `ADMINCOUNT` -> `TA0004 / T1078`

## Приоритизация и риск-скоринг

Для каждого finding рассчитывается:

- `risk_score` (0-100)
- `remediation_priority`:
- `P1` (самое срочное)
- `P2`
- `P3`
- `P4`

Скоринг настраивается через `--risk-config`.

## Выходные артефакты

В каталоге `--out`:

- `unpacked/` — распакованные исходные файлы
- `artifacts/findings.json` — полный список findings
- `artifacts/findings.csv` — табличный экспорт
- `artifacts/summary.json` — агрегированная сводка
- `artifacts/report.md` — человекочитаемый отчёт
- `artifacts/report.html` — опционально (`--html`)

Для сравнения запусков:

- `diff.json`
- `diff.md`

## Команды CLI

### 1. Анализ архива

```bash
ad-analyzer analyze <path_to_zip> --out <out_dir> [options]
```

Основные опции:

- `--html` — сгенерировать `report.html`
- `--open` — открыть HTML в браузере (если он создан)
- `--allowlist <file.json>` — применить исключения
- `--risk-config <file.json>` — переопределить веса скоринга
- `--ollama` — добавить LLM-пояснения
- `--ollama-model <name>` — модель Ollama (по умолчанию `llama3.1:8b`)
- `--verbose` — подробные логи

Пример:

```bash
ad-analyzer analyze sharphound.zip --out ./out --html --allowlist ./allowlist.json
```

### 2. Перегенерация отчётов из findings.json

```bash
ad-analyzer report <artifacts_dir> [options]
```

Опции:

- `--html`
- `--open`
- `--allowlist <file.json>`
- `--risk-config <file.json>`

### 3. Сравнение двух запусков

```bash
ad-analyzer diff <old_artifacts_or_findings.json> <new_artifacts_or_findings.json> --out <diff_dir>
```

Результат:

- новые findings
- resolved findings
- persistent findings
- изменения severity

### 4. Версия

```bash
ad-analyzer version
```

## Формат allowlist

Пример `allowlist.json`:

```json
{
  "categories": ["ADMINCOUNT"],
  "title_contains": ["legacy"],
  "affected_object_ids": ["S-1-5-21-...-1105"],
  "rules": [
    {
      "category": "ACL",
      "affected_object_id": "S-1-5-21-...-512",
      "severity": "MEDIUM"
    }
  ]
}
```

Поддерживаемые поля правила:

- `id`
- `category`
- `severity`
- `title_contains`
- `affected_object_id`

Логика:

- внутри одного rule все условия должны совпасть (`AND`)
- finding подавляется, если совпал хотя бы один rule (`OR` между rules)

## Формат risk-config

Пример `risk_config.json`:

```json
{
  "severity_base": {
    "CRITICAL": 92,
    "HIGH": 74,
    "MEDIUM": 50,
    "LOW": 25
  },
  "category_ease": {
    "DCSYNC": 98,
    "ACL": 88,
    "GROUP_PRIVILEGE": 80,
    "ADMINCOUNT": 40
  },
  "blend_base_weight": 0.75,
  "blend_ease_weight": 0.25,
  "affected_object_bonus_step": 2,
  "affected_object_bonus_cap": 10,
  "group_path_penalty_step": 2,
  "group_path_penalty_cap": 10,
  "priority_thresholds": {
    "P1": 85,
    "P2": 70,
    "P3": 50
  }
}
```

Можно указывать только часть полей: остальные берутся из дефолтного конфига.

## Ollama интеграция

При включении `--ollama`:

- для каждого finding формируется структурированный prompt
- модель должна объяснить риск и remediation без добавления новых фактов
- ответ сохраняется в `llm_explanation`

Если Ollama недоступна:

- анализ не падает
- просто пишется warning в лог

## Технологии и почему именно они

- `Python 3.10+` — быстрый запуск и удобная разработка CLI-инструмента.
- `Typer` — удобный и читаемый CLI с автогенерацией help.
- `Rich` — наглядные таблицы и вывод в консоли.
- `networkx` — гибкая работа с графом AD и путями.
- `Jinja2` — генерация HTML-отчёта по шаблону.
- `pytest` — проверка корректности ключевой логики.

## На каких системах можно запускать

Поддерживается любая система, где есть Python 3.10+:

- Windows
- Linux
- macOS

Утилита запускается локально на ноутбуке/рабочей станции/сервере без необходимости отдельного backend-сервиса.

## Установка

```bash
pip install -e .
```

Для разработки и тестов:

```bash
pip install -e .[dev]
```

## Быстрый старт

1. Получите `SharpHound.zip`.
2. Запустите анализ:

```bash
ad-analyzer analyze sharphound.zip --out ./out --html
```

3. Откройте:

- `./out/artifacts/report.md`
- `./out/artifacts/report.html`
- `./out/artifacts/findings.json`

## Тестирование проекта

Запуск тестов:

```bash
pytest -q tests
```

Тесты покрывают:

- безопасную распаковку ZIP
- нормализацию данных
- работу анализаторов
- allowlist/diff/risk-config/stable-id/MITRE mapping

## Ограничения

- Точность зависит от качества и полноты SharpHound-входа.
- Текущий набор правил ограничен реализованными анализаторами.
- MITRE mapping задан на уровне категорий finding (а не всех частных кейсов).
- Это rules-based анализатор, не ML/AI-детектор новых классов атак.

## Лицензия и версия

- Лицензия: `MIT`
- Текущая версия: `0.1.0`

