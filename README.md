# Linux Policy Audit

Система выявления избыточных прав доступа в ОС Linux на основе
статического анализа конфигурации и динамического мониторинга.

## Что делает

Сравнивает права, разрешённые текущей конфигурацией, с правами,
фактически использованными за период наблюдения. Разница -
избыточные права, которые можно отозвать.

## Использование

```bash
# 1. Собрать снимок конфигурации
python3 run.py collect --dir /srv/test --db policy_audit.db --snapshot snapshot.json

# 2. Запустить мониторинг (требует root)
sudo python3 run.py monitor --dir /srv/test --db policy_audit.db \
    --snapshot snapshot.json --duration 60

# 3. Аудит избыточности
python3 run.py audit --db policy_audit.db --force --output report

# 4. Сгенерировать HTML-отчёт
python3 run.py report --db policy_audit.db --snapshot snapshot.json \
    --output report
```

## Требования

- Python 3.10+
- Linux (ядро 5.8+ для eBPF)
- bpftrace, graphviz

## Структура

- `collector.py` — сбор снимка конфигурации (ФС, ACL, FreeIPA)
- `monitor.py` — динамический мониторинг через bpftrace
- `analyzer.py` — расчёт избыточности, работа с состояниями политики
- `store.py` — хранилище на SQLite (WAL)
- `dac.py` — проверка прав POSIX и ACL
- `alerts.py` — оповещения (console, file, syslog, webhook)
- `visualizer.py` — визуализации (матрица, графы, машина состояний)
- `report_html.py` — HTML-отчёт
- `run.py` — точка входа CLI
