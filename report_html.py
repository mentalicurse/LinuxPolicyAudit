#!/usr/bin/env python3
"""Формирует HTML-отчёт из снимка, результатов аудита и визуализаций."""

from __future__ import annotations

import base64
import os
import time
from html import escape


def _e(value) -> str:
    return escape(str(value), quote=True)


def _octal_to_rwx(s: str) -> str:
    try:
        val = int(s, 8) & 0o777
        bits = ""
        for i in range(9):
            bits += "rwx"[i % 3] if val & (0o400 >> i) else "-"
        return f"{bits[:3]}-{bits[3:6]}-{bits[6:]}"
    except Exception:
        return s


def _rel(path: str, root: str) -> str:
    try:
        r = os.path.relpath(path, root)
        return r if r != "." else "[корень]"
    except ValueError:
        return path


def _embed_image(path: str) -> str:
    if not os.path.exists(path):
        return ""
    with open(path, "rb") as f:
        return f"data:image/png;base64,{base64.b64encode(f.read()).decode()}"


def _fmt_ts(ts: float) -> str:
    if not ts:
        return "—"
    return time.strftime("%d.%m.%Y %H:%M:%S", time.localtime(ts))


_CSS = """
* { box-sizing: border-box; margin: 0; padding: 0; }
html { -webkit-font-smoothing: antialiased; }
body {
  font-family: 'Charter', 'Georgia', 'Iowan Old Style', 'Times New Roman', serif;
  background: #f0f0f0;
  color: #111;
  line-height: 1.65;
  font-size: 15px;
}
.page {
  max-width: 1120px;
  margin: 32px auto;
  padding: 56px 64px 72px;
  background: #ffffff;
  border: 1px solid #d0d0d0;
  box-shadow: 0 2px 8px rgba(0,0,0,0.04);
}
h1 {
  font-family: 'Charter', 'Georgia', serif;
  font-size: 28px;
  font-weight: 400;
  letter-spacing: -0.01em;
  line-height: 1.25;
  color: #000;
  padding-bottom: 20px;
  margin-bottom: 36px;
  border-bottom: 2px solid #000;
}
h2 {
  font-family: 'Charter', 'Georgia', serif;
  font-size: 19px;
  font-weight: 700;
  color: #000;
  margin-bottom: 16px;
  padding-bottom: 8px;
  border-bottom: 1px solid #b0b0b0;
}
h3 {
  font-family: 'Helvetica Neue', 'Arial', sans-serif;
  font-size: 11px;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.16em;
  color: #333;
  margin: 28px 0 12px;
}
.card {
  background: #fff;
  border: 1px solid #c0c0c0;
  border-top: 3px solid #000;
  padding: 24px 28px 12px;
  margin-bottom: 32px;
}
.card-info,
.card-warning,
.card-danger,
.card-success { border-top: 3px solid #000; }
.metrics {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 0;
  margin: 24px 0 32px;
  border: 1px solid #000;
}
.metric {
  padding: 26px 14px 24px;
  text-align: center;
  border-right: 1px solid #d0d0d0;
  background: #fcfcfc;
}
.metric:last-child { border-right: none; }
.metric-num {
  font-family: 'Charter', 'Georgia', serif;
  font-size: 42px;
  font-weight: 400;
  line-height: 1;
  color: #000;
  letter-spacing: -0.03em;
}
.metric-label {
  font-family: 'Helvetica Neue', 'Arial', sans-serif;
  font-size: 10px;
  font-weight: 700;
  color: #444;
  letter-spacing: 0.16em;
  text-transform: uppercase;
  margin-top: 12px;
}
.badge {
  display: inline-block;
  padding: 2px 9px;
  font-family: 'Helvetica Neue', 'Arial', sans-serif;
  font-size: 10px;
  font-weight: 700;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  color: #000;
  background: #f5f5f5;
  border: 1px solid #888;
  border-radius: 2px;
}
.b-red  { background: #1a1a1a; color: #fff; border-color: #1a1a1a; }
.b-ylw  { background: #d8d8d8; color: #000; border-color: #888; }
.b-grn  { background: #f0f0f0; color: #000; border-color: #666; }
.b-blu  { background: #f0f0f0; color: #000; border-color: #666; }
.b-gray { background: #f5f5f5; color: #000; border-color: #aaa; }
.b-prp  { background: #ededed; color: #000; border-color: #888; }
code {
  background: #f0f0f0;
  padding: 2px 7px;
  font-size: 12.5px;
  font-family: 'SFMono-Regular', 'Consolas', 'Menlo', 'Courier New', monospace;
  color: #000;
  border: 1px solid #e0e0e0;
  border-radius: 2px;
}
table {
  width: 100%;
  border-collapse: collapse;
  font-family: 'Helvetica Neue', 'Arial', sans-serif;
  font-size: 12.5px;
  margin-top: 10px;
  border: 1px solid #000;
}
th, td {
  padding: 11px 14px;
  text-align: left;
  vertical-align: top;
  border-bottom: 1px solid #e0e0e0;
  border-right: 1px solid #f0f0f0;
}
th {
  background: #000;
  color: #fff;
  font-size: 10px;
  font-weight: 700;
  letter-spacing: 0.14em;
  text-transform: uppercase;
  border-bottom: 1px solid #000;
  border-right: 1px solid #333;
}
th:last-child { border-right: none; }
tbody tr:nth-child(even) td { background: #fafafa; }
tbody tr:hover td           { background: #f2f2f2; }
.toc {
  background: #fafafa;
  border: 1px solid #c0c0c0;
  padding: 22px 26px;
  margin-bottom: 36px;
}
.toc h3 { margin-top: 0; }
.toc ol { padding-left: 24px; }
.toc li {
  margin: 6px 0;
  font-family: 'Helvetica Neue', 'Arial', sans-serif;
  font-size: 13px;
}
.toc a {
  color: #000;
  text-decoration: none;
  border-bottom: 1px solid #999;
  padding-bottom: 1px;
}
.toc a:hover { border-bottom-color: #000; }
.img-card {
  text-align: center;
  padding: 24px 20px;
  border-top: 3px solid #000;
  background: #fcfcfc;
}
.img-card img {
  max-width: 100%;
  border: 1px solid #c0c0c0;
  margin-top: 16px;
  background: #fff;
  padding: 8px;
}
footer {
  text-align: center;
  color: #666;
  font-family: 'Helvetica Neue', 'Arial', sans-serif;
  font-size: 10px;
  letter-spacing: 0.16em;
  text-transform: uppercase;
  border-top: 2px solid #000;
  padding-top: 24px;
  margin-top: 48px;
}
@media print {
  body { background: #fff; }
  .page { box-shadow: none; margin: 0; padding: 24px; border: none; }
  .toc { display: none; }
  .card { break-inside: avoid; }
  .img-card { break-inside: avoid; }
}
"""


def _section_summary(snap, audit, verify=None, all_states=None):
    ts = _fmt_ts(snap.get("timestamp", 0))
    hsh = _e(snap.get("snapshot_hash", "?"))
    tgt = _e(snap.get("target_dir", "?"))
    warm_up_html = ""
    if audit and getattr(audit, "warm_up", False):
        warm_up_html = ('<div class="card card-warning"><h2>Warm-up</h2>'
                        '<p style="color:#666">Текущая версия политики моложе окна наблюдения. '
                        'Избыточность не рассчитывается.</p></div>')
    if audit:
        total = audit.total_rights
        used = audit.used_rights
        pct = audit.redundancy_pct
        viols = len(audit.violations)
        window = f"{audit.window_days:.0f} дн." if audit.window_days else "вся история"
        events = audit.events_observed
    else:
        total = used = viols = events = 0
        pct = 0.0
        window = "—"
    ver_badge = ""
    if verify is not None:
        ver_badge = ('<span class="badge b-grn">Конфиг соответствует политике</span>'
                     if verify.ok else
                     f'<span class="badge b-red">Расхождений: {len(verify.issues)}</span>')
    states_html = ""
    if all_states:
        rows = ""
        for st in all_states:
            rows += f"""<tr>
  <td><code>#{st.state_id}</code></td>
  <td>{_fmt_ts(st.timestamp)}</td>
  <td>{st.subject_count}</td>
  <td>{st.object_count}</td>
  <td>{st.total_rights}</td>
  <td>{st.used_rights}</td>
  <td>{st.redundant_rights}</td>
  <td>{st.violations}</td></tr>"""
        states_html = f"""
<h3 style="margin-top:22px">Состояния политики ({len(all_states)})</h3>
<table><thead><tr>
  <th>#</th><th>Время</th><th>Субъектов</th><th>Объектов</th>
  <th>Всего прав</th><th>Использовано</th><th>Избыточно</th><th>Нарушений</th>
</tr></thead><tbody>{rows}</tbody></table>
"""
    return f"""
<div class="card card-info">
  <h2>Сводка аудита</h2>
  <p style="font-size:13px;color:#333;margin-bottom:8px">
    Каталог: <code>{tgt}</code> &nbsp;|&nbsp;
    Снят: <b>{ts}</b> &nbsp;|&nbsp; Hash: <code>{hsh}</code>
    {('&nbsp;|&nbsp;' + ver_badge) if ver_badge else ''}
  </p>
  <p style="font-size:12px;color:#666">
    Окно наблюдения: <b>{window}</b> &nbsp;|&nbsp;
    Событий доступа: <b>{events}</b>
  </p>
  {states_html}
</div>
{warm_up_html}
<div class="metrics">
  <div class="metric"><div class="metric-num">{total}</div>
    <div class="metric-label">Всего прав (DAC)</div></div>
  <div class="metric"><div class="metric-num">{used}</div>
    <div class="metric-label">Использовано</div></div>
  <div class="metric"><div class="metric-num">{pct}%</div>
    <div class="metric-label">Избыточность</div></div>
  <div class="metric"><div class="metric-num">{viols}</div>
    <div class="metric-label">Нарушений</div></div>
</div>
"""


def _section_snapshot(snap):
    root = snap.get("target_dir", "")
    subjects = snap.get("subjects", {})
    objects = snap.get("objects", {})
    subj_rows = ""
    for name, info in sorted(subjects.items()):
        gnames = ", ".join(info.get("groups", []))
        gids = ", ".join(str(g) for g in info.get("gids", []))
        subj_rows += f"""<tr><td><code>{_e(name)}</code></td><td>{info.get('uid','?')}</td>
    <td><code>{_e(gids)}</code></td><td>{_e(gnames)}</td></tr>"""
    obj_rows = ""
    for path, info in sorted(objects.items()):
        rel = _rel(path, root)
        mode = info.get("mode", "0000")
        typ = info.get("obj_type", "file")
        typ_badge = f'<span class="badge {"b-blu" if typ=="directory" else "b-gray"}">{typ}</span>'
        obj_rows += f"""<tr><td><code>{_e(rel)}</code></td><td>{typ_badge}</td>
    <td>{_e(info.get('owner', info.get('uid','?')))}</td>
    <td>{_e(info.get('group', info.get('gid','?')))}</td>
    <td><code>{_e(mode)}</code></td>
    <td><span class="badge b-prp">{_e(_octal_to_rwx(mode))}</span></td></tr>"""
    return f"""
<div id="s-snapshot" class="card">
  <h2>3. Статический снимок</h2>
  <h3 style="margin-top:14px">Субъекты ({len(subjects)})</h3>
  <table><thead><tr><th>Пользователь</th><th>UID</th><th>GIDs</th><th>Группы</th></tr></thead>
  <tbody>{subj_rows}</tbody></table>
  <h3 style="margin-top:20px">Объекты ФС ({len(objects)})</h3>
  <table><thead><tr><th>Путь</th><th>Тип</th><th>Владелец</th><th>Группа</th><th>Octal</th><th>Вектор</th></tr></thead>
  <tbody>{obj_rows}</tbody></table>
</div>"""


def _section_violations(audit, root):
    if not audit or not audit.violations:
        return ('<div id="s-violations" class="card card-success">'
                '<h2>Попытки нарушения политики доступа</h2>'
                '<p style="color:#666">Нарушений не обнаружено.</p></div>')
    rows = ""
    for v in audit.violations:
        rows += f"""<tr>
  <td>{_fmt_ts(v.get('timestamp'))}</td>
  <td><code>{_e(v.get('subject','?'))}</code></td>
  <td><code title="{_e(v.get('path',''))}">{_e(os.path.basename(v.get('path','?')))}</code></td>
  <td><span class="badge b-red">{_e(v.get('action','?').upper())}</span></td></tr>"""
    return f"""
<div id="s-violations" class="card card-danger">
  <h2>Попытки нарушения политики доступа ({len(audit.violations)})</h2>
  <p style="font-size:12px;color:#666;margin-bottom:12px">
    События, при которых ядро отклонило доступ: у субъекта нет
    соответствующих прав на объект. Не всякий отказ является
    злонамеренным действием — часть из них может быть следствием
    ошибки пользователя или программы.
  </p>
  <table><thead><tr><th>Время</th><th>Субъект</th><th>Объект</th><th>Действие</th></tr></thead>
  <tbody>{rows}</tbody></table>
</div>"""


def _section_transitions(items):
    """Универсальная секция: принимает как сырые transitions из БД



    (с reason/details), так и обогащённые (с subject/command)."""
    if not items:
        return ('<div id="s-transitions" class="card card-success">'
                '<h2>Изменения политики</h2>'
                '<p style="color:#666">Переходов не зафиксировано.</p></div>')

    # Определяем формат по наличию ключевых полей.

    enriched = "subject" in items[0] or "command" in items[0]
    rows = ""
    for tr in items:
        ts = tr.get("ts", tr.get("timestamp", 0))
        from_id = tr.get("from_state_id", "—")
        to_id = tr.get("to_state_id", "—")
        if enriched:
            subj = tr.get("subject", "—")
            cmd = tr.get("command", "—")
        else:
            subj = "—"
            cmd = tr.get("details", "") or tr.get("reason", "") or "—"
        rows += f"""<tr>
  <td>{_fmt_ts(ts)}</td>
  <td><code>#{from_id}</code></td>
  <td><code>#{to_id}</code></td>
  <td><code>{_e(subj)}</code></td>
  <td style="font-size:12px"><code>{_e(cmd)}</code></td></tr>"""
    return f"""
<div id="s-transitions" class="card card-info">
  <h2>Изменения политики ({len(items)})</h2>
  <p style="font-size:12px;color:#666;margin-bottom:12px">
    Каждая строка — момент, когда конфигурация изменилась: от какого
    состояния к какому произошёл переход, кто инициировал и какой командой.
  </p>
  <table><thead><tr>
    <th>Время</th><th>От</th><th>К</th><th>Инициатор</th><th>Команда</th>
  </tr></thead><tbody>{rows}</tbody></table>
</div>"""


def _section_redundant(audit, root):
    if not audit or not audit.redundant:
        return ('<div id="s-redundant" class="card card-success">'
                '<h2>1. Избыточность за окно</h2>'
                '<p style="color:#666">Избыточных прав не найдено.</p></div>')
    from collections import defaultdict
    grouped, mode_map = defaultdict(list), {}
    for r in audit.redundant:
        grouped[(r.subject, r.path)].append(r.action)
        mode_map[(r.subject, r.path)] = r.last_mode
    rows = ""
    for (subj, path), acts in sorted(grouped.items()):
        acts_html = " ".join(f'<span class="badge b-ylw">{_e(a.upper())}</span>' for a in acts)
        rows += f"""<tr>
  <td><code>{_e(subj)}</code></td>
  <td><code title="{_e(path)}">{_e(_rel(path, root))}</code></td>
  <td>{acts_html}</td>
  <td><code>{_e(mode_map[(subj, path)])}</code></td></tr>"""
    window = f"{audit.window_days:.0f} дней" if audit.window_days else "весь период"
    return f"""
<div id="s-redundant" class="card card-warning">
  <h2>1. Избыточность за окно ({len(audit.redundant)})</h2>
  <p style="font-size:12px;color:#666;margin-bottom:12px">
    Права, разрешённые в текущей конфигурации и не использованные за окно ({window}).
    Учитывается traversal: read файла автоматически включает execute на его родителях.
  </p>
  <table><thead><tr><th>Субъект</th><th>Объект</th><th>Избыточные права</th><th>Маска</th></tr></thead>
  <tbody>{rows}</tbody></table>
</div>"""


def _section_historical_redundant(audit, root):
    if not audit or not getattr(audit, "historical_redundant", None):
        return ('<div id="s-historical-redundant" class="card">'
                '<h2>4. Историческая избыточность</h2>'
                '<p style="color:#666">Не найдено.</p></div>')
    from collections import defaultdict
    grouped, mode_map, seen_map = defaultdict(list), {}, {}
    for r in audit.historical_redundant:
        grouped[(r.subject, r.path)].append(r.action)
        mode_map[(r.subject, r.path)] = r.last_mode
        seen_map[(r.subject, r.path)] = max(seen_map.get((r.subject, r.path), 0), r.versions_seen)
    rows = ""
    for (subj, path), acts in sorted(grouped.items()):
        acts_html = " ".join(f'<span class="badge b-ylw">{_e(a.upper())}</span>' for a in acts)
        rows += f"""<tr>
  <td><code>{_e(subj)}</code></td>
  <td><code title="{_e(path)}">{_e(_rel(path, root))}</code></td>
  <td>{acts_html}</td>
  <td><code>{_e(mode_map[(subj, path)])}</code></td>
  <td>{seen_map[(subj, path)]}</td></tr>"""
    return f"""
<div id="s-historical-redundant" class="card card-warning">
  <h2>4. Историческая избыточность ({len(audit.historical_redundant)})</h2>
  <p style="font-size:12px;color:#666;margin-bottom:12px">
    Право присутствует в текущей политике и не использовалось ни в одной версии,
    где оно было разрешено. Traversal-разворот применён.
  </p>
  <table><thead><tr><th>Субъект</th><th>Объект</th><th>Права</th><th>Маска</th><th>Версий без исп.</th></tr></thead>
  <tbody>{rows}</tbody></table>
</div>"""


def _section_window_usage(audit):
    used = getattr(audit, "used_triples", set())
    if not audit or not used:
        return ('<div id="s-window-usage" class="card">'
                '<h2>5. Использование за окно</h2>'
                '<p style="color:#666">Событий не найдено.</p></div>')
    current_allowed = getattr(audit, "current_allowed", set())

    # Пары (subject, path) из policy_changes с create_file — чтобы

    # показывать CREATE вместо WRITE в отчёте.

    created = {
        (ch.get("subject"), ch.get("path"))
        for ch in getattr(audit, "policy_changes", [])
        if ch.get("action") == "create_file"
    }
    rows = ""
    for subject, path, action in sorted(used):
        status = ('<span class="badge b-grn">still granted</span>'
                  if (subject, path, action) in current_allowed else
                  '<span class="badge b-ylw">historical only</span>')
        if action == "write" and (subject, path) in created:
            display = "CREATE"
        else:
            display = action.upper()
        rows += f"""<tr>
  <td><code>{_e(subject)}</code></td>
  <td><code title="{_e(path)}">{_e(os.path.basename(path) or path)}</code></td>
  <td><span class="badge b-blu">{display}</span></td>
  <td>{status}</td></tr>"""
    return f"""
<div id="s-window-usage" class="card">
  <h2>5. Использование за окно ({len(used)} триплетов)</h2>
  <p style="font-size:12px;color:#666;margin-bottom:12px">
    Сырые события bpftrace. CREATE — файл впервые появился в окне наблюдения,
    WRITE — открытие существующего файла на запись. Без traversal.
  </p>
  <table><thead><tr>
    <th>Субъект</th><th>Объект</th><th>Действие</th><th>Статус</th>
  </tr></thead><tbody>{rows}</tbody></table>
</div>"""


def _section_usage_history(audit):
    if not audit or not getattr(audit, "historical_used_triples", None):
        return ('<div id="s-history-usage" class="card">'
                '<h2>6. Использование за всё время</h2>'
                '<p style="color:#666">Нет данных.</p></div>')
    rows = ""
    for subject, path, action in sorted(audit.historical_used_triples):
        rows += f"""<tr>
  <td><code>{_e(subject)}</code></td>
  <td><code title="{_e(path)}">{_e(os.path.basename(path) or path)}</code></td>
  <td><span class="badge b-grn">{_e(action.upper())}</span></td></tr>"""
    return f"""
<div id="s-history-usage" class="card">
  <h2>6. Использование за всё время ({len(audit.historical_used_triples)} триплетов)</h2>
  <p style="font-size:12px;color:#666;margin-bottom:12px">
    Все события доступа за весь период наблюдения. Дополнительный контекст.
  </p>
  <table><thead><tr><th>Субъект</th><th>Путь</th><th>Действие</th></tr></thead>
  <tbody>{rows}</tbody></table>
</div>"""


def _section_images(out_dir):
    images = [
        ("rights_matrix.png", "Матрица прав доступа"),
        ("state_machine.png", "Переходы состояний политики"),
        ("usage_graph.png", "Использование прав в текущем окне"),
        ("usage_history_graph.png", "Использование прав за всё время"),
    ]
    html = '<div id="s-images">\n'
    found = False
    for fname, caption in images:
        uri = _embed_image(os.path.join(out_dir, fname))
        if not uri:
            continue
        found = True
        html += (f'<div class="card img-card"><h2>{caption}</h2>'
                 f'<img src="{uri}" alt="{caption}"></div>\n')
    if not found:
        html += '<div class="card"><p style="color:#666">Визуализации не найдены.</p></div>\n'
    html += "</div>\n"
    return html


def generate_html_report(snap, audit, verify=None,
                         out="report/report.html",
                         all_states=None,
                         enriched_transitions=None,
                         state_transitions=None) -> None:
    """Собирает HTML-отчёт.



    Аргументы:

      snap                  — dict снимка (target_dir, subjects, objects, ...)

      audit                 — AuditResult или None

      verify                — VerifyResult или None (в минимальной версии не используется)

      all_states            — список _StateSummary для таблицы «Состояния политики»

      enriched_transitions  — transitions с полями subject/command (приоритет)

      state_transitions     — сырые transitions из БД (fallback)

    """
    out_dir = os.path.dirname(out) or "."
    root = snap.get("target_dir", "")
    transitions_for_report = enriched_transitions or state_transitions or []
    toc = """
<div class="toc"><h3>Содержание</h3><ol>
  <li><a href="#s-summary">Сводка</a></li>
  <li><a href="#s-snapshot">Статический снимок</a></li>
  <li><a href="#s-violations">Попытки нарушения политики доступа</a></li>
  <li><a href="#s-transitions">Изменения политики</a></li>
  <li><a href="#s-redundant">Избыточность за окно</a></li>
  <li><a href="#s-historical-redundant">Историческая избыточность</a></li>
  <li><a href="#s-window-usage">Использование за окно</a></li>
  <li><a href="#s-images">Визуализации</a></li>
</ol></div>
"""
    body = "\n".join([
        '<div id="s-summary">' + _section_summary(snap, audit, verify,
                                                  all_states=all_states) + '</div>',
        toc,
        _section_snapshot(snap),
        _section_violations(audit, root),
        _section_transitions(transitions_for_report),
        _section_redundant(audit, root),
        _section_historical_redundant(audit, root),
        _section_window_usage(audit),
        _section_usage_history(audit),
        _section_images(out_dir),
    ])
    html = f"""<!DOCTYPE html>
<html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Отчёт об аудите прав доступа</title><style>{_CSS}</style></head>
<body><div class="page">
  <h1>Linux Policy Audit. Отчёт об аудите прав доступа</h1>
  {body}
  <footer>Сгенерировано: {_fmt_ts(time.time())} · Linux Policy Audit</footer>
</div></body></html>"""
    os.makedirs(out_dir, exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"[report] HTML-отчёт: {out}")
