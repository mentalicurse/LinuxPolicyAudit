#!/usr/bin/env python3
"""
analyzer.py — анализ прав доступа.

Избыточность — это разрешённые права, не использованные за выбранный период.
При расчёте учитываются права execute на родительских каталогах, необходимые
Linux для обхода пути. Историческая избыточность учитывает версии политики,
в которых право существовало, и считается только если оно ни разу не использовалось.
"""
from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass, field

from dac import AccessChecker, default_checker
from store import EventStore


log = logging.getLogger("analyzer")


# Верификация

@dataclass
class PolicyRule:
    subject: str
    path:    str
    action:  str
    allow:   bool


@dataclass
class VerifyIssue:
    kind:    str
    subject: str
    path:    str
    action:  str
    detail:  str


@dataclass
class VerifyResult:
    ok:     bool
    issues: list[VerifyIssue] = field(default_factory=list)

    def add(self, kind, subject, path, action, detail) -> None:
        self.issues.append(VerifyIssue(kind, subject, path, action, detail))
        self.ok = False


def verify_config(policy_rules, snapshot, checker=None, subject=None) -> VerifyResult:
    checker  = checker or default_checker()
    result   = VerifyResult(ok=True)
    subjects = snapshot.get("subjects", {})
    objects  = snapshot.get("objects",  {})
    root_dir = snapshot.get("target_dir", "")

    if subject is not None:
        policy_rules = [r for r in policy_rules if r.subject == subject]

    for rule in policy_rules:
        sub_info = subjects.get(rule.subject)
        obj_info = objects.get(rule.path)

        if sub_info is None:
            result.add("object_missing", rule.subject, rule.path, rule.action,
                       f"Субъект '{rule.subject}' не найден в снимке")
            continue
        if obj_info is None:
            result.add("object_missing", rule.subject, rule.path, rule.action,
                       f"Объект '{rule.path}' не найден в снимке")
            continue

        obj_info = dict(obj_info)
        obj_info["path"] = rule.path

        actual_allowed = checker.check_with_path(
            sub_info, obj_info, rule.action, objects, root_dir
        )

        if rule.allow and not actual_allowed:
            result.add("missing_allow", rule.subject, rule.path, rule.action,
                       f"Политика: РАЗРЕШИТЬ {rule.action} — реально: ЗАПРЕЩЕНО "
                       f"(mode={obj_info.get('mode')})")
        elif not rule.allow and actual_allowed:
            result.add("unexpected_allow", rule.subject, rule.path, rule.action,
                       f"Политика: ЗАПРЕТИТЬ {rule.action} — реально: РАЗРЕШЕНО "
                       f"(mode={obj_info.get('mode')})")

    return result


# Результаты верификации, аудита и сравнения состояний.

@dataclass
class RedundantRight:
    subject:   str
    path:      str
    action:    str
    last_mode: str


@dataclass
class HistoricalRedundantRight:
    subject:   str
    path:      str
    action:    str
    last_mode: str
    versions_seen: int = 0


@dataclass
class StructuralRight:
    subject: str
    path: str
    action: str
    reason: str


@dataclass
class StateTransitionImpact:
    from_state_id: int | None
    to_state_id: int | None
    subject: str
    path: str
    action: str
    diff: str
    timestamp: float = 0.0


@dataclass
class AuditResult:
    window_days:                 float
    since_timestamp:             float
    total_rights:                int
    used_rights:                 int
    redundant_rights:            int
    redundancy_pct:              float
    redundant:                   list[RedundantRight] = field(default_factory=list)
    historical_redundant:        list[HistoricalRedundantRight] = field(default_factory=list)
    structural:                  list[StructuralRight] = field(default_factory=list)
    state_transition_impacts:    list[StateTransitionImpact] = field(default_factory=list)
    violations:                  list[dict]           = field(default_factory=list)
    policy_changes:              list[dict]           = field(default_factory=list)
    used_triples:                set[tuple[str, str, str]] = field(default_factory=set)
    historical_used_triples:     set[tuple[str, str, str]] = field(default_factory=set)
    current_allowed:             set[tuple[str, str, str]] = field(default_factory=set)
    events_observed:             int = 0
    warm_up:                     bool = False
    forced:                      bool = False


@dataclass
class StateDiffEntry:
    kind: str
    subject: str | None
    path: str | None
    action: str | None
    old_value: object = None
    new_value: object = None
    detail: str = ""


@dataclass
class StateSummary:
    state_id: int
    timestamp: float
    subject_count: int
    object_count: int
    total_rights: int
    used_rights: int
    redundant_rights: int
    violations: int


@dataclass
class StateReport:
    from_state_id: int | None
    to_state_id: int | None
    from_summary: StateSummary | None
    to_summary: StateSummary | None
    diff: list[StateDiffEntry]

    @property
    def changed_count(self) -> int:
        return len(self.diff)


# Использованные права с учётом обхода родительских каталогов.

def _expand_used_with_traversal(
    used: set[tuple[str, str, str]],
    objects: dict[str, dict],
    target_dir: str,
) -> set[tuple[str, str, str]]:
    """Добавляет право execute на родительские каталоги использованных объектов."""
    if not used or not objects:
        return used

    root = os.path.realpath(target_dir) if target_dir else ""
    expanded = set(used)

    for (sub, path, act) in used:
        obj = objects.get(path, {})
        obj_type = obj.get("obj_type", "file")

        if obj_type == "directory" and act == "execute":
            continue

        parent = os.path.dirname(path)
        seen: set[str] = set()
        while parent and parent != root and parent.startswith(root):
            if parent in seen:
                break
            seen.add(parent)
            if parent in objects:
                expanded.add((sub, parent, "execute"))
            parent = os.path.dirname(parent)

    return expanded


def build_state_summary(state_id: int, snapshot: dict, store: EventStore,
                        checker: AccessChecker | None = None) -> StateSummary:
    checker = checker or default_checker()
    subjects = snapshot.get("subjects", {}) or {}
    objects = snapshot.get("objects", {}) or {}
    root_dir = snapshot.get("target_dir", "")

    ever_allowed: set[tuple] = set()
    for obj_path, obj_info in objects.items():
        obj_info = dict(obj_info)
        obj_info["path"] = obj_path
        for sub_name, sub_info in subjects.items():
            for action in ("read", "write", "execute"):
                if checker.check(sub_info, obj_info, action):
                    ever_allowed.add((sub_name, obj_path, action))

    used_raw = store.get_used_triples(version_id=state_id)
    used = _expand_used_with_traversal(used_raw, objects, root_dir)
    redundant = ever_allowed - used

    return StateSummary(
        state_id=state_id,
        timestamp=snapshot.get("timestamp", 0),
        subject_count=len(subjects),
        object_count=len(objects),
        total_rights=len(ever_allowed),
        used_rights=len(ever_allowed & used),
        redundant_rights=len(redundant),
        violations=len(store.get_violations(version_id=state_id)),
    )


def generate_state_report(
    store: EventStore,
    from_state_id: int | None = None,
    to_state_id: int | None = None,
) -> StateReport:
    versions = store.get_policy_versions()
    if not versions:
        return StateReport(from_state_id, to_state_id, None, None, [])

    if from_state_id is None and to_state_id is None:
        if len(versions) < 2:
            return StateReport(
                from_state_id=None,
                to_state_id=versions[0][0],
                from_summary=None,
                to_summary=build_state_summary(versions[0][0], versions[0][1], store),
                diff=[],
            )
        from_state_id, _ = versions[1]
        to_state_id, _ = versions[0]
    elif from_state_id is None:
        candidates = [vid for vid, _ in versions if vid != to_state_id]
        if not candidates:
            return StateReport(None, to_state_id,
                               None,
                               build_state_summary(to_state_id, store.get_policy_version_by_id(to_state_id)[1], store),
                               [])
        from_state_id = candidates[0]
    elif to_state_id is None:
        candidates = [vid for vid, _ in versions if vid != from_state_id]
        if not candidates:
            return StateReport(from_state_id, None,
                               build_state_summary(from_state_id, store.get_policy_version_by_id(from_state_id)[1], store),
                               None, [])
        to_state_id = candidates[0]

    old_version = store.get_policy_version_by_id(from_state_id)
    new_version = store.get_policy_version_by_id(to_state_id)
    if old_version is None or new_version is None:
        return StateReport(from_state_id, to_state_id, None, None, [])

    old_snapshot = old_version[1]
    new_snapshot = new_version[1]
    from_summary = build_state_summary(from_state_id, old_snapshot, store)
    to_summary = build_state_summary(to_state_id, new_snapshot, store)
    diff = diff_states(old_snapshot, new_snapshot)

    return StateReport(from_state_id, to_state_id, from_summary, to_summary, diff)


def diff_states(old_state: dict | None, new_state: dict | None) -> list[StateDiffEntry]:
    if not old_state or not new_state:
        return []

    old_subjects = old_state.get("subjects", {}) or {}
    new_subjects = new_state.get("subjects", {}) or {}
    old_objects = old_state.get("objects", {}) or {}
    new_objects = new_state.get("objects", {}) or {}

    diff: list[StateDiffEntry] = []

    for name in sorted(set(old_subjects) - set(new_subjects)):
        diff.append(StateDiffEntry("subject_removed", name, None, None,
                                   old_value=True, new_value=False,
                                   detail=f"Субъект '{name}' удалён"))
    for name in sorted(set(new_subjects) - set(old_subjects)):
        diff.append(StateDiffEntry("subject_added", name, None, None,
                                   old_value=False, new_value=True,
                                   detail=f"Субъект '{name}' добавлен"))
    for name in sorted(set(old_subjects) & set(new_subjects)):
        if old_subjects[name].get("groups") != new_subjects[name].get("groups"):
            diff.append(StateDiffEntry(
                "subject_groups_changed", name, None, None,
                old_value=old_subjects[name].get("groups"),
                new_value=new_subjects[name].get("groups"),
                detail=f"Группы субъекта '{name}' изменились",
            ))

    for path in sorted(set(old_objects) - set(new_objects)):
        diff.append(StateDiffEntry("object_removed", None, path, None,
                                   old_value=True, new_value=False,
                                   detail=f"Объект '{path}' удалён"))
    for path in sorted(set(new_objects) - set(old_objects)):
        diff.append(StateDiffEntry("object_added", None, path, None,
                                   old_value=False, new_value=True,
                                   detail=f"Объект '{path}' добавлен"))

    for path in sorted(set(old_objects) & set(new_objects)):
        old_info, new_info = old_objects[path], new_objects[path]
        if old_info.get("mode") != new_info.get("mode"):
            diff.append(StateDiffEntry(
                "mode_changed", None, path, None,
                old_value=old_info.get("mode"), new_value=new_info.get("mode"),
                detail=f"Режим объекта '{path}' изменён"))
        if old_info.get("acl") != new_info.get("acl"):
            diff.append(StateDiffEntry(
                "acl_changed", None, path, None,
                old_value=old_info.get("acl"), new_value=new_info.get("acl"),
                detail=f"ACL объекта '{path}' изменён"))

    checker = default_checker()
    all_actions = ("read", "write", "execute")
    all_paths = sorted(set(old_objects) | set(new_objects))
    all_subjects = sorted(set(old_subjects) | set(new_subjects))

    for subject in all_subjects:
        old_sub = old_subjects.get(subject)
        new_sub = new_subjects.get(subject)
        if old_sub is None or new_sub is None:
            continue
        for path in all_paths:
            old_obj = old_objects.get(path)
            new_obj = new_objects.get(path)
            if old_obj is None or new_obj is None:
                continue
            for action in all_actions:
                old_allowed = checker.check_with_path(
                    old_sub, {**old_obj, "path": path}, action,
                    old_objects, old_state.get("target_dir", ""))
                new_allowed = checker.check_with_path(
                    new_sub, {**new_obj, "path": path}, action,
                    new_objects, new_state.get("target_dir", ""))
                if old_allowed != new_allowed:
                    diff.append(StateDiffEntry(
                        "right_changed", subject, path, action,
                        old_value=old_allowed, new_value=new_allowed,
                        detail=f"Доступ '{action}' для '{subject}' на '{path}' изменён"))

    return diff


# Аудит избыточности

_SCRIPT_EXTS = {".sh", ".py", ".rb", ".pl", ".bash", ".zsh"}


def audit_redundancy(
    store:       EventStore,
    window_days: float | None = None,
    checker:     AccessChecker | None = None,
    force:       bool = False,
    subject:     str | None = None,
) -> AuditResult:
    checker = checker or default_checker()

    current = store.get_current_policy_version()
    if current is None:
        return AuditResult(
            window_days=window_days or 0, since_timestamp=0,
            total_rights=0, used_rights=0, redundant_rights=0, redundancy_pct=0.0,
            used_triples=set(), warm_up=False, forced=force,
        )

    v_id, snapshot = current
    subjects = snapshot.get("subjects", {})
    root_dir = snapshot.get("target_dir", "")
    version_ts = snapshot.get("timestamp", 0)

    # Текущую избыточность считаем по свежему состоянию ФС, не создавая новую версию в БД.
    try:
        from collector import scan_filesystem
        from dataclasses import asdict as _asdict
        fresh = scan_filesystem(root_dir)
        objects = {p: _asdict(info) for p, info in fresh.items()}
        log.info("Свежий снапшот для аудита: %d объектов", len(objects))
    except Exception as e:
        log.warning("Не удалось снять свежий снапшот (%s), использую из БД", e)
        objects = snapshot.get("objects", {})

    if subject is not None:
        subjects = {subject: subjects.get(subject, {})} if subject in subjects else {}

    now = time.time()
    since = (now - window_days * 86400) if window_days is not None else None

    version_age_days = (now - version_ts) / 86400 if version_ts else 0
    warm_up = (not force and window_days is not None
               and version_age_days < window_days)

    # Все права, которые сейчас разрешены POSIX DAC/ACL для выбранных субъектов.
    ever_allowed: set[tuple] = set()
    for obj_path, obj_info in objects.items():
        obj_info = dict(obj_info)
        obj_info["path"] = obj_path
        for sub_name, sub_info in subjects.items():
            for action in ("read", "write", "execute"):
                if checker.check(sub_info, obj_info, action):
                    ever_allowed.add((sub_name, obj_path, action))

    # Окно наблюдения охватывает все события периода, даже если они записаны
    # под другой policy_version: смена состояния сама по себе не обнуляет историю.
    used_raw = store.get_used_triples(since=since)
    if subject is not None:
        used_raw = {(s, p, a) for (s, p, a) in used_raw if s == subject}

    historical_used_raw = store.get_used_triples()
    if subject is not None:
        historical_used_raw = {(s, p, a) for (s, p, a) in historical_used_raw if s == subject}

    # Запуск скрипта предполагает чтение его исходного файла, даже если ядро
    # зафиксировало только execute-событие.
    for src in (used_raw, historical_used_raw):
        extra = set()
        for (sub, path, act) in list(src):
            if act == "execute" and os.path.splitext(path)[1].lower() in _SCRIPT_EXTS:
                extra.add((sub, path, "read"))
        src |= extra

    # События сохраняются как фактические; traversal добавляется только для сравнения прав.
    used_for_redundancy = _expand_used_with_traversal(used_raw, objects, root_dir)

    current_allowed = set(ever_allowed)

    if warm_up and not force:
        redundant_keys: set[tuple] = set()
    else:
        redundant_keys = ever_allowed - used_for_redundancy

    redundant = [
        RedundantRight(sub, path, act, objects.get(path, {}).get("mode", "?"))
        for (sub, path, act) in sorted(redundant_keys)
        if subject is None or sub == subject
    ]

    # Историческое право избыточно, если не использовалось ни в одной версии,
    # в которой оно присутствовало.
    historical_redundant: list[HistoricalRedundantRight] = []
    redundant_count: dict[tuple[str, str, str], int] = {}
    present_count:   dict[tuple[str, str, str], int] = {}
    all_versions = store.get_policy_versions()

    for version_id, version_snapshot in all_versions:
        version_subjects = version_snapshot.get("subjects", {}) or {}
        version_objects  = version_snapshot.get("objects", {}) or {}
        version_root     = version_snapshot.get("target_dir", "")
        if subject is not None:
            version_subjects = {subject: version_subjects.get(subject, {})} if subject in version_subjects else {}

        version_allowed: set[tuple] = set()
        for obj_path, obj_info in version_objects.items():
            obj_info = dict(obj_info)
            obj_info["path"] = obj_path
            for sub_name, sub_info in version_subjects.items():
                for action in ("read", "write", "execute"):
                    if checker.check(sub_info, obj_info, action):
                        version_allowed.add((sub_name, obj_path, action))

        version_used_raw = store.get_used_triples(version_id=version_id)
        if subject is not None:
            version_used_raw = {(s, p, a) for (s, p, a) in version_used_raw if s == subject}
        version_used = _expand_used_with_traversal(version_used_raw, version_objects, version_root)

        for item in version_allowed:
            present_count[item] = present_count.get(item, 0) + 1
        for item in version_allowed - version_used:
            redundant_count[item] = redundant_count.get(item, 0) + 1

    for (sub, path, act), red_count in sorted(redundant_count.items()):
        if (sub, path, act) not in current_allowed:
            continue
        pres = present_count.get((sub, path, act), 0)
        if pres > 0 and red_count == pres:
            historical_redundant.append(
                HistoricalRedundantRight(
                    sub, path, act,
                    objects.get(path, {}).get("mode", "?"),
                    red_count,
                )
            )

    # Отдельно отмечаем execute-права, нужные для структурного обхода дерева каталогов.
    structural: list[StructuralRight] = []
    structural_roots = ("/", "/root", "/tmp", "/var", "/var/log", "/home")
    for (sub, path, act) in sorted(ever_allowed):
        if act != "execute":
            continue
        path_is_root_like = path in structural_roots or path.startswith(("/tmp/", "/var/", "/home/"))
        path_is_parent_of_other = any(
            other != path and other.startswith(path.rstrip("/") + "/")
            for other in objects
        )
        if path_is_root_like or path_is_parent_of_other:
            structural.append(StructuralRight(sub, path, act, "parent_or_traversal_path"))

    # Переходы нужны для истории аудита, но не являются правами конкретного субъекта.
    transition_impacts: list[StateTransitionImpact] = []
    for tr in store.get_state_transitions():
        from_id, to_id = tr.get("from_state_id"), tr.get("to_state_id")
        if from_id is None or to_id is None or subject is not None:
            continue
        transition_impacts.append(StateTransitionImpact(
            from_state_id=from_id, to_state_id=to_id,
            subject="policy", path="state_transition",
            action="change", diff=str(tr.get("details") or ""),
            timestamp=tr.get("ts", 0.0),
        ))

    # Загружаем отказы из журнала независимо от текущей политики; ниже
    # исключаем те, которые теперь разрешены, чтобы показать только нарушения.
    violations = store.get_violations(since=since)
    if subject is not None:
        violations = [v for v in violations if v.get("subject") == subject]
    violations = [
        v for v in violations
        if (v.get("subject"), v.get("path"), v.get("action")) not in current_allowed
    ]

    policy_changes = store.get_policy_changes(since=since)
    if subject is not None:
        policy_changes = [ch for ch in policy_changes if ch.get("subject") == subject]

    total = len(ever_allowed)
    n_used = len(ever_allowed & used_for_redundancy)
    n_red = len(redundant)
    pct = round(n_red / total * 100, 2) if total > 0 else 0.0

    return AuditResult(
        window_days=window_days or 0,
        since_timestamp=since or 0,
        total_rights=total,
        used_rights=n_used,
        redundant_rights=n_red,
        redundancy_pct=pct,
        redundant=redundant,
        historical_redundant=historical_redundant,
        structural=structural,
        state_transition_impacts=transition_impacts,
        violations=violations,
        policy_changes=policy_changes,
        used_triples=used_raw,
        historical_used_triples=historical_used_raw,
        current_allowed=current_allowed,
        events_observed=store.event_count(since=since, subject=subject),
        warm_up=warm_up,
        forced=force,
    )
    
def _format_policy_change_command(pc: dict) -> str:
    """Собирает текстовое представление команды для отчёта."""
    action = (pc.get("action") or "").lower()
    path   = pc.get("path", "")
    mode   = pc.get("new_mode") or ""
    if action == "chmod":
        return f"chmod {mode} {path}"
    if action == "chown":
        return f"chown {mode} {path}"
    if action in ("create_file", "creat"):
        return f"touch {path}"
    if action == "create_dir":
        return f"mkdir {path}"
    if action == "rename":
        return f"mv {path}"
    return f"{action} {path}".strip()


def enrich_transitions(
    state_transitions: list[dict],
    policy_changes:    list[dict],
) -> list[dict]:
    """
    Связывает переходы состояний с событиями policy_changes.
    Для каждого перехода находит последнее изменение в состоянии from_state_id,
    произошедшее до этого перехода. Возвращает список словарей:
        {timestamp, from_state_id, to_state_id, subject, command}
    """
    changes_sorted = sorted(policy_changes, key=lambda c: c.get("timestamp", 0))
    trs_sorted     = sorted(state_transitions, key=lambda t: t.get("ts", 0))

    enriched: list[dict] = []
    for tr in trs_sorted:
        from_id = tr.get("from_state_id")
        to_id   = tr.get("to_state_id")
        tr_ts   = tr.get("ts", 0)

        window = [
            ch for ch in changes_sorted
            if ch.get("state_id") == from_id
            and ch.get("timestamp", 0) <= tr_ts
        ]

        if window:
            subject = window[-1].get("subject", "—")
            command = _format_policy_change_command(window[-1])
        else:
            subject = "—"
            command = "—"

        enriched.append({
            "timestamp":     tr_ts,
            "from_state_id": from_id,
            "to_state_id":   to_id,
            "subject":       subject,
            "command":       command,
            "reason":        tr.get("reason", ""),
        })
    return enriched    


if __name__ == "__main__":
    import argparse
    import json

    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd")

    v = sub.add_parser("verify")
    v.add_argument("--policy", required=True)
    v.add_argument("--snapshot", required=True)

    a = sub.add_parser("audit")
    a.add_argument("--db", default="policy_audit.db")
    a.add_argument("--window-days", type=float, default=None)
    a.add_argument("--force", action="store_true")

    args = p.parse_args()

    if args.cmd == "verify":
        with open(args.policy, encoding="utf-8") as f:
            rules = [PolicyRule(**r) for r in json.load(f)]
        with open(args.snapshot, encoding="utf-8") as f:
            snap = json.load(f)
        result = verify_config(rules, snap)
        if result.ok:
            print("✅ Конфигурация соответствует политике.")
        else:
            print(f"❌ Расхождений: {len(result.issues)}")
            for iss in result.issues:
                print(f"  [{iss.kind}] {iss.subject} → {iss.path} ({iss.action})")
                print(f"    {iss.detail}")

    elif args.cmd == "audit":
        store = EventStore(args.db)
        try:
            result = audit_redundancy(store, args.window_days, force=args.force)
        finally:
            store.close()
        if result.warm_up and not result.forced:
            print("⚠️  Warm-up: версия моложе окна.")
        print(f"Окно:            {args.window_days or 'вся история'}")
        print(f"Событий:         {result.events_observed}")
        print(f"Всего прав:      {result.total_rights}")
        print(f"Использовано:    {result.used_rights}")
        print(f"Избыточных:      {result.redundant_rights} ({result.redundancy_pct}%)")
        print(f"Нарушений:       {len(result.violations)}")