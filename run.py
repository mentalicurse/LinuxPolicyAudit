#!/usr/bin/env python3
"""CLI приложения: сбор снимков, мониторинг, аудит, проверка и отчёты."""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from dataclasses import asdict


logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] %(message)s",
                    datefmt="%H:%M:%S")
log = logging.getLogger("run")


def cmd_collect(args) -> None:
    from collector import auto_detect_subjects, collect_freeipa_subjects, snapshot_is_equal
    from collector import collect_snapshot, save_snapshot
    from store import EventStore

    log.info("Сбор конфигурации: %s", args.dir)
    subjects = auto_detect_subjects(args.users, args.uid_min)

    if args.freeipa:
        log.info("Подключение к FreeIPA: %s", args.freeipa)
        ipa = collect_freeipa_subjects(
            args.freeipa, args.bind_dn or "", args.bind_pw or "", args.base_dn or ""
        )
        subjects.update(ipa)

    log.info("Субъектов обнаружено: %d — %s", len(subjects), list(subjects.keys()))
    snap = collect_snapshot(args.dir, subjects)
    save_snapshot(snap, args.snapshot)
    log.info("Объектов в снимке: %d, hash=%s", len(snap.objects), snap.snapshot_hash)

    store = EventStore(args.db)
    try:
        snap_dict = asdict(snap)
        current = store.get_current_policy_version()
        if current is not None:
            prev_snapshot = current[1]
            if snapshot_is_equal(prev_snapshot, snap_dict):
                log.info("Конфигурация не изменилась. Новая версия не создаётся.")
            else:
                vid = store.add_policy_version(snap_dict)
                log.info("Создана версия политики #%d", vid)
        else:
            vid = store.add_policy_version(snap_dict)
            log.info("Создана начальная версия политики #%d", vid)
    finally:
        store.close()


def cmd_monitor(args) -> None:
    if os.geteuid() != 0:
        log.error("Мониторинг требует root.")
        sys.exit(1)

    from collector import load_snapshot
    from monitor import start_monitoring
    from alerts import build_dispatcher_from_config

    snap = load_snapshot(args.snapshot)
    if snap is None:
        log.error("Снимок не найден: %s. Сначала: collect", args.snapshot)
        sys.exit(1)

    dispatcher = build_dispatcher_from_config({
        "console": not args.quiet,
        "file": args.alert_file,
        "syslog": args.syslog,
        "webhook": args.webhook,
        "throttle_sec": args.throttle_sec,
    })

    whitelist = set(args.whitelist) if args.whitelist is not None else None

    channels = ", ".join(filter(None, [
        "console" if not args.quiet else None,
        f"file={args.alert_file}" if args.alert_file else None,
        "syslog" if args.syslog else None,
        "webhook" if args.webhook else None,
    ])) or "нет каналов"

    mode = f"{args.duration} сек" if args.duration else "демон"
    log.info("Мониторинг: %s. Режим: %s.", snap.target_dir, mode)
    log.info("Каналы алертов: %s", channels)
    if whitelist is not None:
        log.info("Фильтр ВКЛ. State создают: root + %s",
                 sorted(whitelist) if whitelist else "(только root)")
    else:
        log.info("Фильтр ВЫКЛ — любое изменение создаёт state.")

    start_monitoring(
        target_dir=snap.target_dir,
        subjects=snap.subjects,
        dispatcher=dispatcher,
        db_path=args.db,
        snapshot_file=args.snapshot,
        duration=args.duration,
        whitelist=whitelist,
    )


def cmd_verify(args) -> None:
    from collector import load_snapshot
    from analyzer import PolicyRule, verify_config

    if not os.path.exists(args.policy):
        log.error("Файл политики не найден: %s", args.policy)
        sys.exit(1)

    with open(args.policy, encoding="utf-8") as f:
        rules = [PolicyRule(**r) for r in json.load(f)]

    snap = load_snapshot(args.snapshot)
    if snap is None:
        log.error("Снимок не найден: %s", args.snapshot)
        sys.exit(1)

    result = verify_config(rules, asdict(snap), subject=getattr(args, "subject", None))

    if result.ok:
        log.info("✅ Конфигурация соответствует политике.")
    else:
        log.warning("❌ Расхождений: %d", len(result.issues))
        for iss in result.issues:
            log.warning("  [%s] %s → %s (%s): %s",
                        iss.kind, iss.subject, iss.path, iss.action, iss.detail)

    os.makedirs(args.output, exist_ok=True)
    out = os.path.join(args.output, "verify_result.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump({"ok": result.ok, "issues": [asdict(i) for i in result.issues]},
                  f, indent=2, ensure_ascii=False)
    log.info("Результат: %s", out)


def cmd_audit(args) -> None:
    from store import EventStore
    from analyzer import audit_redundancy

    if not os.path.exists(args.db):
        log.error("БД не найдена: %s", args.db)
        sys.exit(1)

    store = EventStore(args.db)
    try:
        result = audit_redundancy(
            store,
            window_days=args.window_days,
            force=args.force,
            subject=getattr(args, "subject", None),
        )
    finally:
        store.close()

    if getattr(result, "warm_up", False) and not args.force:
        log.warning("⚠️  Warm-up: версия моложе окна.")

    window_str = f"{args.window_days} дн." if args.window_days else "вся история"
    log.info("─" * 50)
    log.info("Окно:                %s", window_str)
    log.info("Событий:             %d", result.events_observed)
    log.info("Всего прав:          %d", result.total_rights)
    log.info("Использовано:        %d", result.used_rights)
    log.info("Избыточных:          %d (%s%%)", result.redundant_rights, result.redundancy_pct)
    log.info("Исторически избыт.:  %d", len(result.historical_redundant))
    log.info("Нарушений:           %d", len(result.violations))
    log.info("─" * 50)

    if result.violations:
        log.warning("🚨 Нарушения:")
        for v in result.violations[-20:]:
            log.warning("  %s → %s (%s)", v["subject"], v["path"], v["action"])

    if result.redundant:
        log.info("⚠️  Избыточные (топ-20):")
        for r in result.redundant[:20]:
            log.info("  %-12s %-8s %s (mode=%s)",
                     r.subject, r.action, r.path, r.last_mode)

    os.makedirs(args.output, exist_ok=True)
    out_path = os.path.join(args.output, "audit_result.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump({
            "window_days": result.window_days,
            "warm_up": getattr(result, "warm_up", False),
            "forced": getattr(result, "forced", False),
            "events_observed": result.events_observed,
            "total_rights": result.total_rights,
            "used_rights": result.used_rights,
            "redundant_rights": result.redundant_rights,
            "redundancy_pct": result.redundancy_pct,
            "redundant": [asdict(r) for r in result.redundant],
            "violations": result.violations,
            "policy_changes": result.policy_changes,
        }, f, indent=2, ensure_ascii=False)
    log.info("Результат: %s", out_path)


def cmd_report(args) -> None:
    from collector import load_snapshot
    from store import EventStore
    from analyzer import (audit_redundancy, verify_config, PolicyRule,
                          build_state_summary, enrich_transitions)
    from visualizer import draw_all
    from report_html import generate_html_report

    os.makedirs(args.output, exist_ok=True)
    snap = load_snapshot(args.snapshot)
    if snap is None:
        log.error("Снимок не найден: %s", args.snapshot)
        sys.exit(1)

    audit = None
    all_states: list = []
    enriched_transitions: list = []
    state_transitions: list = []

    if os.path.exists(args.db):
        store = EventStore(args.db)
        try:
            audit = audit_redundancy(
                store,
                window_days=args.window_days,
                force=args.force,
                subject=getattr(args, "subject", None),
            )
            versions = list(reversed(store.get_policy_versions()))
            all_states = [
                build_state_summary(vid, snap_dict, store)
                for vid, snap_dict in versions
            ]
            state_transitions = store.get_state_transitions()
            policy_changes    = store.get_policy_changes()
            enriched_transitions = enrich_transitions(
                state_transitions, policy_changes
            )
        finally:
            store.close()

    verify = None
    if os.path.exists(args.policy):
        with open(args.policy, encoding="utf-8") as f:
            rules = [PolicyRule(**r) for r in json.load(f)]
        verify = verify_config(rules, asdict(snap), subject=getattr(args, "subject", None))

    log.info("Генерация визуализаций...")
    draw_all(
        snapshot=asdict(snap),
        audit=audit or __empty_audit(),
        verify=verify,
        used_triples=audit.used_triples if audit is not None else set(),
        state_transitions=state_transitions,
        output_dir=args.output,
    )

    log.info("Генерация HTML-отчёта...")
    generate_html_report(
        snap=asdict(snap),
        audit=audit,
        verify=verify,
        all_states=all_states,
        enriched_transitions=enriched_transitions,
        out=os.path.join(args.output, "report.html"),
    )
    log.info("Готово! Отчёты: %s", args.output)


def __empty_audit():
    from analyzer import AuditResult
    return AuditResult(0, 0, 0, 0, 0, 0.0)


def cmd_ui(args) -> None:
    log.error("UI удалён из проекта. Используйте CLI-команды collect/monitor/report.")


def cmd_all(args) -> None:
    log.info("═" * 55)
    log.info("  ПОЛНЫЙ ЦИКЛ")
    log.info("═" * 55)

    log.info("\n▶ Шаг 1: Сбор конфигурации")
    cmd_collect(args)

    log.info("\n▶ Шаг 2: Мониторинг (%s сек)", args.duration or 60)
    args.quiet = False
    cmd_monitor(args)

    log.info("\n▶ Шаг 3: Аудит избыточности")
    if not hasattr(args, "force"):
        args.force = True
    cmd_audit(args)

    log.info("\n▶ Шаг 4: Генерация отчёта")
    cmd_report(args)


def build_parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="lpa",
                                   description="Linux Policy Audit")
    subs = root.add_subparsers(dest="cmd", required=True)

    def common(p):
        p.add_argument("--snapshot", default="config_snapshot.json")
        p.add_argument("--db",       default="policy_audit.db")
        p.add_argument("--policy",   default="policy.json")
        p.add_argument("--output",   default="report")

    p_col = subs.add_parser("collect")
    common(p_col)
    p_col.add_argument("--dir", required=True)
    p_col.add_argument("--users", nargs="+")
    p_col.add_argument("--uid-min", type=int, default=1_000, dest="uid_min")
    p_col.add_argument("--freeipa")
    p_col.add_argument("--bind-dn", dest="bind_dn")
    p_col.add_argument("--bind-pw", dest="bind_pw")
    p_col.add_argument("--base-dn", dest="base_dn")
    p_col.set_defaults(func=cmd_collect)

    p_mon = subs.add_parser("monitor")
    common(p_mon)
    p_mon.add_argument("--dir")
    p_mon.add_argument("--duration", type=int)
    p_mon.add_argument("--webhook")
    p_mon.add_argument("--syslog", action="store_true")
    p_mon.add_argument("--alert-file", default="violations.jsonl")
    p_mon.add_argument("--quiet", action="store_true")
    p_mon.add_argument("--throttle-sec", type=float, default=30.0, dest="throttle_sec")
    p_mon.add_argument("--whitelist", nargs="*", default=None,
                       help="Список субъектов, чьи изменения создают state. "
                            "Если флаг не задан — фильтр выключен.")
    p_mon.set_defaults(func=cmd_monitor)

    p_ver = subs.add_parser("verify")
    common(p_ver)
    p_ver.add_argument("--subject")
    p_ver.set_defaults(func=cmd_verify)

    p_aud = subs.add_parser("audit")
    common(p_aud)
    p_aud.add_argument("--window-days", type=float, default=None)
    p_aud.add_argument("--force", action="store_true")
    p_aud.add_argument("--subject")
    p_aud.set_defaults(func=cmd_audit)

    p_rep = subs.add_parser("report")
    common(p_rep)
    p_rep.add_argument("--window-days", type=float, default=None)
    p_rep.add_argument("--subject")
    p_rep.add_argument("--from-state", type=int, default=None)
    p_rep.add_argument("--to-state", type=int, default=None)
    p_rep.add_argument("--force", action="store_true")
    p_rep.set_defaults(func=cmd_report)

    p_all = subs.add_parser("all")
    common(p_all)
    p_all.add_argument("--dir", required=True)
    p_all.add_argument("--users", nargs="+")
    p_all.add_argument("--uid-min", type=int, default=1_000, dest="uid_min")
    p_all.add_argument("--duration", type=int, default=60)
    p_all.add_argument("--window-days", type=float, default=None)
    p_all.add_argument("--webhook")
    p_all.add_argument("--syslog", action="store_true")
    p_all.add_argument("--alert-file", default="violations.jsonl")
    p_all.add_argument("--throttle-sec", type=float, default=30.0, dest="throttle_sec")
    p_all.add_argument("--whitelist", nargs="*", default=None)
    p_all.add_argument("--force", action="store_true", default=True)
    p_all.add_argument("--freeipa")
    p_all.add_argument("--bind-dn", dest="bind_dn")
    p_all.add_argument("--bind-pw", dest="bind_pw")
    p_all.add_argument("--base-dn", dest="base_dn")
    p_all.set_defaults(func=cmd_all)

    return root


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()