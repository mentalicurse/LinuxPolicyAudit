#!/usr/bin/env python3
"""
monitor.py — мониторинг файловой системы через eBPF/bpftrace.

Модуль классифицирует события доступа и изменения прав, обновляет снимок
политики и записывает события в хранилище. Whitelist ограничивает создание
новых состояний политики, но не сам сбор событий; без него состояние создаётся
при любом изменении. Периодический heartbeat создаёт контрольные состояния,
чтобы исторический аудит сохранял временные границы даже без изменений.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import pwd
import stat
import subprocess
import tempfile
import time

from collector import ConfigSnapshot, collect_snapshot, save_snapshot, load_snapshot, compute_snapshot_hash, snapshot_is_equal
from dac import AccessChecker, default_checker
from alerts import AlertDispatcher, ViolationEvent
from store import EventStore

import threading


log = logging.getLogger("monitor")


TRANSIENT_SUFFIXES = (
    ".swp", ".swo", ".swn", ".tmp", ".bak", ".orig",
    ".dpkg-new", ".rpmnew", ".pyc"
)


def is_transient(path: str) -> bool:
    name = os.path.basename(path)
    if any(name.endswith(s) for s in TRANSIENT_SUFFIXES):
        return True
    if name.endswith("~") or name.startswith(".goutputstream-") or name.startswith(".#"):
        return True
    return False


BPFTRACE_SCRIPT = r"""
#include <linux/sched.h>

tracepoint:syscalls:sys_enter_open,
tracepoint:syscalls:sys_enter_openat
{
    @filenames[tid] = str(args->filename);
    @flags[tid] = args->flags;
}
tracepoint:syscalls:sys_exit_open,
tracepoint:syscalls:sys_exit_openat
/ @filenames[tid] != "" /
{
    $flags = @flags[tid];
    if (args->ret >= 0) {
        if ($flags & 64) {
            printf("EVENT|%llu|CREAT|%d|%d|%s|%s\n",
                   elapsed, uid, pid, @filenames[tid], comm);
        }
        if (($flags & 1) || ($flags & 2)) {
            printf("EVENT|%llu|WRITE|%d|%d|%s\n",
                   elapsed, uid, pid, @filenames[tid]);
        } else {
            printf("EVENT|%llu|READ|%d|%d|%s\n",
                   elapsed, uid, pid, @filenames[tid]);
        }
    } else {
        if (($flags & 1) || ($flags & 2)) {
            printf("EVENT|%llu|DENIED_WRITE|%d|%d|%s|%d\n",
                   elapsed, uid, pid, @filenames[tid], args->ret);
        } else {
            printf("EVENT|%llu|DENIED_READ|%d|%d|%s|%d\n",
                   elapsed, uid, pid, @filenames[tid], args->ret);
        }
    }
    delete(@filenames[tid]); delete(@flags[tid]);
}

tracepoint:syscalls:sys_enter_mkdir,
tracepoint:syscalls:sys_enter_mkdirat
{
    @mkdir_paths[tid] = str(args->pathname);
    @mkdir_comm[tid]  = comm;
}
tracepoint:syscalls:sys_exit_mkdir,
tracepoint:syscalls:sys_exit_mkdirat
/ @mkdir_paths[tid] != "" /
{
    if (args->ret >= 0) {
        printf("EVENT|%llu|MKDIR|%d|%d|%s|%s\n",
               elapsed, uid, pid, @mkdir_paths[tid], @mkdir_comm[tid]);
    } else {
        printf("EVENT|%llu|DENIED_MKDIR|%d|%d|%s|%d\n",
               elapsed, uid, pid, @mkdir_paths[tid], args->ret);
    }
    delete(@mkdir_paths[tid]); delete(@mkdir_comm[tid]);
}

tracepoint:syscalls:sys_enter_chmod
{
    @chmod_paths[tid] = str(args->filename);
    @chmod_modes[tid] = args->mode;
    @chmod_comm[tid]  = comm;
}
tracepoint:syscalls:sys_enter_fchmodat
{
    @chmod_paths[tid] = str(args->filename);
    @chmod_modes[tid] = args->mode;
    @chmod_comm[tid]  = comm;
}
tracepoint:syscalls:sys_exit_chmod,
tracepoint:syscalls:sys_exit_fchmodat
/ @chmod_paths[tid] != "" /
{
    if (args->ret >= 0) {
        printf("EVENT|%llu|CHMOD|%d|%d|%s|0x%x|%s\n",
               elapsed, uid, pid,
               @chmod_paths[tid], @chmod_modes[tid], @chmod_comm[tid]);
    } else {
        printf("EVENT|%llu|DENIED_CHMOD|%d|%d|%s|%d\n",
               elapsed, uid, pid,
               @chmod_paths[tid], args->ret);
    }
    delete(@chmod_paths[tid]); delete(@chmod_modes[tid]); delete(@chmod_comm[tid]);
}

tracepoint:syscalls:sys_enter_chown
{
    @chown_paths[tid] = str(args->filename);
    @chown_owners[tid] = args->user;
    @chown_groups[tid] = args->group;
}
tracepoint:syscalls:sys_enter_fchownat
{
    @chown_paths[tid] = str(args->filename);
    @chown_owners[tid] = args->user;
    @chown_groups[tid] = args->group;
}
tracepoint:syscalls:sys_exit_chown,
tracepoint:syscalls:sys_exit_fchownat
/ @chown_paths[tid] != "" /
{
    if (args->ret >= 0) {
        printf("EVENT|%llu|CHOWN|%d|%d|%s|%d|%d\n",
               elapsed, uid, pid,
               @chown_paths[tid], @chown_owners[tid], @chown_groups[tid]);
    } else {
        printf("EVENT|%llu|DENIED_CHOWN|%d|%d|%s|%d\n",
               elapsed, uid, pid,
               @chown_paths[tid], args->ret);
    }
    delete(@chown_paths[tid]); delete(@chown_owners[tid]); delete(@chown_groups[tid]);
}

tracepoint:syscalls:sys_enter_execve,
tracepoint:syscalls:sys_enter_execveat
{ @exec_paths[tid] = str(args->filename); }
tracepoint:syscalls:sys_exit_execve,
tracepoint:syscalls:sys_exit_execveat
/ @exec_paths[tid] != "" /
{
    if (args->ret == 0) {
        printf("EVENT|%llu|EXECUTE|%d|%d|%s\n", elapsed, uid, pid, @exec_paths[tid]);
    } else {
        printf("EVENT|%llu|DENIED_EXECUTE|%d|%d|%s|%d\n", elapsed, uid, pid, @exec_paths[tid], args->ret);
    }
    delete(@exec_paths[tid]);
}

tracepoint:syscalls:sys_enter_rename,
tracepoint:syscalls:sys_enter_renameat
{
    @rename_old[tid] = str(args->oldname);
    @rename_new[tid] = str(args->newname);
    @rename_comm[tid] = comm;
}
tracepoint:syscalls:sys_exit_rename,
tracepoint:syscalls:sys_exit_renameat
/ @rename_old[tid] != "" /
{
    if (args->ret == 0) {
        printf("EVENT|%llu|RENAME|%d|%d|%s|%s|%s\n",
               elapsed, uid, pid,
               @rename_old[tid], @rename_new[tid], @rename_comm[tid]);
    } else {
        printf("EVENT|%llu|DENIED_RENAME|%d|%d|%s|%d\n",
               elapsed, uid, pid,
               @rename_old[tid], args->ret);
    }
    delete(@rename_old[tid]); delete(@rename_new[tid]); delete(@rename_comm[tid]);
}
"""


# Event path resolution, UID mapping and mode normalization.

def _normalize_mode(raw: str) -> str:
    raw = raw.strip()
    try:
        if raw.startswith(("0x", "0X")):
            return f"{int(raw, 16):04o}"
        if raw.startswith("0") and len(raw) > 1:
            return f"{int(raw, 8):04o}"
        return f"{int(raw):04o}"
    except ValueError:
        return "0644"


def _is_world_writable(mode_octal: str) -> bool:
    """True если в правах есть бит записи для 'others' (0o002)."""
    try:
        return (int(mode_octal, 8) & 0o002) != 0
    except (ValueError, TypeError):
        return False


def _resolve(raw: str, base: str) -> str:
    if not raw.startswith("/"):
        base_name = os.path.basename(base)
        if raw == base_name or raw.startswith(base_name + "/"):
            parent_dir = os.path.dirname(base)
            return os.path.realpath(os.path.join(parent_dir, raw))
        return os.path.realpath(os.path.join(base, raw))
    return os.path.realpath(raw)


class UidResolver:
    def __init__(self, snapshot: dict):
        self._uid_map: dict[int, str] = {
            info.get("uid"): name
            for name, info in snapshot.get("subjects", {}).items()
            if isinstance(info.get("uid"), int)
        }

    def resolve(self, uid_str: str) -> str:
        if not uid_str.isdigit():
            return uid_str
        uid = int(uid_str)
        try:
            return pwd.getpwuid(uid).pw_name
        except KeyError:
            pass
        return self._uid_map.get(uid, uid_str)


# Event collection, policy-state lifecycle and alert dispatch.

class RealtimeMonitor:
    def __init__(
        self,
        target_dir: str,
        subjects: dict,
        checker: AccessChecker,
        dispatcher: AlertDispatcher,
        store: EventStore,
        snapshot_file: str = "config_snapshot.json",
        recheck_debounce_sec: float = 2.0,
        state_id: int | None = None,
        session_id: int | None = None,
        whitelist: set[str] | None = None,
        heartbeat_sec: float | None = 86400.0,
    ):
        self.target_dir = os.path.realpath(target_dir)
        self.subjects = subjects
        self.checker = checker
        self.dispatcher = dispatcher
        self.store = store
        self.snapshot_file = snapshot_file
        self.debounce = recheck_debounce_sec
        self.heartbeat_sec = heartbeat_sec

        # None отключает фильтр; заданное множество разрешает создавать state
        # только для root и указанных субъектов (даже если множество пустое).
        self._filter_enabled = whitelist is not None
        self._whitelist = set(whitelist) if whitelist else set()

        self._snapshot: dict = {}
        self._policy_version_id: int = -1
        self._state_id: int | None = state_id
        self._session_id: int | None = session_id
        self._pending_reload: float | None = None
        self._reload_timer: threading.Timer | None = None
        self._reload_lock = threading.RLock()
        self._flush_lock = threading.RLock()

        self._pending: list[tuple[str, str, str, float]] = []
        self._pending_max = 10_000
        self._dirty_paths: set[str] = set()
        self._stateful_pending: bool = False

        self._daily_timer: threading.Timer | None = None

        self._load_or_create_snapshot()
        self._start_daily_heartbeat()

    # Пакетное обновление снимка после группы файловых событий.

    def _schedule_reload(self) -> None:
        with self._reload_lock:
            if self._pending_reload is None:
                return
            if self._reload_timer is not None:
                self._reload_timer.cancel()
            self._reload_timer = threading.Timer(
                self.debounce,
                self._apply_pending_reload_incremental,
                kwargs={"force": True},
            )
            self._reload_timer.daemon = True
            self._reload_timer.start()

    def _ensure_policy_state(
        self,
        snapshot: dict,
        parent_version_id: int | None = None,
        *,
        force: bool = False,
    ) -> int:
        current = self.store.get_current_policy_version()
        if current is not None and not force:
            current_id, current_snapshot = current
            if (
                current_snapshot.get("target_dir") == snapshot.get("target_dir")
                and snapshot_is_equal(current_snapshot, snapshot)
            ):
                return current_id
        return self.store.add_policy_version(
            snapshot,
            parent_version_id=parent_version_id,
            source="auto",
        )

    def _start_or_reuse_session(self, state_id: int) -> int:
        session_id = self.store.get_active_session_for_state(state_id)
        if session_id is not None:
            return session_id
        return self.store.create_monitoring_session(
            state_id,
            description=f"monitor:{self.target_dir}",
        )

    def _load_or_create_snapshot(self) -> None:
        from collector import SubjectInfo
        from dataclasses import asdict

        # После запуска с фильтром перечитываем ФС: прошлые незначимые изменения
        # обновляли только память и могли не попасть в сохранённый снимок.
        if self._filter_enabled and self.subjects:
            smap = {k: SubjectInfo(**v) for k, v in self.subjects.items()}
            snap = collect_snapshot(self.target_dir, smap)
            save_snapshot(snap, self.snapshot_file)
        else:
            snap = load_snapshot(self.snapshot_file)
            if snap is None:
                if not self.subjects:
                    raise RuntimeError(
                        "Нет ни snapshot-файла, ни subjects для сбора конфигурации"
                    )
                smap = {k: SubjectInfo(**v) for k, v in self.subjects.items()}
                snap = collect_snapshot(self.target_dir, smap)
                save_snapshot(snap, self.snapshot_file)

        self._snapshot = asdict(snap)
        self._policy_version_id = self._ensure_policy_state(
            self._snapshot, parent_version_id=self._state_id
        )
        self._state_id = self._policy_version_id
        self._session_id = self._start_or_reuse_session(self._state_id)

        self._uid_resolver = UidResolver(self._snapshot)
        log.info(
            "Версия политики #%d (hash=%s); фильтр %s",
            self._policy_version_id,
            self._snapshot.get("snapshot_hash"),
            "ВКЛ" if self._filter_enabled else "ВЫКЛ",
        )

    # Правило, определяющее, должно ли изменение создавать новую версию политики.

    def _is_stateful_change(self, subject: str, path: str) -> bool:
        """Создаёт ли это изменение новое состояние политики?

        Упрощённая модель: state создаётся только при изменениях от
        root или пользователей из whitelist. Остальные пользователи
        физически не могут менять чужие файлы (POSIX: нужен CAP_FOWNER),
        поэтому отдельная проверка «свой / чужой» не нужна — она всегда
        даст «свой», и такой случай мы просто не считаем значимым.

        Все события всё равно пишутся в access_events / policy_changes.
        """
        if not self._filter_enabled:
            return True
        if subject == "root":
            return True
        if subject in self._whitelist:
            return True
        return False

    # Сбор изменений, влияющих на снимок политики.

    def _mark_config_changed(
        self,
        path: str | None = None,
        subject: str | None = None,
    ) -> None:
        """Помечает путь изменённым; создание state откладывается на debounce.

        Новый state будет создан, только если хотя бы одно изменение
        в текущей пачке оказалось значимым (см. _is_stateful_change).
        """
        if path:
            self._dirty_paths.add(path)
            if subject is None or self._is_stateful_change(subject, path):
                self._stateful_pending = True

        self._pending_reload = time.time()
        self._schedule_reload()

    def _apply_pending_reload_incremental(self, force: bool = False) -> None:
        with self._flush_lock:
            self._apply_pending_reload_incremental_locked(force=force)

    def _apply_pending_reload_incremental_locked(self, force: bool = False) -> None:
        if not force:
            if (self._pending_reload is None
                    or time.time() - self._pending_reload < self.debounce):
                return

        if not self._dirty_paths:
            self._pending_reload = None
            if self._reload_timer is not None:
                self._reload_timer.cancel()
                self._reload_timer = None
            return

        self._pending_reload = None
        if self._reload_timer is not None:
            self._reload_timer.cancel()
            self._reload_timer = None

        from collector import get_object_metadata
        dirty_paths = sorted(self._dirty_paths)
        new_objects = dict(self._snapshot.get("objects", {}))

        for path in dirty_paths:
            if not os.path.exists(path):
                for key in list(new_objects.keys()):
                    if key == path or key.startswith(path.rstrip("/") + "/"):
                        new_objects.pop(key, None)
                continue

            try:
                st = os.stat(path)
            except OSError:
                for key in list(new_objects.keys()):
                    if key == path or key.startswith(path.rstrip("/") + "/"):
                        new_objects.pop(key, None)
                continue

            if stat.S_ISDIR(st.st_mode):
                for root, _, files in os.walk(path):
                    for f in files:
                        child = os.path.join(root, f)
                        meta = get_object_metadata(child, "file")
                        if meta:
                            new_objects[child] = meta
                    dir_meta = get_object_metadata(root, "directory")
                    if dir_meta:
                        new_objects[root] = dir_meta
                for key in list(new_objects.keys()):
                    if key.startswith(path.rstrip("/") + "/") and not os.path.exists(key):
                        new_objects.pop(key, None)
            else:
                meta = get_object_metadata(path, "file")
                if meta:
                    new_objects[path] = meta

        self._dirty_paths.clear()

        new_snapshot = dict(self._snapshot)
        new_snapshot["objects"] = new_objects
        new_snapshot["timestamp"] = time.time()
        new_snapshot["snapshot_hash"] = compute_snapshot_hash({
            "subjects": new_snapshot.get("subjects", {}),
            "objects":  new_objects,
        })

        if snapshot_is_equal(self._snapshot, new_snapshot):
            return

        significant = self._stateful_pending
        self._stateful_pending = False

        if not significant:
            # Изменение видно текущему процессу, но по фильтру не создаёт версию в БД.
            self._snapshot = new_snapshot
            self.subjects = dict(new_snapshot.get("subjects", {}))
            self._uid_resolver = UidResolver(new_snapshot)
            log.info(
                "🔄 Снапшот обновлён без нового state (незначимое изменение): %s",
                ", ".join(dirty_paths),
            )
            self._apply_pending()
            return

        self._create_new_state_from_snapshot(
            new_snapshot,
            reason="config_changed",
            details=f"dirty paths: {dirty_paths}",
        )
        self._apply_pending()

    def _create_new_state_from_snapshot(
        self,
        new_snapshot: dict,
        reason: str,
        details: str = "",
    ) -> int:
        prev_state_id = self._state_id
        new_state_id = self._ensure_policy_state(
            new_snapshot,
            parent_version_id=prev_state_id,
            force=True,
        )
        self.store.record_transition(prev_state_id, new_state_id, reason, details)
        log.info(
            "⚙️  Новое состояние #%d (%s): %s",
            new_state_id, reason, details,
        )

        self.store.close_monitoring_session(self._session_id)
        self._session_id = self._start_or_reuse_session(new_state_id)

        self._snapshot = new_snapshot
        self._policy_version_id = new_state_id
        self._state_id = new_state_id
        self.subjects = dict(new_snapshot.get("subjects", {}))
        self._uid_resolver = UidResolver(new_snapshot)

        try:
            from collector import save_snapshot, ConfigSnapshot
            save_snapshot(ConfigSnapshot(**self._snapshot), self.snapshot_file)
        except Exception as e:
            log.warning("Не удалось сохранить snapshot после смены состояния: %s", e)

        return new_state_id

    def _force_create_state(self, reason: str) -> int:
        """Принудительно создаёт новый state из текущего in-memory снапшота.

        Используется для суточного heartbeat, когда нужно создать «якорь»,
        даже если фактически ничего не менялось.
        """
        with self._flush_lock:
            new_snapshot = dict(self._snapshot)
            new_snapshot["timestamp"] = time.time()
            return self._create_new_state_from_snapshot(
                new_snapshot, reason=reason, details=""
            )

    # Периодические версии-якоря для исторического аудита.

    def _start_daily_heartbeat(self) -> None:
        if self.heartbeat_sec is None or self.heartbeat_sec <= 0:
            return
        if self._daily_timer is not None:
            self._daily_timer.cancel()
        self._daily_timer = threading.Timer(
            self.heartbeat_sec,
            self._daily_heartbeat_tick,
        )
        self._daily_timer.daemon = True
        self._daily_timer.start()
        log.debug("💓 Heartbeat запланирован через %.0f сек", self.heartbeat_sec)

    def _daily_heartbeat_tick(self) -> None:
        try:
            log.info("💓 Суточный heartbeat: принудительное создание нового state")
            self._force_create_state(reason="daily_heartbeat")
        except Exception as e:
            log.error("Ошибка daily heartbeat: %s", e)
        finally:
            self._start_daily_heartbeat()

    # Отложенная классификация событий, для которых объект ещё не попал в снимок.

    def _queue_pending(self, subject: str, path: str, action: str, ts: float) -> None:
        if len(self._pending) >= self._pending_max:
            self._pending.pop(0)
        self._pending.append((subject, path, action, ts))

    def _apply_pending(self) -> None:
        if not self._pending:
            return
        remaining: list[tuple[str, str, str, float]] = []
        for (subj, path, action, ts) in self._pending:
            if path in self._snapshot.get("objects", {}):
                self._classify_and_store(subj, path, action, ts, os_allowed=True)
            else:
                remaining.append((subj, path, action, ts))
        self._pending = remaining
        if self._pending:
            log.debug("Осталось pending: %d", len(self._pending))

    # Эвристики подозрительных изменений и отправка оповещений.

    def _is_suspicious_change(
        self,
        subject: str,
        path: str,
        action: str,
        new_mode: str | None = None,
    ) -> bool:
        if subject == "root":
            return False
        if action not in {"chmod", "chown", "create_file", "create_dir", "rename"}:
            return False

        # Разрешение записи для всех пользователей опасно независимо от владельца.
        if action == "chmod" and new_mode and _is_world_writable(new_mode):
            return True

        # Изменение чужого объекта (или объекта с неизвестным владельцем) подозрительно.
        obj = self._snapshot.get("objects", {}).get(path)
        if obj is not None and obj.get("uid") is not None:
            try:
                owner_name = self._uid_resolver.resolve(str(obj.get("uid")))
            except Exception:
                owner_name = None
            if owner_name == subject:
                return False
        return True

    def _dispatch_suspicious_change(
        self,
        subject: str,
        path: str,
        action: str,
        mode: str,
        ts: float,
    ) -> None:
        event = ViolationEvent(
            timestamp=ts,
            subject=subject,
            path=path,
            action=action,
            mode=mode,
            kind="suspicious_change",
        )
        self.dispatcher.dispatch(event)

    def _record_denied_access(
        self, subject: str, path: str, action: str, err_code: int, ts: float
    ) -> None:
        obj_info = self._snapshot.get("objects", {}).get(path, {})
        self.store.record_access(
            self._policy_version_id,
            subject, path, action,
            False, ts,
            state_id=self._state_id,
            session_id=self._session_id,
        )
        event = ViolationEvent(
            timestamp=ts,
            subject=subject,
            path=path,
            action=action,
            mode=f"{obj_info.get('mode', '?')} (OS errno={err_code})",
            kind="denied",
        )
        self.dispatcher.dispatch(event)

    def _classify_and_store(
        self,
        subject: str,
        path: str,
        action: str,
        ts: float,
        os_allowed: bool = True,
    ) -> None:
        obj_info = self._snapshot.get("objects", {}).get(path)
        sub_info = self._snapshot.get("subjects", {}).get(subject)

        if obj_info is None:
            self._queue_pending(subject, path, action, ts)
            return

        if sub_info is None:
            log.debug(
                "Access event from untracked subject=%s path=%s action=%s",
                subject, path, action,
            )

        self.store.record_access(
            self._policy_version_id,
            subject, path, action,
            bool(os_allowed), ts,
            state_id=self._state_id,
            session_id=self._session_id,
        )

    # Разбор протокола EVENT|... от bpftrace и маршрутизация событий.

    def _handle_line(self, line: str) -> None:
        line = line.strip()
        if not line.startswith("EVENT|"):
            return

        parts = line.split("|")
        if len(parts) < 6:
            return

        ev_type  = parts[2]
        uid_str  = parts[3]
        filename = parts[5]
        extra    = parts[6] if len(parts) > 6 else "unknown"
        extra2   = parts[7] if len(parts) > 7 else "unknown"

        subject = self._uid_resolver.resolve(uid_str)
        if subject == "root":
            if ev_type in ("READ", "WRITE", "EXECUTE",
                           "DENIED_READ", "DENIED_WRITE", "DENIED_EXECUTE"):
                return

        ts = time.time()

        # Для rename bpftrace передаёт новый путь отдельно от исходного.
        if ev_type == "RENAME":
            if len(parts) < 7:
                return
            new_path = _resolve(extra, self.target_dir)
            if not new_path.startswith(self.target_dir) or is_transient(new_path):
                return
            self._mark_config_changed(new_path, subject=subject)
            self._classify_and_store(subject, new_path, "write", ts, os_allowed=True)
            return

        abs_path = _resolve(filename, self.target_dir)
        if not abs_path.startswith(self.target_dir) or is_transient(abs_path):
            return
        # Отказ фиксируем до проверки существования пути: неудачное создание
        # файла в недоступном каталоге не оставляет объект в файловой системе.
        if ev_type in ("DENIED_READ", "DENIED_WRITE", "DENIED_EXECUTE"):
            action = ev_type.replace("DENIED_", "").lower()
            try:
                err_code = int(extra)
            except (ValueError, TypeError):
                err_code = -1
            self._record_denied_access(subject, abs_path, action, err_code, ts)
            return

        if ev_type in ("DENIED_MKDIR", "DENIED_CHMOD",
                       "DENIED_RENAME", "DENIED_CHOWN"):
            log.warning(
                "Попытка %s завершилась отказом ОС (subject=%s, path=%s)",
                ev_type, subject, abs_path,
            )
            return
                        
        if not os.path.exists(abs_path):
            return

        # Изменения прав и владельца обновляют политику и попадают в журнал.
        if ev_type == "CHMOD":
            new_mode = _normalize_mode(extra)
            self._mark_config_changed(abs_path, subject=subject)

            if abs_path in self._snapshot.get("objects", {}) \
                    and self._snapshot["objects"][abs_path].get("obj_type") == "directory":
                for candidate in sorted(self._snapshot.get("objects", {})):
                    if candidate.startswith(abs_path.rstrip("/") + "/"):
                        self._dirty_paths.add(candidate)

            suspicious = self._is_suspicious_change(
                subject, abs_path, "chmod", new_mode=new_mode
            )
            log.info(
                "⚙️  policy change: chmod %s -> %s (subject=%s, state=%s, suspicious=%s)",
                abs_path, new_mode, subject, self._state_id, suspicious,
            )
            self.store.record_policy_change(
                self._policy_version_id, subject, abs_path,
                "chmod", new_mode, extra2, ts,
                state_id=self._state_id,
                session_id=self._session_id,
                suspicious=suspicious,
            )
            if suspicious:
                self._dispatch_suspicious_change(
                    subject, abs_path, "chmod", new_mode, ts
                )

        elif ev_type == "CHOWN":
            self._mark_config_changed(abs_path, subject=subject)

            owner = parts[6] if len(parts) > 6 else "?"
            group = parts[7] if len(parts) > 7 else "?"
            new_value = f"{owner}:{group}"
            suspicious = self._is_suspicious_change(subject, abs_path, "chown")
            log.info(
                "⚙️  policy change: chown %s -> %s (subject=%s, state=%s, suspicious=%s)",
                abs_path, new_value, subject, self._state_id, suspicious,
            )
            self.store.record_policy_change(
                self._policy_version_id, subject, abs_path,
                "chown", new_value, parts[8] if len(parts) > 8 else "chown", ts,
                state_id=self._state_id,
                session_id=self._session_id,
                suspicious=suspicious,
            )
            if suspicious:
                self._dispatch_suspicious_change(
                    subject, abs_path, "chown", new_value, ts
                )

        elif ev_type == "MKDIR":
            self._mark_config_changed(abs_path, subject=subject)

            suspicious = self._is_suspicious_change(subject, abs_path, "create_dir")
            log.info(
                "⚙️  policy change: create_dir %s (subject=%s, state=%s, suspicious=%s)",
                abs_path, subject, self._state_id, suspicious,
            )
            self.store.record_policy_change(
                self._policy_version_id, subject, abs_path,
                "create_dir", "0755", extra, ts,
                state_id=self._state_id,
                session_id=self._session_id,
                suspicious=suspicious,
            )
            if suspicious:
                self._dispatch_suspicious_change(
                    subject, abs_path, "create_dir", "0755", ts
                )

        # Новые файлы меняют снимок; повторное открытие существующего — событие записи.
        elif ev_type in ("CREAT", "CREATE_FILE"):
            if abs_path not in self._snapshot.get("objects", {}):
                self._mark_config_changed(abs_path, subject=subject)

                suspicious = self._is_suspicious_change(
                    subject, abs_path, "create_file"
                )
                log.info(
                    "⚙️  policy change: create_file %s (subject=%s, state=%s, suspicious=%s)",
                    abs_path, subject, self._state_id, suspicious,
                )
                self.store.record_policy_change(
                    self._policy_version_id, subject, abs_path,
                    "create_file", "0644", extra, ts,
                    state_id=self._state_id,
                    session_id=self._session_id,
                    suspicious=suspicious,
                )
                if suspicious:
                    self._dispatch_suspicious_change(
                        subject, abs_path, "create_file", "0644", ts
                    )
            else:
                self._classify_and_store(subject, abs_path, "write", ts, os_allowed=True)

        # Успешное использование учитывается после применения ожидающих изменений снимка.
        elif ev_type in ("READ", "WRITE", "EXECUTE"):
            self._apply_pending_reload_incremental()
            self._classify_and_store(subject, abs_path, ev_type.lower(), ts, os_allowed=True)

        elif ev_type in ("DENIED_READ", "DENIED_WRITE", "DENIED_EXECUTE"):
            action = ev_type.replace("DENIED_", "").lower()
            err_code = int(extra) if ev_type != "DENIED_EXECUTE" else int(parts[6])
            self._apply_pending_reload_incremental()
            self._record_denied_access(subject, abs_path, action, err_code, ts)

        elif ev_type in ("DENIED_MKDIR", "DENIED_CHMOD", "DENIED_RENAME", "DENIED_CHOWN"):
            log.warning(
                "Попытка %s завершилась отказом ОС (subject=%s, path=%s)",
                ev_type, subject, abs_path,
            )

    # Управление процессом bpftrace и завершение мониторинга.

    def run(self, duration: int | None = None) -> None:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".bt", delete=False, encoding="utf-8"
        ) as tf:
            tf.write(BPFTRACE_SCRIPT)
            bt_file = tf.name

        cmd = ["sudo", "stdbuf", "-oL", "-eL", "bpftrace", bt_file]
        if duration:
            cmd = ["sudo", "timeout", str(duration),
                   "stdbuf", "-oL", "-eL", "bpftrace", bt_file]

        log.info(
            "bpftrace запущен%s. Нарушения алертятся мгновенно.",
            f" на {duration} сек" if duration else " (демон-режим, Ctrl+C для остановки)",
        )

        proc = None
        try:
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, bufsize=1,
            )
            for line in proc.stdout:
                self._handle_line(line)

            rc = proc.wait()
            stderr_out = proc.stderr.read()
            if rc not in (0, 124) and stderr_out:
                log.warning("bpftrace завершился с кодом %d:", rc)
                for l in stderr_out.splitlines():
                    if l.strip():
                        log.warning("  %s", l)

        except KeyboardInterrupt:
            log.info("Остановлено пользователем.")
            if proc and proc.poll() is None:
                proc.terminate()
        finally:
            if self._reload_timer is not None:
                self._reload_timer.cancel()
                self._reload_timer = None
            if self._daily_timer is not None:
                self._daily_timer.cancel()
                self._daily_timer = None
            try:
                self._apply_pending_reload_incremental(force=True)
                self._apply_pending()
            except Exception as e:
                log.error("Ошибка финального flush: %s", e)
            try:
                os.unlink(bt_file)
            except OSError:
                pass
            log.info("Мониторинг завершён. Версий политики: %d",
                     self.store.count_policy_versions())


def start_monitoring(
    target_dir: str,
    subjects: dict,
    dispatcher: AlertDispatcher,
    db_path: str = "policy_audit.db",
    snapshot_file: str = "config_snapshot.json",
    duration: int | None = None,
    checker: AccessChecker | None = None,
    whitelist: set[str] | None = None,
    heartbeat_sec: float | None = 86400.0,
) -> None:
    store = EventStore(db_path)
    try:
        mon = RealtimeMonitor(
            target_dir    = target_dir,
            subjects      = subjects,
            checker       = checker or default_checker(),
            dispatcher    = dispatcher,
            store         = store,
            snapshot_file = snapshot_file,
            whitelist     = whitelist,
            heartbeat_sec = heartbeat_sec,
        )
        mon.run(duration)
    finally:
        store.close()


if __name__ == "__main__":
    import argparse
    from dataclasses import asdict as _asdict
    from collector import auto_detect_subjects
    from alerts import build_dispatcher_from_config

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )

    p = argparse.ArgumentParser(description="Real-time мониторинг доступа (требует root)")
    p.add_argument("--dir",        required=True)
    p.add_argument("--snapshot", default="config_snapshot.json")
    p.add_argument("--db",       default="policy_audit.db")
    p.add_argument("--duration", type=int)
    p.add_argument("--users",    nargs="+")
    p.add_argument("--webhook")
    p.add_argument("--syslog",   action="store_true")
    p.add_argument("--alert-file", default="violations.jsonl")
    p.add_argument(
        "--whitelist", nargs="*", default=None,
        help="Список субъектов, чьи изменения создают новое состояние. "
             "Если флаг не задан — фильтр выключен.",
    )
    args = p.parse_args()

    if os.geteuid() != 0:
        print("Ошибка: мониторинг требует root. Запустите через sudo.")
        raise SystemExit(1)

    smap     = auto_detect_subjects(args.users)
    subjects = {k: _asdict(v) for k, v in smap.items()}

    dispatcher = build_dispatcher_from_config({
        "console": True,
        "file":    args.alert_file,
        "syslog":  args.syslog,
        "webhook": args.webhook,
    })

    start_monitoring(
        target_dir    = args.dir,
        subjects      = subjects,
        dispatcher    = dispatcher,
        db_path       = args.db,
        snapshot_file = args.snapshot,
        duration      = args.duration,
        whitelist     = set(args.whitelist) if args.whitelist is not None else None,
    )