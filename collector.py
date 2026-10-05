#!/usr/bin/env python3
"""
collector.py — снимает конфигурацию прав доступа из трёх источников:
  1. POSIX-права файловой системы (stat + mode)
  2. POSIX ACL (через getfacl)
  3. FreeIPA / LDAP — пользователи, группы, членство

Результат сохраняется в config_snapshot.json.
Каждый снимок имеет timestamp и hash — при изменении конфига
monitor.py начнёт новую эпоху автоматически.
"""
from __future__ import annotations

import grp
import hashlib
import json
import os
import pwd
import re
import stat
import subprocess
import time
from dataclasses import dataclass, field, asdict
from typing import Optional


# Структуры данных

@dataclass
class SubjectInfo:
    name:   str
    uid:    int
    gids:   list[int]
    groups: list[str]


@dataclass
class ObjectInfo:
    path:     str
    obj_type: str
    uid:      int
    gid:      int
    mode:     str
    owner:    str
    group:    str
    acl:      list[str]


# Нормализация и сравнение снимков

def _normalize_for_compare(value):
    if isinstance(value, dict):
        return {k: _normalize_for_compare(v) for k, v in sorted(value.items())}
    if isinstance(value, list):
        items = [_normalize_for_compare(v) for v in value]
        try:
            items = sorted(items)
        except TypeError:
            items = sorted(
                items,
                key=lambda x: json.dumps(x, sort_keys=True, separators=(",", ":")),
            )
        normalized = []
        seen = set()
        for item in items:
            marker = json.dumps(item, sort_keys=True, separators=(",", ":"))
            if marker in seen:
                continue
            seen.add(marker)
            normalized.append(item)
        return normalized
    return value


def snapshot_is_equal(left: dict, right: dict) -> bool:
    """Сравнивает снимки по смыслу, игнорируя timestamp/hash и порядок в ACL/списках."""
    left_norm  = {k: v for k, v in left.items()
                  if k not in {"timestamp", "snapshot_hash"}}
    right_norm = {k: v for k, v in right.items()
                  if k not in {"timestamp", "snapshot_hash"}}
    return _normalize_for_compare(left_norm) == _normalize_for_compare(right_norm)


def compute_snapshot_hash(snapshot: dict) -> str:
    """Хеш только значимой части снимка: subjects + objects."""
    blob = json.dumps(
        _normalize_for_compare({
            "subjects": snapshot.get("subjects", {}),
            "objects":  snapshot.get("objects", {}),
        }),
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()[:16]


@dataclass
class ConfigSnapshot:
    timestamp:     float
    target_dir:    str
    subjects:      dict[str, dict]
    objects:       dict[str, dict]
    snapshot_hash: str = ""

    def compute_hash(self) -> str:
        return compute_snapshot_hash({
            "subjects": self.subjects,
            "objects":  self.objects,
        })


# POSIX-владельцы, права доступа и ACL.

def _uid_to_name(uid: int) -> str:
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return str(uid)


def _gid_to_name(gid: int) -> str:
    try:
        return grp.getgrgid(gid).gr_name
    except KeyError:
        return str(gid)


def _get_acl(path: str) -> list[str]:
    try:
        result = subprocess.run(
            ["getfacl", "--omit-header", "--skip-base", path],
            capture_output=True, text=True, timeout=5,
        )
        return [l.strip() for l in result.stdout.splitlines()
                if l.strip() and not l.startswith("#")]
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []


def get_object_metadata(path: str, obj_type: str | None = None) -> dict | None:
    try:
        st = os.stat(path)
    except OSError:
        return None

    if obj_type is None:
        if stat.S_ISDIR(st.st_mode):
            obj_type = "directory"
        elif stat.S_ISREG(st.st_mode):
            obj_type = "file"
        else:
            return None

    real = os.path.realpath(path)
    return {
        "path":     real,
        "obj_type": obj_type,
        "uid":      st.st_uid,
        "gid":      st.st_gid,
        "mode":     f"{stat.S_IMODE(st.st_mode):04o}",
        "owner":    _uid_to_name(st.st_uid),
        "group":    _gid_to_name(st.st_gid),
        "acl":      _get_acl(real),
    }


def scan_filesystem(root_dir: str) -> dict[str, ObjectInfo]:
    objects: dict[str, ObjectInfo] = {}
    root_real = os.path.realpath(root_dir)

    for dirpath, dirnames, filenames in os.walk(root_real):
        entries = (
            [(dirpath, "directory")]
            + [(os.path.join(dirpath, d), "directory") for d in dirnames]
            + [(os.path.join(dirpath, f), "file")      for f in filenames]
        )
        for name, obj_type in entries:
            meta = get_object_metadata(name, obj_type)
            if meta is None:
                continue
            objects[meta["path"]] = ObjectInfo(**meta)

    return objects


# Локальные субъекты

def _local_user_info(username: str) -> Optional[SubjectInfo]:
    try:
        pw = pwd.getpwnam(username)
    except KeyError:
        return None
    gids = [g.gr_gid for g in grp.getgrall() if username in g.gr_mem]
    gids.append(pw.pw_gid)
    gids = sorted(set(gids))
    gnames = sorted(_gid_to_name(g) for g in gids)
    return SubjectInfo(name=pw.pw_name, uid=pw.pw_uid,
                       gids=gids, groups=gnames)


def collect_local_subjects(usernames: list[str]) -> dict[str, SubjectInfo]:
    result = {}
    for name in usernames:
        info = _local_user_info(name)
        if info:
            result[name] = info
    return result


# Фильтр системных групп FreeIPA

# Эти служебные группы управляют FreeIPA (репликацией, регистрацией хостов,
# HBAC и т. п.), а не файловым доступом, поэтому не должны попадать в аудит.
_SYSTEM_GROUP_PREFIXES = (
    "System:",
    "Replication",
    "Add ",
    "Modify ",
    "Read ",
    "Remove ",
    "Write ",
    "Host ",
    "DNA",
    "PassSync",
    "LDBM",
    "Domain ",
)

_SYSTEM_GROUP_EXACT = {
    "admins",
    "trust admins",
    "ipaservers",
    "editors",
    "ipausers",           # Общая группа домена не описывает отдельные файловые права.
    "hbac",               # Группа подсистемы контроля доступа FreeIPA.
}


def _is_system_group(name: str) -> bool:
    if not name:
        return True
    if len(name) > 40:                # Длинные описательные имена обычно служебные.
        return True
    if name in _SYSTEM_GROUP_EXACT:
        return True
    for p in _SYSTEM_GROUP_PREFIXES:
        if name.startswith(p):
            return True
    return False


# Доменные субъекты FreeIPA

def collect_freeipa_subjects(
    ldap_uri:    str,
    bind_dn:     str,
    bind_pw:     str,
    base_dn:     str,
    uid_min:     int = 1_000_000,
) -> dict[str, SubjectInfo]:
    """
    Читает пользователей FreeIPA через LDAP. Системные группы отфильтровываются.
    При отсутствии библиотеки ldap3 или недоступности сервера возвращает {}.
    """
    try:
        from ldap3 import Server, Connection, ALL, SUBTREE
    except ImportError:
        print("[collector] ldap3 не установлен, FreeIPA пропущен.")
        return {}

    subjects: dict[str, SubjectInfo] = {}
    try:
        server = Server(ldap_uri, get_info=ALL)
        conn   = Connection(server, bind_dn, bind_pw, auto_bind=True)

        conn.search(
            base_dn,
            f"(&(objectClass=posixAccount)(uidNumber>={uid_min}))",
            SUBTREE,
            attributes=["uid", "uidNumber", "gidNumber", "memberOf"],
        )

        for entry in conn.entries:
            uname = str(entry.uid.value)
            uid   = int(entry.uidNumber.value)
            gid   = int(entry.gidNumber.value)

            member_of = entry.memberOf.values if entry.memberOf else []
            gnames: list[str] = []
            for dn in member_of:
                m = re.search(r"cn=([^,]+)", str(dn))
                if not m:
                    continue
                gname = m.group(1)
                if _is_system_group(gname):
                    continue
                gnames.append(gname)

            # Локальные проверки DAC используют числовые GID, FreeIPA отдаёт имена групп.
            gids = [gid]
            for gname in gnames:
                try:
                    gids.append(grp.getgrnam(gname).gr_gid)
                except KeyError:
                    # Неизвестная локальной ОС группа остаётся в groups для отчёта,
                    # но не может участвовать в сравнении POSIX GID.
                    pass

            subjects[uname] = SubjectInfo(
                name=uname, uid=uid,
                gids=sorted(set(gids)),
                groups=sorted(gnames),
            )

        conn.unbind()

    except Exception as e:
        print(f"[collector] FreeIPA LDAP ошибка: {e}")

    return subjects


# Автоопределение субъектов

def auto_detect_subjects(
    explicit: list[str] | None = None,
    uid_min:  int = 1_000,
) -> dict[str, SubjectInfo]:
    if explicit:
        return collect_local_subjects(explicit)

    subjects = {}
    for pw in pwd.getpwall():
        if pw.pw_uid >= uid_min and pw.pw_name not in ("nobody", "nfsnobody"):
            info = _local_user_info(pw.pw_name)
            if info:
                subjects[pw.pw_name] = info

    if not subjects:
        me = pwd.getpwuid(os.getuid()).pw_name
        info = _local_user_info(me)
        if info:
            subjects[me] = info

    return subjects


# Сборка снимка

def collect_snapshot(
    target_dir:   str,
    subjects_map: dict[str, SubjectInfo],
) -> ConfigSnapshot:
    objects = scan_filesystem(target_dir)

    snap = ConfigSnapshot(
        timestamp  = time.time(),
        target_dir = os.path.realpath(target_dir),
        subjects   = {k: asdict(v) for k, v in subjects_map.items()},
        objects    = {k: asdict(v) for k, v in objects.items()},
    )
    snap.snapshot_hash = snap.compute_hash()
    return snap


def save_snapshot(snap: ConfigSnapshot, path: str = "config_snapshot.json") -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(asdict(snap), f, indent=2, ensure_ascii=False)
    print(f"[collector] Снимок сохранён: {path}  hash={snap.snapshot_hash}")


def load_snapshot(path: str) -> ConfigSnapshot | None:
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as f:
        d = json.load(f)
    return ConfigSnapshot(**d)


# CLI

if __name__ == "__main__":
    import argparse

    p = argparse.ArgumentParser(description="Сбор конфигурации прав доступа")
    p.add_argument("--dir",      required=True)
    p.add_argument("--users",    nargs="+")
    p.add_argument("--uid-min",  type=int, default=1_000)
    p.add_argument("--out",      default="config_snapshot.json")
    p.add_argument("--freeipa")
    p.add_argument("--bind-dn")
    p.add_argument("--bind-pw")
    p.add_argument("--base-dn")
    args = p.parse_args()

    subjects = auto_detect_subjects(args.users, args.uid_min)

    if args.freeipa and args.bind_dn and args.base_dn:
        ipa_subjects = collect_freeipa_subjects(
            args.freeipa, args.bind_dn, args.bind_pw or "", args.base_dn
        )
        subjects.update(ipa_subjects)

    print(f"[collector] Субъектов: {len(subjects)} — {list(subjects.keys())}")
    snap = collect_snapshot(args.dir, subjects)
    save_snapshot(snap, args.out)