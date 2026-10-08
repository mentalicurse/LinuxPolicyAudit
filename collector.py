#!/usr/bin/env python3
"""Собирает конфигурацию доступа из файловой системы и FreeIPA.

Снимки сохраняются приложением в SQLite. У каждого снимка есть временная метка
и хеш: monitor.py начинает новую эпоху при изменении конфигурации.
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
from dataclasses import asdict, dataclass
from typing import Optional


@dataclass
class SubjectInfo:
    """Пользователь и его группы для проверки прав доступа."""

    name: str
    uid: int
    gids: list[int]
    groups: list[str]


@dataclass
class ObjectInfo:
    """Метаданные файловой системы, необходимые для проверки прав."""

    path: str
    obj_type: str
    uid: int
    gid: int
    mode: str
    owner: str
    group: str
    acl: list[str]


def _normalize_for_compare(value):
    """Сортирует вложенные значения и удаляет повторы для стабильного сравнения."""
    if isinstance(value, dict):
        return {key: _normalize_for_compare(item) for key, item in sorted(value.items())}
    if isinstance(value, list):
        items = [_normalize_for_compare(item) for item in value]
        try:
            items = sorted(items)
        except TypeError:
            items = sorted(
                items,
                key=lambda item: json.dumps(
                    item, sort_keys=True, separators=(",", ":")
                ),
            )

        normalized = []
        seen = set()
        for item in items:
            marker = json.dumps(item, sort_keys=True, separators=(",", ":"))
            if marker not in seen:
                seen.add(marker)
                normalized.append(item)
        return normalized
    return value


def snapshot_is_equal(left: dict, right: dict) -> bool:
    """Сравнивает снимки без учёта timestamp, hash и порядка элементов списков."""
    left_norm = {
        key: value
        for key, value in left.items()
        if key not in {"timestamp", "snapshot_hash"}
    }
    right_norm = {
        key: value
        for key, value in right.items()
        if key not in {"timestamp", "snapshot_hash"}
    }
    return _normalize_for_compare(left_norm) == _normalize_for_compare(right_norm)


def compute_snapshot_hash(snapshot: dict) -> str:
    """Вычисляет хеш только для субъектов и объектов, без временных данных."""
    blob = json.dumps(
        _normalize_for_compare(
            {
                "subjects": snapshot.get("subjects", {}),
                "objects": snapshot.get("objects", {}),
            }
        ),
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()[:16]


@dataclass
class ConfigSnapshot:
    timestamp: float
    target_dir: str
    subjects: dict[str, dict]
    objects: dict[str, dict]
    snapshot_hash: str = ""

    def compute_hash(self) -> str:
        return compute_snapshot_hash(
            {
                "subjects": self.subjects,
                "objects": self.objects,
            }
        )


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
    """Возвращает записи ACL, отличные от базовых; без getfacl список пуст."""
    try:
        result = subprocess.run(
            ["getfacl", "--omit-header", "--skip-base", path],
            capture_output=True,
            text=True,
            timeout=5,
        )
        return [
            line.strip()
            for line in result.stdout.splitlines()
            if line.strip() and not line.startswith("#")
        ]
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []


def get_object_metadata(path: str, obj_type: str | None = None) -> dict | None:
    """Читает владельца, режим и ACL поддерживаемого объекта файловой системы."""
    try:
        st = os.lstat(path)
    except OSError:
        return None

    if obj_type is None:
        if stat.S_ISDIR(st.st_mode):
            obj_type = "directory"
        elif stat.S_ISREG(st.st_mode):
            obj_type = "file"
        else:
            return None
    elif stat.S_ISLNK(st.st_mode):
        return None

    real = os.path.realpath(path)
    return {
        "path": real,
        "obj_type": obj_type,
        "uid": st.st_uid,
        "gid": st.st_gid,
        "mode": f"{stat.S_IMODE(st.st_mode):04o}",
        "owner": _uid_to_name(st.st_uid),
        "group": _gid_to_name(st.st_gid),
        "acl": _get_acl(real),
    }


def scan_filesystem(root_dir: str) -> dict[str, ObjectInfo]:
    """Рекурсивно собирает метаданные, пропуская ссылки и неподдерживаемые объекты."""
    objects: dict[str, ObjectInfo] = {}
    root_real = os.path.realpath(root_dir)
    if not os.path.isdir(root_real):
        raise NotADirectoryError(root_dir)

    def raise_walk_error(error: OSError) -> None:
        raise error

    for dirpath, dirnames, filenames in os.walk(
        root_real, onerror=raise_walk_error
    ):
        # Не обходить каталоги-ссылки и не включать файлы-ссылки в снимок.
        dirnames[:] = [
            name
            for name in dirnames
            if not os.path.islink(os.path.join(dirpath, name))
        ]
        entries = (
            [(dirpath, "directory")]
            + [(os.path.join(dirpath, name), "directory") for name in dirnames]
            + [
                (os.path.join(dirpath, name), "file")
                for name in filenames
                if not os.path.islink(os.path.join(dirpath, name))
            ]
        )
        for path, obj_type in entries:
            meta = get_object_metadata(path, obj_type)
            if meta is not None:
                objects[meta["path"]] = ObjectInfo(**meta)

    return objects


def _local_user_info(username: str) -> Optional[SubjectInfo]:
    try:
        pw = pwd.getpwnam(username)
    except KeyError:
        return None

    gids = [group.gr_gid for group in grp.getgrall() if username in group.gr_mem]
    gids.append(pw.pw_gid)
    gids = sorted(set(gids))
    group_names = sorted(_gid_to_name(gid) for gid in gids)
    return SubjectInfo(
        name=pw.pw_name,
        uid=pw.pw_uid,
        gids=gids,
        groups=group_names,
    )


def collect_local_subjects(usernames: list[str]) -> dict[str, SubjectInfo]:
    """Собирает сведения об учетных записях и дополнительных группах пользователей."""
    result = {}
    for name in usernames:
        info = _local_user_info(name)
        if info:
            result[name] = info
    return result


# Эти группы FreeIPA управляют службой каталогов, а не доступом к файлам.
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
    "ipausers",  # Общая группа домена не описывает отдельные файловые права.
    "hbac",  # Группа подсистемы контроля доступа FreeIPA.
}


def _is_system_group(name: str) -> bool:
    if not name or len(name) > 40:
        # Длинные описательные имена обычно относятся к служебным группам.
        return True
    if name in _SYSTEM_GROUP_EXACT:
        return True
    return any(name.startswith(prefix) for prefix in _SYSTEM_GROUP_PREFIXES)


def collect_freeipa_subjects(
    ldap_uri: str,
    bind_dn: str,
    bind_pw: str,
    base_dn: str,
    uid_min: int = 1_000_000,
) -> dict[str, SubjectInfo]:
    """Читает пользователей FreeIPA, исключая служебные группы."""
    try:
        from ldap3 import ALL, SUBTREE, Connection, Server
    except ImportError:
        print("[collector] ldap3 не установлен, FreeIPA пропущен.")
        return {}

    subjects: dict[str, SubjectInfo] = {}
    try:
        server = Server(ldap_uri, get_info=ALL)
        conn = Connection(server, bind_dn, bind_pw, auto_bind=True)
        conn.search(
            base_dn,
            f"(&(objectClass=posixAccount)(uidNumber>={uid_min}))",
            SUBTREE,
            attributes=["uid", "uidNumber", "gidNumber", "memberOf"],
        )

        for entry in conn.entries:
            username = str(entry.uid.value)
            uid = int(entry.uidNumber.value)
            gid = int(entry.gidNumber.value)

            member_of = entry.memberOf.values if entry.memberOf else []
            group_names: list[str] = []
            for dn in member_of:
                match = re.search(r"cn=([^,]+)", str(dn))
                if not match:
                    continue
                group_name = match.group(1)
                if not _is_system_group(group_name):
                    group_names.append(group_name)

            # Проверки DAC используют GID, а FreeIPA возвращает имена групп.
            gids = [gid]
            for group_name in group_names:
                try:
                    gids.append(grp.getgrnam(group_name).gr_gid)
                except KeyError:
                    # Неизвестную локально группу сохраняем для отчётов, но не для проверки GID.
                    pass

            subjects[username] = SubjectInfo(
                name=username,
                uid=uid,
                gids=sorted(set(gids)),
                groups=sorted(group_names),
            )

        conn.unbind()
    except Exception as error:
        print(f"[collector] FreeIPA LDAP ошибка: {error}")

    return subjects


def auto_detect_subjects(
    explicit: list[str] | None = None,
    uid_min: int = 1_000,
) -> dict[str, SubjectInfo]:
    """Берёт указанных пользователей или автоматически находит несистемные учётные записи."""
    if explicit:
        return collect_local_subjects(explicit)

    subjects = {}
    for pw in pwd.getpwall():
        if pw.pw_uid >= uid_min and pw.pw_name not in ("nobody", "nfsnobody"):
            info = _local_user_info(pw.pw_name)
            if info:
                subjects[pw.pw_name] = info

    if not subjects:
        username = pwd.getpwuid(os.getuid()).pw_name
        info = _local_user_info(username)
        if info:
            subjects[username] = info

    return subjects


def collect_snapshot(
    target_dir: str,
    subjects_map: dict[str, SubjectInfo],
) -> ConfigSnapshot:
    """Объединяет объекты файловой системы и субъектов в снимок с временной меткой."""
    objects = scan_filesystem(target_dir)
    snapshot = ConfigSnapshot(
        timestamp=time.time(),
        target_dir=os.path.realpath(target_dir),
        subjects={key: asdict(value) for key, value in subjects_map.items()},
        objects={key: asdict(value) for key, value in objects.items()},
    )
    snapshot.snapshot_hash = snapshot.compute_hash()
    return snapshot
