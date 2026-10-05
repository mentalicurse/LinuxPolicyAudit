#!/usr/bin/env python3
"""
dac.py — POSIX-проверка доступа к объекту и пути к нему.

check() проверяет биты owner/group/others или POSIX ACL.
check_with_path() дополнительно учитывает, что Linux требует право execute
на каждом родительском каталоге при разрешении пути.
"""
from __future__ import annotations

import os
from abc import ABC, abstractmethod


class AccessChecker(ABC):
    @abstractmethod
    def check(self, subject: dict, obj: dict, action: str) -> bool:
        ...

    def check_with_path(
        self,
        subject: dict,
        obj:     dict,
        action:  str,
        all_objects: dict[str, dict],
        target_dir:  str,
    ) -> bool:
        if not self.check(subject, obj, action):
            return False

        if subject.get("uid") == 0:
            return True

        target_dir = os.path.realpath(target_dir)
        path = os.path.realpath(obj["path"])

        parent = os.path.dirname(path)
        while parent and parent != target_dir and parent.startswith(target_dir):
            p_obj = all_objects.get(parent)
            if p_obj is None:
                return False
            if not self.check(subject, p_obj, "execute"):
                return False
            parent = os.path.dirname(parent)

        return True


class PosixDACChecker(AccessChecker):
    _BIT = {"read": 4, "write": 2, "execute": 1}

    def check(self, subject: dict, obj: dict, action: str) -> bool:
        s_uid = subject.get("uid")
        if s_uid == 0:
            return True

        try:
            mode = int(obj.get("mode", "0000"), 8)
        except (ValueError, TypeError):
            return False

        s_gids = subject.get("gids", [])
        o_uid  = obj.get("uid")
        o_gid  = obj.get("gid")

        if s_uid == o_uid:
            shift = 6
        elif o_gid in s_gids:
            shift = 3
        else:
            shift = 0

        bits = (mode >> shift) & 0o7
        return bool(bits & self._BIT.get(action, 0))


class PosixACLChecker(AccessChecker):
    _ACTION_TO_CHAR = {"read": "r", "write": "w", "execute": "x"}

    @staticmethod
    def _parse_perm_set(perms: str) -> set[str]:
        return {char for char, flag in zip("rwx", perms) if flag != "-"}

    @staticmethod
    def _clean_entry(entry: str) -> str:
        if "#" in entry:
            entry = entry.split("#")[0]
        return entry.strip()

    def __init__(self, fallback: AccessChecker | None = None):
        self._fallback = fallback or PosixDACChecker()

    def check(self, subject: dict, obj: dict, action: str) -> bool:
        acl_entries = obj.get("acl") or []
        if not acl_entries:
            return self._fallback.check(subject, obj, action)

        s_name = subject.get("name")
        s_groups = set(subject.get("groups", []))
        action_char = self._ACTION_TO_CHAR.get(action)
        if action_char is None:
            return False

        mask_perms = None
        named_user_perms = None
        named_group_perms = None

        for raw in acl_entries:
            entry = self._clean_entry(raw)
            parts = entry.split(":")
            if len(parts) != 3:
                continue
            kind, name, perms = parts
            if kind == "mask" and name == "":
                mask_perms = self._parse_perm_set(perms)
            elif kind == "user" and name == s_name:
                named_user_perms = self._parse_perm_set(perms)
            elif kind == "group" and name in s_groups and named_group_perms is None:
                named_group_perms = self._parse_perm_set(perms)

        effective = None
        if named_user_perms is not None:
            effective = named_user_perms
        elif named_group_perms is not None:
            effective = named_group_perms

        if effective is not None:
            if mask_perms is not None:
                effective = effective & mask_perms
            return action_char in effective

        return self._fallback.check(subject, obj, action)


def default_checker() -> AccessChecker:
    return PosixDACChecker()