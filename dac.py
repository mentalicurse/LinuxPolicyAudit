#!/usr/bin/env python3
"""Проверка POSIX DAC/ACL и доступности объекта через родительские каталоги."""

from __future__ import annotations

import os
from abc import ABC, abstractmethod


class AccessChecker(ABC):
    """Общий интерфейс проверки действия субъекта над объектом."""

    @abstractmethod
    def check(self, subject: dict, obj: dict, action: str) -> bool:
        ...

    def check_with_path(
        self,
        subject: dict,
        obj: dict,
        action: str,
        all_objects: dict[str, dict],
        target_dir: str,
    ) -> bool:
        """Проверяет объект и execute-доступ к каталогам на пути к нему."""
        path = os.path.realpath(obj["path"])
        if target_dir:
            target_dir = os.path.realpath(target_dir)
            try:
                if os.path.commonpath((target_dir, path)) != target_dir:
                    return False
            except ValueError:
                return False
        if not self.check(subject, obj, action):
            return False
        if subject.get("uid") == 0:
            return True
        if not target_dir:
            return True
        parent = os.path.dirname(path)
        while parent and parent != target_dir:
            try:
                if os.path.commonpath((target_dir, parent)) != target_dir:
                    break
            except ValueError:
                break
            parent_obj = all_objects.get(parent)
            if parent_obj is None:
                return False
            if not self.check(subject, parent_obj, "execute"):
                return False
            parent = os.path.dirname(parent)
        return True


class PosixDACChecker(AccessChecker):
    """Проверяет стандартные биты владельца, группы и остальных."""
    _BIT = {"read": 4, "write": 2, "execute": 1}

    def check(self, subject: dict, obj: dict, action: str) -> bool:
        subject_uid = subject.get("uid")
        if subject_uid == 0:
            return True
        try:
            mode = int(obj.get("mode", "0000"), 8)
        except (ValueError, TypeError):
            return False
        subject_gids = subject.get("gids", [])
        object_uid = obj.get("uid")
        object_gid = obj.get("gid")
        if subject_uid == object_uid:
            shift = 6
        elif object_gid in subject_gids:
            shift = 3
        else:
            shift = 0
        bits = (mode >> shift) & 0o7
        return bool(bits & self._BIT.get(action, 0))


class PosixACLChecker(AccessChecker):
    """Проверяет POSIX ACL с учётом mask и стандартным DAC fallback."""
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
        if subject.get("uid") == 0:
            return True
        acl_entries = obj.get("acl") or []
        if not acl_entries:
            return self._fallback.check(subject, obj, action)
        action_char = self._ACTION_TO_CHAR.get(action)
        if action_char is None:
            return False
        subject_uid = subject.get("uid")
        if subject_uid == obj.get("uid"):
            return self._fallback.check(subject, obj, action)
        subject_names = {str(subject.get("name", "")), str(subject_uid)}
        subject_groups = {str(group) for group in subject.get("groups", [])}
        subject_gids = {str(gid) for gid in subject.get("gids", [])}
        group_perms: set[str] = set()
        matched_group = False
        named_user_perms: set[str] | None = None
        mask_perms: set[str] | None = None
        other_perms: set[str] | None = None
        for raw_entry in acl_entries:
            entry = self._clean_entry(raw_entry)
            parts = entry.split(":")
            if len(parts) != 3:
                continue
            kind, name, perms = parts
            if kind == "mask" and not name:
                mask_perms = self._parse_perm_set(perms)
            elif kind == "user" and name and name in subject_names:
                named_user_perms = self._parse_perm_set(perms)
            elif kind == "group":
                if not name:
                    matches = str(obj.get("gid")) in subject_gids
                else:
                    matches = name in subject_groups or name in subject_gids
                if matches:
                    matched_group = True
                    group_perms.update(self._parse_perm_set(perms))
            elif kind == "other" and not name:
                other_perms = self._parse_perm_set(perms)
        if named_user_perms is not None:
            if mask_perms is not None:
                named_user_perms &= mask_perms
            return action_char in named_user_perms
        if matched_group:
            if mask_perms is not None:
                group_perms &= mask_perms
            return action_char in group_perms
        if other_perms is not None:
            return action_char in other_perms
        return self._fallback.check(subject, obj, action)


def default_checker() -> AccessChecker:
    """Возвращает стандартную проверку с поддержкой ACL."""
    return PosixACLChecker()
