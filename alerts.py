"""Нормализованные события нарушений и подключаемые каналы оповещения."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
import json
import logging
import os
import syslog
import time
import urllib.request


log = logging.getLogger("alerts")


@dataclass
class ViolationEvent:
    """Событие отказа в доступе или подозрительного изменения конфигурации."""

    timestamp: float
    subject: str
    path: str
    action: str
    mode: str
    kind: str = "denied"  # "denied" или "suspicious_change"


class AlertSink(ABC):
    """Интерфейс одного канала доставки уведомлений."""

    @abstractmethod
    def notify(self, event: ViolationEvent) -> None:
        pass


class ConsoleAlertSink(AlertSink):
    def notify(self, event: ViolationEvent) -> None:
        timestamp = time.strftime("%H:%M:%S", time.localtime(event.timestamp))
        if event.kind == "suspicious_change":
            color, label = "\033[93m", "SUSPICIOUS"
        else:
            color, label = "\033[91m", "DENIED"
        print(
            f"{color}[{label} {timestamp}]\033[0m "
            f"Subject: {event.subject} | Action: {event.action.upper()} | "
            f"Path: {event.path} | Mode: {event.mode}",
            flush=True,
        )


class FileAlertSink(AlertSink):
    """Записывает события в JSON Lines-файл с одной резервной копией."""

    def __init__(
        self,
        path: str = "violations.jsonl",
        max_bytes: int = 100 * 1024 * 1024,
    ):
        self.path = path
        self.max_bytes = max_bytes

    def _rotate_if_needed(self) -> None:
        if not os.path.exists(self.path):
            return
        if os.path.getsize(self.path) < self.max_bytes:
            return
        rotated = self.path + ".1"
        try:
            if os.path.exists(rotated):
                os.unlink(rotated)
            os.rename(self.path, rotated)
        except OSError as error:
            log.warning("Ошибка ротации файла алертов: %s", error)

    def notify(self, event: ViolationEvent) -> None:
        self._rotate_if_needed()
        payload = {
            "timestamp": event.timestamp,
            "subject": event.subject,
            "path": event.path,
            "action": event.action,
            "mode": event.mode,
            "kind": event.kind,
        }
        try:
            with open(self.path, "a", encoding="utf-8") as file:
                file.write(json.dumps(payload, ensure_ascii=False) + "\n")
        except OSError as error:
            log.error("Ошибка записи в файл алертов: %s", error)


class SyslogAlertSink(AlertSink):
    def __init__(self, ident: str = "policy_audit"):
        syslog.openlog(ident, syslog.LOG_PID, syslog.LOG_AUTH)

    def notify(self, event: ViolationEvent) -> None:
        message = (
            f"{event.kind.upper()} subject={event.subject} action={event.action} "
            f"path={event.path} mode={event.mode}"
        )
        syslog.syslog(syslog.LOG_WARNING, message)


class WebhookAlertSink(AlertSink):
    def __init__(self, url: str):
        self.url = url

    def notify(self, event: ViolationEvent) -> None:
        data = json.dumps(
            {
                "timestamp": event.timestamp,
                "subject": event.subject,
                "path": event.path,
                "action": event.action,
                "mode": event.mode,
                "kind": event.kind,
            }
        ).encode("utf-8")
        request = urllib.request.Request(
            self.url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=3.0):
                pass
        except Exception as error:
            log.error("Ошибка отправки webhook алерта: %s", error)


class ThrottledSink(AlertSink):
    """Ограничивает частоту одинаковых оповещений в заданном временном окне."""

    def __init__(self, inner: AlertSink, window_sec: float = 30.0):
        self._inner = inner
        self._window = window_sec
        self._last: dict[tuple[str, str, str, str], float] = {}

    def notify(self, event: ViolationEvent) -> None:
        key = (
            event.kind,
            event.subject,
            os.path.realpath(event.path),
            event.action,
        )
        now = time.time()
        last = self._last.get(key, 0.0)
        if now - last < self._window:
            return
        self._last[key] = now
        self._inner.notify(event)


class AlertDispatcher:
    """Передаёт событие всем настроенным каналам оповещения."""

    def __init__(self) -> None:
        self._sinks: list[AlertSink] = []

    def add_sink(self, sink: AlertSink) -> None:
        self._sinks.append(sink)

    def dispatch(self, event: ViolationEvent) -> None:
        for sink in self._sinks:
            try:
                sink.notify(event)
            except Exception as error:
                log.error("Ошибка при обработке алерта в %s: %s", sink, error)


def build_dispatcher_from_config(config: dict) -> AlertDispatcher:
    """Создаёт каналы оповещения и применяет к каждому общий throttle."""
    dispatcher = AlertDispatcher()
    throttle_sec = float(config.get("throttle_sec", 30.0))

    if config.get("console", True):
        dispatcher.add_sink(ThrottledSink(ConsoleAlertSink(), throttle_sec))
    if config.get("file"):
        dispatcher.add_sink(ThrottledSink(FileAlertSink(config["file"]), throttle_sec))
    if config.get("syslog"):
        dispatcher.add_sink(ThrottledSink(SyslogAlertSink(), throttle_sec))
    if config.get("webhook"):
        dispatcher.add_sink(ThrottledSink(WebhookAlertSink(config["webhook"]), throttle_sec))

    return dispatcher
