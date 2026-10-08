#!/usr/bin/env python3
"""Построение графиков и диаграмм по результатам аудита."""

from __future__ import annotations

import os

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np
from matplotlib.colors import BoundaryNorm, ListedColormap

from analyzer import _expand_used_with_traversal


CLR_USED = "#22c55e"
CLR_REDUNDANT = "#facc15"
CLR_VIOLATION = "#ef4444"
CLR_NONE = "#d1d5db"
CLR_DIR = "#3b82f6"
CLR_FILE = "#f97316"


def draw_fs_tree(snapshot: dict, audit, output_file: str = "fs_tree") -> None:
    try:
        from graphviz import Digraph
    except ImportError:
        print("[viz] graphviz не установлен. Пропущено.")
        return


def _usage_triplets_for_display(audit, used_triples=None):
    if used_triples is not None:
        return set(used_triples)
    return set(getattr(audit, "used_triples", set()))


def draw_rights_matrix(
    snapshot,
    audit,
    used_triples,
    output_file="rights_matrix.png",
    max_subjects=None,
    max_objects=None,
) -> None:
    """Рисует матрицу фактически использованных, лишних и нарушенных прав."""
    subjects = sorted(snapshot.get("subjects", {}).keys())
    objects = sorted(snapshot.get("objects", {}).keys())
    if max_subjects is not None:
        subjects = subjects[:max_subjects]
    if max_objects is not None:
        objects = objects[:max_objects]

    subject_indexes = {subject: index for index, subject in enumerate(subjects)}
    object_indexes = {path: index for index, path in enumerate(objects)}
    matrix = np.zeros((len(subjects), len(objects)), dtype=int)

    used_raw = _usage_triplets_for_display(audit, used_triples)
    used = _expand_used_with_traversal(
        used_raw,
        snapshot.get("objects", {}),
        snapshot.get("target_dir", ""),
    )
    for subject, path, action in used:
        subject_index = subject_indexes.get(subject)
        object_index = object_indexes.get(path)
        if subject_index is not None and object_index is not None:
            matrix[subject_index, object_index] = 1

    for right in getattr(audit, "redundant", []):
        subject_index = subject_indexes.get(right.subject)
        object_index = object_indexes.get(right.path)
        if (
            subject_index is not None
            and object_index is not None
            and matrix[subject_index, object_index] == 0
        ):
            matrix[subject_index, object_index] = 2

    for violation in getattr(audit, "violations", []):
        subject_index = subject_indexes.get(violation.get("subject"))
        object_index = object_indexes.get(violation.get("path"))
        if subject_index is not None and object_index is not None:
            matrix[subject_index, object_index] = 3

    cmap = ListedColormap(["#ffffff", "#111111", "#d0d0d0", "#888888"])
    norm = BoundaryNorm([0, 1, 2, 3, 4], cmap.N)
    fig_w = max(12, len(objects) * 0.42)
    fig_h = max(5, len(subjects) * 0.42)
    fig, ax = plt.subplots(figsize=(fig_w, fig_h))
    fig.patch.set_facecolor("white")
    ax.imshow(matrix, cmap=cmap, norm=norm, aspect="auto")

    ax.set_xticks(np.arange(-0.5, len(objects), 1), minor=True)
    ax.set_yticks(np.arange(-0.5, len(subjects), 1), minor=True)
    ax.grid(which="minor", color="#bbbbbb", linewidth=0.5)
    ax.tick_params(which="minor", length=0)
    ax.set_xticks(range(len(objects)))
    ax.set_xticklabels(
        [os.path.basename(path) or path for path in objects],
        rotation=50,
        ha="right",
        fontsize=8,
        color="black",
    )
    ax.set_yticks(range(len(subjects)))
    ax.set_yticklabels(subjects, fontsize=9, color="black")
    ax.set_title(
        "Матрица прав доступа (субъекты × объекты)",
        fontsize=13,
        fontweight="bold",
        pad=16,
        color="black",
    )
    ax.set_xlabel("Объекты ФС", fontsize=10)
    ax.set_ylabel("Субъекты", fontsize=10)

    legend = [
        mpatches.Patch(facecolor="#ffffff", edgecolor="black", label="Нет прав"),
        mpatches.Patch(facecolor="#111111", edgecolor="black", label="Использовано"),
        mpatches.Patch(facecolor="#d0d0d0", edgecolor="black", label="Избыточно"),
        mpatches.Patch(facecolor="#888888", edgecolor="black", label="Нарушение"),
    ]
    ax.legend(
        handles=legend,
        loc="upper left",
        bbox_to_anchor=(1.01, 1),
        borderaxespad=0,
        frameon=False,
        fontsize=9,
    )
    for spine in ax.spines.values():
        spine.set_color("black")

    plt.tight_layout()
    plt.savefig(output_file, dpi=150, bbox_inches="tight", facecolor="white")
    plt.close()
    print(f"[viz] Матрица: {output_file}")


def draw_usage_graph(
    snapshot,
    audit,
    output_file="usage_graph.png",
    used_triples=None,
    title="Использование прав",
) -> None:
    """Показывает связи между субъектами, объектами и действиями."""
    used = _usage_triplets_for_display(audit, used_triples)
    if not used:
        print("[viz] Нет данных для usage graph.")
        return

    subjects = sorted({subject for subject, _, _ in used})
    objects = sorted({path for _, path, _ in used})
    subject_count, object_count = len(subjects), len(objects)
    row_height = 0.7
    height = max(subject_count, object_count) * row_height + 1.8
    fig, ax = plt.subplots(figsize=(13, height))
    fig.patch.set_facecolor("white")
    ax.set_xlim(0, 10)
    ax.set_ylim(0, max(subject_count, object_count) * row_height + 1)
    ax.axis("off")
    ax.text(
        5,
        max(subject_count, object_count) * row_height + 0.9,
        title,
        ha="center",
        va="center",
        fontsize=13,
        fontweight="bold",
        color="#111111",
    )

    subject_y = {
        subject: (subject_count - index - 0.5) * row_height
        for index, subject in enumerate(subjects)
    }
    object_y = {
        path: (object_count - index - 0.5) * row_height
        for index, path in enumerate(objects)
    }
    for subject, y in subject_y.items():
        ax.text(1.2, y, subject, ha="right", va="center", fontsize=10, color="#111111")
        ax.plot([1.35, 1.35], [y - 0.22, y + 0.22], color="#111111", linewidth=1.2)
    for path, y in object_y.items():
        name = os.path.basename(path) or path
        ax.text(8.8, y, name, ha="left", va="center", fontsize=9, color="#111111")
        ax.plot([8.65, 8.65], [y - 0.22, y + 0.22], color="#111111", linewidth=1.2)

    color_by_action = {
        "read": "#2ca02c",
        "write": "#1f77b4",
        "execute": "#111111",
    }
    default_color = "#888888"

    from matplotlib.path import Path
    from matplotlib.patches import PathPatch

    pair_counter: dict[tuple[str, str], int] = {}
    for subject, path, action in used:
        key = (subject, path)
        pair_counter[key] = pair_counter.get(key, 0) + 1

    pair_index: dict[tuple[str, str], int] = {}
    drawn_styles: set = set()
    x1, x2 = 1.45, 8.55
    base_bend = 0.35
    step_bend = 0.40

    for subject, path, action in sorted(used):
        if subject not in subject_y or path not in object_y:
            continue
        y1, y2 = subject_y[subject], object_y[path]
        color = color_by_action.get(action, default_color)
        label = action if action not in drawn_styles else None
        drawn_styles.add(action)

        key = (subject, path)
        index = pair_index.get(key, 0)
        pair_index[key] = index + 1
        total = pair_counter[key]
        if total == 1:
            bend = 0.0
        else:
            offset = (
                (index - (total - 1) / 2) / max(1, (total - 1) / 2)
                if total > 1
                else 0
            )
            bend = offset * base_bend + (index - (total - 1) / 2) * step_bend * 0.4

        midpoint = (x1 + x2) / 2
        vertices = [(x1, y1), (midpoint - bend, y1), (midpoint + bend, y2), (x2, y2)]
        codes = [Path.MOVETO, Path.CURVE4, Path.CURVE4, Path.CURVE4]
        patch = PathPatch(
            Path(vertices, codes),
            facecolor="none",
            edgecolor=color,
            linewidth=1.8,
            label=label,
            alpha=0.9,
        )
        ax.add_patch(patch)
        ax.annotate(
            "",
            xy=(x2, y2),
            xytext=(x2 - 0.15, y2),
            arrowprops=dict(arrowstyle="-|>", color=color, lw=1.8),
        )

    from matplotlib.lines import Line2D

    handles = [
        Line2D([0], [0], color=color_by_action["read"], lw=2, label="read"),
        Line2D([0], [0], color=color_by_action["write"], lw=2, label="write"),
        Line2D([0], [0], color=color_by_action["execute"], lw=2, label="execute"),
    ]
    ax.legend(
        handles=handles,
        loc="upper center",
        bbox_to_anchor=(0.5, -0.02),
        ncol=3,
        frameon=False,
        fontsize=11,
    )
    plt.tight_layout()
    plt.savefig(output_file, dpi=150, bbox_inches="tight", facecolor="white")
    plt.close()
    print(f"[viz] Usage graph: {output_file}")


def draw_state_machine(
    state_transitions: list[dict],
    output_file="state_machine.png",
) -> None:
    """Строит последовательность переходов между состояниями политики."""
    if not state_transitions:
        print("[viz] Нет переходов состояний.")
        return

    state_ids: set[int] = set()
    for transition in state_transitions:
        if transition.get("from_state_id") is not None:
            state_ids.add(transition["from_state_id"])
        if transition.get("to_state_id") is not None:
            state_ids.add(transition["to_state_id"])
    state_ids = sorted(state_ids)
    if not state_ids:
        print("[viz] Недостаточно состояний.")
        return

    count = len(state_ids)
    box_w, box_h = 0.16, 0.22
    gap = 0.10
    total_w = count * box_w + (count - 1) * gap
    start_x = (1 - total_w) / 2
    y_box = 0.42
    fig_w = max(10, count * 2.5)
    fig, ax = plt.subplots(figsize=(fig_w, 4.6))
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis("off")
    ax.set_title(
        "Переходы состояний политики",
        fontsize=13,
        fontweight="bold",
        pad=10,
        color="black",
    )

    pos_by_id: dict[int, float] = {}
    x = start_x
    for state_id in state_ids:
        pos_by_id[state_id] = x
        ax.add_patch(
            mpatches.FancyBboxPatch(
                (x, y_box),
                box_w,
                box_h,
                boxstyle="round,pad=0.02,rounding_size=0.04",
                linewidth=1.5,
                edgecolor="black",
                facecolor="white",
            )
        )
        ax.text(
            x + box_w / 2,
            y_box + box_h / 2,
            f"S{state_id}",
            ha="center",
            va="center",
            fontsize=12,
            fontweight="bold",
            color="black",
        )
        x += box_w + gap

    for transition in state_transitions:
        from_id = transition.get("from_state_id")
        to_id = transition.get("to_state_id")
        if from_id not in pos_by_id or to_id not in pos_by_id:
            continue
        x1 = pos_by_id[from_id] + box_w
        x2 = pos_by_id[to_id]
        if x2 < x1:
            continue
        y_mid = y_box + box_h / 2
        ax.annotate(
            "",
            xy=(x2, y_mid),
            xytext=(x1, y_mid),
            arrowprops=dict(arrowstyle="-|>", lw=1.6, color="black"),
        )

        subject = transition.get("subject") or ""
        command = transition.get("command") or ""
        if subject or command:
            label = f"{subject}\n{command}" if subject else command
        else:
            reason = transition.get("reason", "") or "change"
            details = transition.get("details", "") or ""
            label = f"{reason}\n{details[:70]}" if details else reason
        ax.text(
            (x1 + x2) / 2,
            y_box + box_h + 0.06,
            label,
            ha="center",
            va="bottom",
            fontsize=7,
            color="black",
            bbox=dict(boxstyle="round,pad=0.18", fc="white", ec="gray", lw=0.8),
        )

    plt.tight_layout()
    plt.savefig(output_file, dpi=150, bbox_inches="tight", facecolor="white")
    plt.close()
    print(f"[viz] State machine: {output_file}")


def draw_all(
    snapshot,
    audit,
    verify=None,
    used_triples=None,
    state_transitions=None,
    output_dir=".",
) -> None:
    """Создаёт все актуальные визуализации для отчёта."""
    os.makedirs(output_dir, exist_ok=True)

    for name in (
        "rights_matrix.png",
        "policy_timeline.png",
        "usage_graph.png",
        "usage_history_graph.png",
        "state_machine.png",
    ):
        path = os.path.join(output_dir, name)
        if os.path.exists(path):
            try:
                os.remove(path)
            except OSError:
                pass

    draw_rights_matrix(
        snapshot,
        audit,
        used_triples,
        os.path.join(output_dir, "rights_matrix.png"),
    )

    if getattr(audit, "used_triples", None):
        draw_usage_graph(
            snapshot,
            audit,
            os.path.join(output_dir, "usage_graph.png"),
            title="Использование прав в текущем окне",
        )

    if getattr(audit, "historical_used_triples", None):
        draw_usage_graph(
            snapshot,
            audit,
            os.path.join(output_dir, "usage_history_graph.png"),
            used_triples=getattr(audit, "historical_used_triples", set()),
            title="Использование прав за всё время",
        )

    if state_transitions:
        draw_state_machine(
            state_transitions,
            os.path.join(output_dir, "state_machine.png"),
        )
