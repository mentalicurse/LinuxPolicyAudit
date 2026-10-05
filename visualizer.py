#!/usr/bin/env python3
"""
visualizer.py — построение графиков и диаграмм для результатов аудита.
"""
from __future__ import annotations

import os
from collections import defaultdict

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np
from matplotlib.colors import ListedColormap, BoundaryNorm

from analyzer import AuditResult, VerifyResult, _expand_used_with_traversal


CLR_USED      = "#22c55e"
CLR_REDUNDANT = "#facc15"
CLR_VIOLATION = "#ef4444"
CLR_NONE      = "#d1d5db"
CLR_DIR       = "#3b82f6"
CLR_FILE      = "#f97316"


def draw_fs_tree(snapshot: dict, audit: AuditResult, output_file: str = "fs_tree") -> None:
    try:
        from graphviz import Digraph
    except ImportError:
        print("[viz] graphviz не установлен. Пропущено.")
        return

    objects  = snapshot.get("objects", {})
    subjects = snapshot.get("subjects", {})
    root_dir = snapshot.get("target_dir", "")

    dot = Digraph("FS_Tree", comment="Filesystem access tree")
    dot.attr(rankdir="LR", splines="spline", nodesep="0.28", ranksep="0.9")
    dot.attr("node", fontname="Segoe UI", fontsize="10")
    dot.attr("edge", arrowsize="0.7", color="#64748b", penwidth="1.0")

    with dot.subgraph(name="cluster_subjects") as sub:
        sub.attr(label="Субъекты", style="rounded,filled", fillcolor="#f8fafc",
                 color="#cbd5e1", fontcolor="#334155", fontsize="11")
        for name in sorted(subjects):
            uid = subjects[name].get("uid", "?")
            sub.node(f"s_{name}", label=f"{name}\nuid={uid}", shape="ellipse",
                     style="filled", fillcolor="#e0f2fe", color="#0ea5e9",
                     fontcolor="#0f172a")

    node_id_by_path: dict[str, str] = {}
    for i, path in enumerate(sorted(objects.keys())):
        node_id_by_path[path] = f"f_{i}"

    with dot.subgraph(name="cluster_fs") as sub:
        sub.attr(label="Файловая система", style="rounded,filled", fillcolor="#f8fafc",
                 color="#cbd5e1", fontcolor="#334155", fontsize="11")
        for path in sorted(objects.keys()):
            if not path.startswith(root_dir):
                continue
            obj = objects[path]
            name = os.path.basename(path) or path
            mode = obj.get("mode", "?")
            if obj.get("obj_type") == "directory":
                shape, fill, border = "folder", "#fef3c7", "#f59e0b"
                label = f"{name}\n{mode}"
            else:
                shape, fill, border = "box", "#e2e8f0", "#475569"
                label = f"{name}\n{mode}"
            sub.node(node_id_by_path[path], label=label, shape=shape, style="filled,rounded",
                     fillcolor=fill, color=border, fontcolor="#0f172a")

    for path in sorted(objects.keys()):
        if not path.startswith(root_dir):
            continue
        parent = os.path.dirname(path)
        if parent in objects and parent != path:
            dot.edge(node_id_by_path[parent], node_id_by_path[path], color="#94a3b8")

    edge_status: dict[tuple[str, str], str] = {}
    for r in getattr(audit, "redundant", []):
        edge_status[(r.subject, r.path)] = "redundant"
    for v in getattr(audit, "violations", []):
        edge_status[(v.get("subject"), v.get("path"))] = "violation"

    for (subject, path), status in edge_status.items():
        if not path or path not in node_id_by_path:
            continue
        if status == "redundant":
            dot.edge(f"s_{subject}", node_id_by_path[path], color="#d97706",
                     style="dashed", penwidth="1.4", label="redundant",
                     fontcolor="#92400e")
        else:
            dot.edge(f"s_{subject}", node_id_by_path[path], color="#dc2626",
                     style="bold", penwidth="1.8", label="violation",
                     fontcolor="#991b1b")

    try:
        dot.render(output_file, format="png", cleanup=True)
    except TypeError:
        dot.format = "png"
        dot.render(output_file, cleanup=True)
        print(f"[viz] Дерево ФС: {output_file}.png")


def _usage_triplets_for_display(audit, used_triples=None):
    if used_triples is not None:
        return set(used_triples)
    return set(getattr(audit, "used_triples", set()))


def draw_rights_matrix(snapshot, audit, used_triples,
                       output_file="rights_matrix.png",
                       max_subjects=None, max_objects=None) -> None:
    subjects = sorted(snapshot.get("subjects", {}).keys())
    objects  = sorted(snapshot.get("objects", {}).keys())
    all_rights = _expand_used_with_traversal(
    _usage_triplets_for_display(audit, used_triples),
    snapshot.get("objects", {}),
    snapshot.get("target_dir", ""),
)
    if max_subjects is not None: subjects = subjects[:max_subjects]
    if max_objects  is not None: objects  = objects[:max_objects]

    s_idx = {s: i for i, s in enumerate(subjects)}
    o_idx = {o: i for i, o in enumerate(objects)}

    # Код ячейки: 0 — нет права, 1 — использовано, 2 — избыточно, 3 — нарушение.
    matrix = np.zeros((len(subjects), len(objects)), dtype=int)

    used_raw = _usage_triplets_for_display(audit, used_triples)
    # Добавляем execute на родительских каталогах, чтобы числа в матрице
    # совпадали со сводкой аудита, учитывающей обязательный обход пути.
    used = _expand_used_with_traversal(
        used_raw,
        snapshot.get("objects", {}),
        snapshot.get("target_dir", ""),
    )    
    for (sub, path, act) in used:
        si, oi = s_idx.get(sub), o_idx.get(path)
        if si is not None and oi is not None:
            matrix[si, oi] = 1

    for r in getattr(audit, "redundant", []):
        si, oi = s_idx.get(r.subject), o_idx.get(r.path)
        if si is not None and oi is not None and matrix[si, oi] == 0:
            matrix[si, oi] = 2

    for v in getattr(audit, "violations", []):
        si, oi = s_idx.get(v.get("subject")), o_idx.get(v.get("path"))
        if si is not None and oi is not None:
            matrix[si, oi] = 3

    cmap   = ListedColormap(["#ffffff", "#111111", "#d0d0d0", "#888888"])
    norm   = BoundaryNorm([0, 1, 2, 3, 4], cmap.N)

    fig_w = max(12, len(objects) * 0.42)
    fig_h = max(5,  len(subjects) * 0.42)
    fig, ax = plt.subplots(figsize=(fig_w, fig_h))
    fig.patch.set_facecolor("white")

    ax.imshow(matrix, cmap=cmap, norm=norm, aspect="auto")

    ax.set_xticks(np.arange(-.5, len(objects), 1), minor=True)
    ax.set_yticks(np.arange(-.5, len(subjects), 1), minor=True)
    ax.grid(which="minor", color="#bbbbbb", linewidth=0.5)
    ax.tick_params(which="minor", length=0)

    ax.set_xticks(range(len(objects)))
    ax.set_xticklabels([os.path.basename(o) or o for o in objects],
                       rotation=50, ha="right", fontsize=8, color="black")
    ax.set_yticks(range(len(subjects)))
    ax.set_yticklabels(subjects, fontsize=9, color="black")

    ax.set_title("Матрица прав доступа (субъекты × объекты)",
                 fontsize=13, fontweight="bold", pad=16, color="black")
    ax.set_xlabel("Объекты ФС", fontsize=10)
    ax.set_ylabel("Субъекты", fontsize=10)

    legend = [
        mpatches.Patch(facecolor="#ffffff", edgecolor="black", label="Нет прав"),
        mpatches.Patch(facecolor="#111111", edgecolor="black", label="Использовано"),
        mpatches.Patch(facecolor="#d0d0d0", edgecolor="black", label="Избыточно"),
        mpatches.Patch(facecolor="#888888", edgecolor="black", label="Нарушение"),
    ]
    ax.legend(handles=legend, loc="upper left", bbox_to_anchor=(1.01, 1),
              borderaxespad=0, frameon=False, fontsize=9)

    for spine in ax.spines.values():
        spine.set_color("black")

    plt.tight_layout()
    plt.savefig(output_file, dpi=150, bbox_inches="tight",
                facecolor="white")
    plt.close()
    print(f"[viz] Матрица: {output_file}")


def draw_verify_diff(verify_result: VerifyResult, output_file: str = "verify_diff.png") -> None:
    issues = verify_result.issues
    if not issues:
        print("[viz] Verify: расхождений нет.")
        return

    kind_labels = {
        "missing_allow":    "Не хватает разрешения",
        "unexpected_allow": "Лишнее разрешение",
        "object_missing":   "Объект/субъект отсутствует",
    }
    kind_colors = {
        "missing_allow":    "#fca5a5",
        "unexpected_allow": "#fde68a",
        "object_missing":   "#e5e7eb",
    }
    rows = [
        [kind_labels.get(iss.kind, iss.kind), iss.subject,
         os.path.basename(iss.path), iss.action,
         iss.detail[:55] + ("…" if len(iss.detail) > 55 else "")]
        for iss in issues
    ]
    cols = ["Тип", "Субъект", "Объект", "Действие", "Детали"]
    row_colors = [[kind_colors.get(iss.kind, "#ffffff")] * 5 for iss in issues]

    fig_h = max(3, len(rows) * 0.45 + 1.5)
    fig, ax = plt.subplots(figsize=(16, fig_h))
    ax.axis("off")
    tbl = ax.table(cellText=rows, colLabels=cols, cellColours=row_colors,
                   loc="center", cellLoc="left")
    tbl.auto_set_font_size(False)
    tbl.set_fontsize(9)
    tbl.auto_set_column_width(col=list(range(len(cols))))

    ax.set_title(f"Верификация — {len(issues)} расхождений",
                 fontsize=13, fontweight="bold", pad=12)
    plt.tight_layout()
    plt.savefig(output_file, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"[viz] Verify diff: {output_file}")


def draw_usage_graph(snapshot, audit, output_file="usage_graph.png",
                     used_triples=None, title="Использование прав") -> None:
    used = _usage_triplets_for_display(audit, used_triples)
    if not used:
        print("[viz] Нет данных для usage graph.")
        return

    subjects = sorted({s for s, _, _ in used})
    objects  = sorted({p for _, p, _ in used})

    n_s, n_o = len(subjects), len(objects)
    row_h    = 0.7
    height   = max(n_s, n_o) * row_h + 1.8
    fig, ax  = plt.subplots(figsize=(13, height))
    fig.patch.set_facecolor("white")
    ax.set_xlim(0, 10)
    ax.set_ylim(0, max(n_s, n_o) * row_h + 1)
    ax.axis("off")

    ax.text(5, max(n_s, n_o) * row_h + 0.9, title,
            ha="center", va="center", fontsize=13, fontweight="bold",
            color="#111111")

    sub_y = {s: (n_s - i - 0.5) * row_h for i, s in enumerate(subjects)}
    obj_y = {o: (n_o - i - 0.5) * row_h for i, o in enumerate(objects)}

    for s, y in sub_y.items():
        ax.text(1.2, y, s, ha="right", va="center",
                fontsize=10, color="#111111")
        ax.plot([1.35, 1.35], [y - 0.22, y + 0.22],
                color="#111111", linewidth=1.2)

    for o, y in obj_y.items():
        name = os.path.basename(o) or o
        ax.text(8.8, y, name, ha="left", va="center",
                fontsize=9, color="#111111")
        ax.plot([8.65, 8.65], [y - 0.22, y + 0.22],
                color="#111111", linewidth=1.2)

    color_by_action = {
        "read":    "#2ca02c",
        "write":   "#1f77b4",
        "execute": "#111111",
    }
    default_color = "#888888"

    from matplotlib.path import Path
    from matplotlib.patches import PathPatch

    # Параллельные права одной пары субъект-объект разводятся веером,
    # чтобы линии не совпадали на графике.
    pair_counter: dict[tuple[str, str], int] = {}
    for sub, path, act in used:
        key = (sub, path)
        pair_counter[key] = pair_counter.get(key, 0) + 1

    pair_index: dict[tuple[str, str], int] = {}

    drawn_styles: set = set()

    x1, x2 = 1.45, 8.55
    base_bend = 0.35
    step_bend = 0.40

    for sub, path, act in sorted(used):
        if sub not in sub_y or path not in obj_y:
            continue
        y1, y2 = sub_y[sub], obj_y[path]
        color = color_by_action.get(act, default_color)

        label = act if act not in drawn_styles else None
        drawn_styles.add(act)

        key = (sub, path)
        idx = pair_index.get(key, 0)
        pair_index[key] = idx + 1
        total = pair_counter[key]

        if total == 1:
            bend = 0.0
        else:
            # Разводим кривые симметрично относительно центральной линии пары.
            offset = (idx - (total - 1) / 2) / max(1, (total - 1) / 2) if total > 1 else 0
            bend = offset * base_bend + (idx - (total - 1) / 2) * step_bend * 0.4

        # Контрольные точки кривой Безье задают изгиб линии по горизонтали.
        xm1 = (x1 + x2) / 2 - bend
        xm2 = (x1 + x2) / 2 + bend
        verts = [
            (x1, y1),
            (xm1, y1),
            (xm2, y2),
            (x2, y2),
        ]
        codes = [Path.MOVETO, Path.CURVE4, Path.CURVE4, Path.CURVE4]
        patch = PathPatch(Path(verts, codes),
                          facecolor="none",
                          edgecolor=color,
                          linewidth=1.8,
                          label=label,
                          alpha=0.9)
        ax.add_patch(patch)
        ax.annotate("",
                    xy=(x2, y2),
                    xytext=(x2 - 0.15, y2),
                    arrowprops=dict(arrowstyle="-|>",
                                    color=color,
                                    lw=1.8))

    from matplotlib.lines import Line2D
    handles = [
        Line2D([0], [0], color=color_by_action["read"],
               lw=2, label="read"),
        Line2D([0], [0], color=color_by_action["write"],
               lw=2, label="write"),
        Line2D([0], [0], color=color_by_action["execute"],
               lw=2, label="execute"),
    ]
    ax.legend(handles=handles, loc="upper center",
              bbox_to_anchor=(0.5, -0.02),
              ncol=3, frameon=False, fontsize=11)

    plt.tight_layout()
    plt.savefig(output_file, dpi=150, bbox_inches="tight", facecolor="white")
    plt.close()
    print(f"[viz] Usage graph: {output_file}")


def draw_state_machine(state_transitions: list[dict],
                       output_file="state_machine.png") -> None:
    if not state_transitions:
        print("[viz] Нет переходов состояний.")
        return

    # Собираем состояния, упомянутые в переходах, включая начальные и конечные.
    state_ids: set[int] = set()
    for tr in state_transitions:
        fid = tr.get("from_state_id")
        tid = tr.get("to_state_id")
        if fid is not None:
            state_ids.add(fid)
        if tid is not None:
            state_ids.add(tid)
    state_ids = sorted(state_ids)

    if not state_ids:
        print("[viz] Недостаточно состояний.")
        return

    n = len(state_ids)
    box_w, box_h = 0.16, 0.22
    gap = 0.10
    total_w = n * box_w + (n - 1) * gap
    start_x = (1 - total_w) / 2
    y_box = 0.42

    fig_w = max(10, n * 2.5)
    fig, ax = plt.subplots(figsize=(fig_w, 4.6))
    ax.set_xlim(0, 1); ax.set_ylim(0, 1); ax.axis("off")
    ax.set_title("Переходы состояний политики",
                 fontsize=13, fontweight="bold", pad=10, color="black")

    pos_by_id: dict[int, float] = {}
    x = start_x
    for sid in state_ids:
        pos_by_id[sid] = x
        ax.add_patch(mpatches.FancyBboxPatch(
            (x, y_box), box_w, box_h,
            boxstyle="round,pad=0.02,rounding_size=0.04",
            linewidth=1.5, edgecolor="black", facecolor="white"))
        ax.text(x + box_w / 2, y_box + box_h / 2, f"S{sid}",
                ha="center", va="center", fontsize=12,
                fontweight="bold", color="black")
        x += box_w + gap

    for tr in state_transitions:
        fid = tr.get("from_state_id")
        tid = tr.get("to_state_id")
        if fid not in pos_by_id or tid not in pos_by_id:
            continue
        x1 = pos_by_id[fid] + box_w
        x2 = pos_by_id[tid]
        if x2 < x1:
            continue
        y_mid = y_box + box_h / 2

        ax.annotate("", xy=(x2, y_mid), xytext=(x1, y_mid),
                    arrowprops=dict(arrowstyle="-|>", lw=1.6, color="black"))

        reason = tr.get("reason", "") or "change"
        details = tr.get("details", "") or ""
        label = reason
        if details:
            label = f"{reason}\n{details[:70]}"

        ax.text((x1 + x2) / 2, y_box + box_h + 0.06, label,
                ha="center", va="bottom", fontsize=7, color="black",
                bbox=dict(boxstyle="round,pad=0.18", fc="white",
                          ec="gray", lw=0.8))

    plt.tight_layout()
    plt.savefig(output_file, dpi=150, bbox_inches="tight", facecolor="white")
    plt.close()
    print(f"[viz] State machine: {output_file}")


def draw_policy_timeline(policy_changes: list[dict], output_file="policy_timeline.png") -> None:
    import datetime
    if not policy_changes:
        print("[viz] Нет данных для timeline.")
        return

    files_ordered = list(dict.fromkeys(c["path"] for c in policy_changes))
    f_idx = {f: i for i, f in enumerate(files_ordered)}

    STYLES = {
        "chmod":       {"color": "#7c3aed", "marker": "o", "label": "chmod"},
        "create_file": {"color": "#059669", "marker": "s", "label": "create_file"},
        "create_dir":  {"color": "#d97706", "marker": "^", "label": "create_dir"},
    }
    DEFAULT = {"color": "#6b7280", "marker": "D", "label": "other"}

    fig_h = max(5, len(files_ordered) * 0.4)
    fig, ax = plt.subplots(figsize=(14, fig_h))
    for yi in range(len(files_ordered)):
        ax.axhline(yi, color="#e5e7eb", linewidth=0.5, zorder=0)

    plotted: set = set()
    xs = [c["timestamp"] for c in policy_changes]

    for ch in policy_changes:
        xi, yi = ch["timestamp"], f_idx[ch["path"]]
        action = ch.get("action", "other")
        style = STYLES.get(action, DEFAULT)
        label = style["label"] if style["label"] not in plotted else None
        plotted.add(style["label"])
        ax.scatter(xi, yi, color=style["color"], marker=style["marker"],
                   s=90, zorder=3, label=label)
        mode = ch.get("new_mode", "")
        note = f"{ch.get('subject','')}\n{mode}" if mode else ch.get("subject", "")
        ax.annotate(note, (xi, yi), textcoords="offset points",
                    xytext=(4, 4), fontsize=6, color="#374151")

    ax.set_yticks(range(len(files_ordered)))
    ax.set_yticklabels([os.path.basename(f) or f for f in files_ordered], fontsize=8)

    if xs:
        ticks = sorted(set(xs))[:: max(1, len(set(xs)) // 8)]
        ax.set_xticks(ticks)
        ax.set_xticklabels(
            [datetime.datetime.fromtimestamp(t).strftime("%d.%m %H:%M") for t in ticks],
            rotation=30, ha="right", fontsize=7)

    ax.set_xlabel("Время")
    ax.set_title("Хронология изменений", fontsize=13, fontweight="bold", pad=12)
    ax.legend(loc="upper right", fontsize=9)

    plt.tight_layout()
    plt.savefig(output_file, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"[viz] Timeline: {output_file}")


def draw_all(snapshot, audit, verify, used_triples,
             state_transitions=None, output_dir=".") -> None:
    os.makedirs(output_dir, exist_ok=True)

    draw_rights_matrix(snapshot, audit, used_triples,
                       os.path.join(output_dir, "rights_matrix.png"))

    if getattr(audit, "used_triples", None):
        draw_usage_graph(snapshot, audit,
                         os.path.join(output_dir, "usage_graph.png"),
                         title="Использование прав в текущем окне")

    if getattr(audit, "historical_used_triples", None):
        draw_usage_graph(snapshot, audit,
                         os.path.join(output_dir, "usage_history_graph.png"),
                         used_triples=getattr(audit, "historical_used_triples", set()),
                         title="Использование прав за всё время")

    if state_transitions:
        draw_state_machine(state_transitions,
                           os.path.join(output_dir, "state_machine.png"))