"""Deterministic, self-contained SVG rendering of the showcase graph.

The layout is computed here from the report: no graph-library layout, no
randomness, no JavaScript, no external resources. It is a small layered
(Sugiyama-style) drawing:

- entities are placed top to bottom in layers by their longest distance from
  the analysis source, so every relationship points downwards;
- a relationship spanning several layers gets an invisible waypoint in each
  intermediate layer, which takes part in placement, so edges run between
  boxes instead of through them;
- within a layer, items are placed under the average position of their
  predecessors and overlaps are resolved left to right;
- labels sit in the gap below the relationship's source, at the first
  position along the curve that does not collide with another label.

All coordinates are integers, so the same report always renders to the same
bytes. Every label is escaped.
"""

import uuid
from html import escape

from app.showcase.report import ShowcaseReport

_NODE_W = 208
_NODE_H = 46
_WAYPOINT_W = 14
_H_GAP = 30
_LAYER_GAP = 64
_MARGIN = 24
_TOP = 70
_LEGEND_H = 104
_LABEL_TS = (0.5, 0.35, 0.65, 0.22, 0.78)

_TYPE_LABEL = {
    "SERVICE_ACCOUNT": "service account",
    "NETWORK_SEGMENT": "network segment",
    "CLOUD_RESOURCE": "cloud resource",
}


def _layers(report: ShowcaseReport) -> dict[uuid.UUID, int]:
    """Longest-path layering from the analysis source; BFS depth if the graph has a cycle."""
    successors: dict[uuid.UUID, list[uuid.UUID]] = {e.id: [] for e in report.environment.entities}
    predecessors: dict[uuid.UUID, list[uuid.UUID]] = {e.id: [] for e in report.environment.entities}
    for r in report.environment.relationships:
        successors[r.source_entity_id].append(r.target_entity_id)
        predecessors[r.target_entity_id].append(r.source_entity_id)

    source = report.analysis.source_entity_id
    depth: dict[uuid.UUID, int] = {source: 0}
    frontier = [source]
    while frontier:
        reached = []
        for node in frontier:
            for target in sorted(successors[node], key=str):
                if target not in depth:
                    depth[target] = depth[node] + 1
                    reached.append(target)
        frontier = sorted(set(reached), key=str)

    longest: dict[uuid.UUID, int] = {}
    visiting: set[uuid.UUID] = set()

    def visit(node: uuid.UUID) -> int | None:
        if node in longest:
            return longest[node]
        if node in visiting:
            return None  # cycle
        visiting.add(node)
        best = 0
        for pred in sorted((p for p in predecessors[node] if p in depth), key=str):
            value = visit(pred)
            if value is None:
                return None
            best = max(best, value + 1)
        visiting.discard(node)
        longest[node] = 0 if node == source else best
        return longest[node]

    acyclic = all(visit(node) is not None for node in sorted(depth, key=str))
    layer = {node: (longest[node] if acyclic else depth[node]) for node in depth}
    unreachable = max(layer.values(), default=0) + 1
    for e in report.environment.entities:
        layer.setdefault(e.id, unreachable)
    return layer


def _bezier(p0, p1, p2, p3, t: float) -> tuple[int, int]:
    u = 1 - t
    x = u ** 3 * p0[0] + 3 * u * u * t * p1[0] + 3 * u * t * t * p2[0] + t ** 3 * p3[0]
    y = u ** 3 * p0[1] + 3 * u * u * t * p1[1] + 3 * u * t * t * p2[1] + t ** 3 * p3[1]
    return round(x), round(y)


def _short(text: str, limit: int = 28) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "…"


def render_svg(report: ShowcaseReport) -> str:
    entities = {e.id: e for e in report.environment.entities}
    relationships = sorted(report.environment.relationships, key=lambda r: str(r.id))
    layer = _layers(report)

    # Items are entities ("n", id) and waypoints ("w", relationship id, layer).
    item_layer: dict[tuple, int] = {("n", node): index for node, index in layer.items()}
    chains: dict[uuid.UUID, list[tuple]] = {}
    for r in relationships:
        start, end = layer[r.source_entity_id], layer[r.target_entity_id]
        waypoints = [("w", r.id, i) for i in range(start + 1, end)] if end > start + 1 else []
        for item in waypoints:
            item_layer[item] = item[2]
        chains[r.id] = [("n", r.source_entity_id), *waypoints, ("n", r.target_entity_id)]

    predecessors: dict[tuple, list[tuple]] = {}
    for chain in chains.values():
        for before, after in zip(chain, chain[1:]):
            predecessors.setdefault(after, []).append(before)

    def item_width(item: tuple) -> int:
        return _NODE_W if item[0] == "n" else _WAYPOINT_W

    def sort_name(item: tuple) -> str:
        return entities[item[1]].name if item[0] == "n" else f"~{item[1]}"

    rows: dict[int, list[tuple]] = {}
    for item, index in item_layer.items():
        rows.setdefault(index, []).append(item)
    inner = max(
        sum(item_width(i) for i in items) + (len(items) - 1) * _H_GAP for items in rows.values()
    )
    width = inner + 2 * _MARGIN
    centre: dict[tuple, int] = {}
    for index in sorted(rows):
        def desired(item: tuple) -> int:
            placed = [centre[p] for p in predecessors.get(item, []) if p in centre]
            return sum(placed) // len(placed) if placed else width // 2
        items = sorted(rows[index], key=lambda i: (desired(i), sort_name(i), str(i)))
        lefts: list[int] = []
        for item in items:
            left = desired(item) - item_width(item) // 2
            if lefts:
                previous = items[len(lefts) - 1]
                left = max(left, lefts[-1] + item_width(previous) + _H_GAP)
            lefts.append(left)
        # Keep the layer inside the canvas without reordering it.
        overflow = lefts[-1] + item_width(items[-1]) - (width - _MARGIN)
        if overflow > 0:
            lefts = [x - overflow for x in lefts]
        underflow = _MARGIN - lefts[0]
        if underflow > 0:
            lefts = [x + underflow for x in lefts]
        for item, left in zip(items, lefts):
            centre[item] = left + item_width(item) // 2

    def top(item: tuple) -> int:
        return _TOP + item_layer[item] * (_NODE_H + _LAYER_GAP)

    last_layer = max(item_layer.values())
    graph_bottom = _TOP + last_layer * (_NODE_H + _LAYER_GAP) + _NODE_H
    height = graph_bottom + 34 + _LEGEND_H

    featured = report.remediation.featured_relationship_id
    source = report.analysis.source_entity_id
    target = report.analysis.target_entity_id

    out = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}" font-family="Helvetica, Arial, sans-serif" '
        f'role="img" aria-labelledby="ag-title ag-desc">',
        '<title id="ag-title">AttackGraph showcase: synthetic environment graph</title>',
        f'<desc id="ag-desc">{len(entities)} entities and {len(relationships)} relationships; '
        f'{report.baseline.path_count} plausible paths from the analysis source to the critical asset '
        f'under the showcase policy.</desc>',
        '<defs>',
    ]
    for name, color in (("path", "#334155"), ("off", "#cbd5e1"), ("fix", "#dc2626")):
        out.append(
            f'<marker id="arrow-{name}" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" '
            f'markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="{color}"/></marker>'
        )
    out.append('</defs>')
    out.append(f'<rect x="0" y="0" width="{width}" height="{height}" fill="#ffffff"/>')
    out.append(
        f'<text x="{_MARGIN}" y="30" font-size="17" font-weight="700" fill="#0f172a">'
        f'AttackGraph showcase — {escape(report.environment.organisation)}</text>'
    )
    out.append(
        f'<text x="{_MARGIN}" y="50" font-size="12" fill="#475569">'
        f'{report.baseline.path_count} plausible paths from {escape(entities[source].name)} to '
        f'{escape(entities[target].name)} · bounded traversal {report.baseline.termination_reason}</text>'
    )

    # Parallel relationships between the same ordered pair are bent apart so
    # that each stays visible (ARCH-15), and share one combined label.
    siblings: dict[tuple[uuid.UUID, uuid.UUID], list] = {}
    for r in relationships:
        siblings.setdefault((r.source_entity_id, r.target_entity_id), []).append(r)

    placed_labels: list[tuple[int, int, int, int]] = []
    labels = []
    for r in sorted(relationships, key=lambda r: (r.id == featured, r.on_baseline_path, str(r.id))):
        pair = siblings[(r.source_entity_id, r.target_entity_id)]
        bend = ([p.id for p in pair].index(r.id) * 2 - (len(pair) - 1)) * 24
        chain = chains[r.id]
        points = []
        for index, item in enumerate(chain):
            x = centre[item]
            if index > 0:
                points.append((x, top(item)))
            if index < len(chain) - 1:
                points.append((x, top(item) + (_NODE_H if item[0] == "n" else _NODE_H)))
        # points alternate: bottom of item i, top of item i+1, ...
        segments = [(points[i], points[i + 1]) for i in range(0, len(points), 2)]
        d = [f"M{segments[0][0][0]},{segments[0][0][1]}"]
        curves = []
        for index, (p0, p3) in enumerate(segments):
            if index > 0:
                d.append(f"L{p0[0]},{p0[1]}")
            dy = (p3[1] - p0[1]) // 2
            p1, p2 = (p0[0] + bend, p0[1] + dy), (p3[0] + bend, p3[1] - dy)
            d.append(f"C{p1[0]},{p1[1]} {p2[0]},{p2[1]} {p3[0]},{p3[1]}")
            curves.append((p0, p1, p2, p3))

        if r.id == featured:
            stroke, stroke_w, dash, marker, fill, weight = "#dc2626", 3, ' stroke-dasharray="7 4"', "fix", "#b91c1c", "700"
        elif r.on_baseline_path:
            stroke, stroke_w, dash, marker, fill, weight = "#334155", 2, "", "path", "#334155", "400"
        else:
            stroke, stroke_w, dash, marker, fill, weight = "#cbd5e1", 1, "", "off", "#94a3b8", "400"
        tooltip = (f"{entities[r.source_entity_id].name} {r.relationship_type} {entities[r.target_entity_id].name} "
                   f"({r.truth_tier.lower()}, {r.resolved_confidence.lower()} confidence)")
        out.append(
            f'<path d="{" ".join(d)}" fill="none" stroke="{stroke}" stroke-width="{stroke_w}"{dash} '
            f'marker-end="url(#arrow-{marker})"><title>{escape(tooltip)}</title></path>'
        )

        if r.id != pair[0].id:
            continue  # parallel siblings share the first sibling's label
        text = " · ".join(p.relationship_type + ("*" if p.truth_tier == "INFERRED" else "") for p in pair)
        half_w, half_h = len(text) * 3 + 4, 7
        choice = None
        for t in _LABEL_TS:
            lx, ly = _bezier(*curves[0], t)
            box = (lx - half_w, ly - half_h, lx + half_w, ly + half_h)
            if not any(box[0] < o[2] and o[0] < box[2] and box[1] < o[3] and o[1] < box[3] for o in placed_labels):
                choice = (lx, ly, box)
                break
        if choice is None:
            lx, ly = _bezier(*curves[0], 0.5)
            choice = (lx, ly, (lx - half_w, ly - half_h, lx + half_w, ly + half_h))
        placed_labels.append(choice[2])
        labels.append(
            f'<text x="{choice[0]}" y="{choice[1] + 3}" font-size="9" text-anchor="middle" fill="{fill}" '
            f'font-weight="{weight}" paint-order="stroke" stroke="#ffffff" stroke-width="3">{escape(text)}</text>'
        )

    for node in sorted(entities, key=lambda n: (layer[n], centre[("n", n)])):
        e = entities[node]
        x, y = centre[("n", node)] - _NODE_W // 2, top(("n", node))
        if node == source:
            fill, stroke, stroke_w = "#dbeafe", "#1d4ed8", 2
        elif e.criticality == "CRITICAL":
            fill, stroke, stroke_w = "#fee2e2", "#b91c1c", 3
        elif e.exposure == "EXTERNAL":
            fill, stroke, stroke_w = "#eff6ff", "#3b82f6", 2
        else:
            fill, stroke, stroke_w = "#f8fafc", "#64748b", 1
        kind = _TYPE_LABEL.get(e.entity_type, e.entity_type.lower())
        details = ", ".join(v.lower() for v in (e.criticality, e.exposure) if v)
        tooltip = escape(e.name) + " — " + escape(kind) + (": " + escape(details) if details else "")
        subtitle = escape(kind) + (" · " + escape(details) if details else "")
        out.append(
            f'<g><title>{tooltip}</title><rect x="{x}" y="{y}" width="{_NODE_W}" height="{_NODE_H}" '
            f'rx="7" fill="{fill}" stroke="{stroke}" stroke-width="{stroke_w}"/>'
            f'<text x="{x + 10}" y="{y + 19}" font-size="12" font-weight="600" fill="#0f172a">'
            f'{escape(_short(e.name))}</text>'
            f'<text x="{x + 10}" y="{y + 36}" font-size="10" fill="#475569">{subtitle}</text></g>'
        )
    out.extend(labels)

    ly = graph_bottom + 34
    featured_rel = next(r for r in relationships if r.id == featured)
    out.append(f'<line x1="{_MARGIN}" y1="{ly - 14}" x2="{width - _MARGIN}" y2="{ly - 14}" stroke="#e2e8f0"/>')
    legend = [
        ('<rect x="{x}" y="{y}" width="22" height="14" rx="3" fill="#dbeafe" stroke="#1d4ed8" stroke-width="2"/>',
         "analysis source (entry)"),
        ('<rect x="{x}" y="{y}" width="22" height="14" rx="3" fill="#fee2e2" stroke="#b91c1c" stroke-width="3"/>',
         "critical asset (analysis target)"),
        ('<rect x="{x}" y="{y}" width="22" height="14" rx="3" fill="#eff6ff" stroke="#3b82f6" stroke-width="2"/>',
         "externally exposed entity"),
        ('<line x1="{x}" y1="{cy}" x2="{x2}" y2="{cy}" stroke="#334155" stroke-width="2"/>',
         "relationship on a plausible path"),
        ('<line x1="{x}" y1="{cy}" x2="{x2}" y2="{cy}" stroke="#cbd5e1" stroke-width="1"/>',
         "relationship not on any path"),
        ('<line x1="{x}" y1="{cy}" x2="{x2}" y2="{cy}" stroke="#dc2626" stroke-width="3" stroke-dasharray="7 4"/>',
         "top-ranked remediation candidate"),
    ]
    column_w = (width - 2 * _MARGIN) // 2
    for index, (shape, text) in enumerate(legend):
        x = _MARGIN + (index % 2) * column_w
        y = ly + (index // 2) * 22
        out.append(shape.format(x=x, y=y, cy=y + 7, x2=x + 22))
        out.append(f'<text x="{x + 30}" y="{y + 11}" font-size="11" fill="#334155">{escape(text)}</text>')
    out.append(
        f'<text x="{_MARGIN}" y="{ly + 84}" font-size="11" fill="#475569">'
        f'* inferred relationship · remediation candidate: '
        f'{escape(entities[featured_rel.source_entity_id].name)} {escape(featured_rel.relationship_type)} '
        f'{escape(entities[featured_rel.target_entity_id].name)}</text>'
    )
    out.append('</svg>')
    return "\n".join(out) + "\n"
