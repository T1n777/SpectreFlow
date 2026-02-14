import tkinter as tk
from tkinter import ttk

import matplotlib
matplotlib.use("TkAgg")

import matplotlib.pyplot as plt
from matplotlib.lines import Line2D
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg, NavigationToolbar2Tk
import networkx as nx


def get_radare2_data() -> dict:
    nodes_info = {
         1: ("Program Start", "entry"),
         2: ("Detect Virtual Machine", "suspicious"),
         3: ("Validate Input", "normal"),
         4: ("Decode Hidden Text", "suspicious"),
         5: ("Log Error", "normal"),
         6: ("Load Settings", "normal"),
         7: ("Receive Instructions", "normal"),
         8: ("Retry Connection", "suspicious"),
         9: ("Use Backup Config", "suspicious"),
        10: ("Setup Network", "normal"),
        11: ("Clean Up & Exit", "normal"),
        12: ("Run Malicious Code", "suspicious"),
        13: ("Find Remote Server", "suspicious"),
        14: ("Connect to Server", "suspicious"),
    }
    nodes = list(nodes_info.keys())
    labels = {k: v[0] for k, v in nodes_info.items()}
    types = {k: v[1] for k, v in nodes_info.items()}
    edges = [
        (1, 2), (1, 3), (2, 4), (2, 5), (3, 5), (3, 6),
        (4, 7), (4, 12), (5, 7), (5, 9), (6, 9), (6, 10),
        (7, 11), (7, 12), (8, 5), (8, 12), (9, 13), (9, 10),
        (10, 13), (10, 14), (12, 11), (13, 14), (13, 8), (14, 11),
    ]
    return {"nodes": nodes, "edges": edges, "labels": labels, "types": types}


def build_dynamic_graph_data(result: dict) -> dict:
    nodes, edges, labels, types = [], [], {}, {}
    nid = 1

    target_name = result.get("target_location") or "Target"
    if len(target_name) > 30:
        target_name = "..." + target_name[-27:]
    root = nid
    nodes.append(nid)
    labels[nid] = target_name
    types[nid] = "entry"
    nid += 1

    if result.get("cpu_spike"):
        nodes.append(nid)
        labels[nid] = "CPU Spike"
        types[nid] = "suspicious"
        edges.append((root, nid))
        nid += 1

    net = result.get("network_activity", [])
    if net:
        hub = nid
        nodes.append(nid)
        labels[nid] = "Network Activity"
        types[nid] = "suspicious"
        edges.append((root, nid))
        nid += 1
        for endpoint in net:
            nodes.append(nid)
            labels[nid] = endpoint
            types[nid] = "suspicious"
            edges.append((hub, nid))
            nid += 1

    files = result.get("file_activity", [])
    if files:
        hub = nid
        nodes.append(nid)
        labels[nid] = "File Activity"
        types[nid] = "normal"
        edges.append((root, nid))
        nid += 1
        seen = set()
        for ev in files:
            fname = ev.get("file", "?")
            if fname not in seen:
                seen.add(fname)
                nodes.append(nid)
                labels[nid] = f"{ev['action']}: {fname}"
                ext = fname.rsplit(".", 1)[-1].lower() if "." in fname else ""
                types[nid] = "suspicious" if ext in (
                    "exe", "dll", "bat", "cmd", "ps1", "vbs",
                    "scr", "pif", "msi", "jar", "hta",
                ) else "normal"
                edges.append((hub, nid))
                nid += 1

    flagged = result.get("flagged_functions", [])
    if flagged:
        hub = nid
        nodes.append(nid)
        labels[nid] = "Flagged Functions"
        types[nid] = "suspicious"
        edges.append((root, nid))
        nid += 1
        for fn in flagged:
            nodes.append(nid)
            labels[nid] = fn
            types[nid] = "suspicious"
            edges.append((hub, nid))
            nid += 1

    return {"nodes": nodes, "edges": edges, "labels": labels, "types": types}


def build_graph(data: dict) -> nx.DiGraph:
    graph = nx.DiGraph()
    graph.add_nodes_from(data["nodes"])
    graph.add_edges_from(data["edges"])
    if "labels" in data:
        nx.set_node_attributes(graph, data["labels"], "label")
    if "types" in data:
        nx.set_node_attributes(graph, data["types"], "type")
    return graph


class GraphVisualizerApp:
    BG        = "#1e1e2e"
    FG        = "#cdd6f4"
    NODE      = "#89b4fa"
    ENTRY     = "#f38ba8"
    SUSPICIOUS= "#fab387"
    EDGE      = "#a6adc8"
    ACCENT    = "#a6e3a1"
    STATUS_BG = "#181825"
    LEGEND_BG = "#313244"
    LEGEND_BD = "#45475a"

    _THREAT_COLORS = {"HIGH": "#f38ba8", "MEDIUM": "#fab387", "LOW": "#a6e3a1"}

    def __init__(self, root: tk.Tk, data: dict = None,
                 report_info: dict | None = None) -> None:
        self.root = root
        self.data = data
        self.report_info = report_info or {}
        self.root.title("SpectreFlow - Graph Visualizer")
        self.root.configure(bg=self.BG)
        self.root.state('zoomed')
        self.root.minsize(800, 600)
        self._build_ui()
        self._render_graph()

    def _build_ui(self) -> None:
        header = tk.Frame(self.root, bg=self.BG)
        header.pack(fill=tk.X, padx=12, pady=(10, 0))

        tk.Label(
            header, text="SpectreFlow",
            font=("Segoe UI", 16, "bold"), fg=self.NODE, bg=self.BG,
        ).pack(side=tk.LEFT)

        threat = self.report_info.get("threat_level")
        score = self.report_info.get("risk_score")
        if threat and score is not None:
            badge_color = self._THREAT_COLORS.get(threat, self.FG)
            tk.Label(
                header, text=f"  Risk: {score}  ─  {threat}  ",
                font=("Segoe UI", 12, "bold"), fg=self.BG, bg=badge_color,
            ).pack(side=tk.LEFT, padx=12)

        style = ttk.Style()
        style.theme_use("clam")
        style.configure(
            "Accent.TButton", background=self.ACCENT, foreground=self.BG,
            font=("Segoe UI", 10, "bold"), padding=6,
        )
        style.map("Accent.TButton", background=[("active", "#74c78b")])

        ttk.Button(
            header, text="Reload Graph",
            style="Accent.TButton", command=self._render_graph,
        ).pack(side=tk.RIGHT)

        ttk.Separator(self.root, orient=tk.HORIZONTAL).pack(fill=tk.X, padx=12, pady=6)

        self.canvas_frame = tk.Frame(self.root, bg=self.BG)
        self.canvas_frame.pack(fill=tk.BOTH, expand=True, padx=12, pady=(0, 6))

        self.status_var = tk.StringVar(value="Ready")
        tk.Label(
            self.root, textvariable=self.status_var,
            font=("Segoe UI", 9), fg=self.FG, bg=self.STATUS_BG,
            anchor=tk.W, padx=10, pady=4,
        ).pack(fill=tk.X, side=tk.BOTTOM)

    def _layout_hierarchical(self, graph: nx.DiGraph) -> dict:
        if not graph.nodes():
            return {}

        entry_nodes = [n for n in graph.nodes() if graph.in_degree(n) == 0]
        if not entry_nodes:
            entry_nodes = [list(graph.nodes())[0]]

        layers = {}
        queue = [(node, 0) for node in entry_nodes]
        visited = set(entry_nodes)
        for node in entry_nodes:
            layers[node] = 0

        while queue:
            current, level = queue.pop(0)
            layers[current] = level
            for neighbor in sorted(graph.successors(current), key=str):
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append((neighbor, level + 1))

        max_level = max(layers.values()) if layers else 0
        for node in graph.nodes():
            if node not in layers:
                layers[node] = max_level + 1

        nx.set_node_attributes(graph, layers, "subset")
        pos = nx.multipartite_layout(graph, subset_key="subset", align="vertical")
        return {node: (y, -x) for node, (x, y) in pos.items()}

    def _render_graph(self) -> None:
        for widget in self.canvas_frame.winfo_children():
            widget.destroy()

        data = self.data if self.data else get_radare2_data()
        graph = build_graph(data)

        node_colors = []
        for n in graph.nodes():
            n_type = graph.nodes[n].get("type", "normal")
            if n_type == "entry":
                node_colors.append(self.ENTRY)
            elif n_type == "suspicious":
                node_colors.append(self.SUSPICIOUS)
            else:
                node_colors.append(self.NODE)

        fig, ax = plt.subplots(figsize=(14, 9))
        fig.patch.set_facecolor(self.BG)
        ax.set_facecolor(self.BG)
        ax.axis("off")

        threat = self.report_info.get("threat_level", "")
        title = "SpectreFlow — Analysis Graph"
        if threat:
            title += f"   [{threat} RISK]"
        ax.set_title(title, fontsize=16, fontweight="bold", color=self.FG, pad=15)

        try:
            pos = self._layout_hierarchical(graph)
        except Exception:
            pos = nx.spring_layout(graph, seed=42, k=2.0)

        label_offset = 0.08
        if pos:
            ys = [p[1] for p in pos.values()]
            y_range = max(ys) - min(ys) if len(ys) > 1 else 1
            pad = y_range * 0.15 if y_range > 0 else 0.2
            label_offset = y_range * 0.06 if y_range > 0 else 0.08
            ax.set_xlim(min(p[0] for p in pos.values()) - pad,
                        max(p[0] for p in pos.values()) + pad)
            ax.set_ylim(min(ys) - pad * 3, max(ys) + pad)

        nx.draw_networkx_nodes(
            graph, pos, ax=ax, node_size=900,
            node_color=node_colors, edgecolors=self.FG, linewidths=2,
        )

        labels = {}
        for n in graph.nodes():
            raw = graph.nodes[n].get("label", f"0x{n:x}")
            if len(raw) > 20:
                mid = len(raw) // 2
                best = mid
                for offset in range(min(8, mid)):
                    for sep_pos in (mid + offset, mid - offset):
                        if 0 < sep_pos < len(raw) and raw[sep_pos] in (" ", ":", "\\", "/", "_", "-"):
                            best = sep_pos + 1
                            break
                    else:
                        continue
                    break
                labels[n] = raw[:best].rstrip() + "\n" + raw[best:].lstrip()
            else:
                labels[n] = raw

        label_pos = {k: (v[0], v[1] - label_offset) for k, v in pos.items()}

        nx.draw_networkx_labels(
            graph, label_pos, ax=ax, labels=labels,
            font_size=7, font_weight="bold", font_color=self.FG,
            bbox={"facecolor": self.BG, "edgecolor": "none", "alpha": 0.8, "pad": 2},
            verticalalignment="top",
        )

        nx.draw_networkx_edges(
            graph, pos, ax=ax, edge_color=self.EDGE,
            width=1.5, arrows=True, arrowsize=15,
            arrowstyle="-|>", connectionstyle="arc3,rad=0.1",
        )

        legend_handles = [
            Line2D([0], [0], marker="o", color="w",
                   markerfacecolor=self.ENTRY, markersize=10, label="Entry / Target"),
            Line2D([0], [0], marker="o", color="w",
                   markerfacecolor=self.SUSPICIOUS, markersize=10, label="Suspicious"),
            Line2D([0], [0], marker="o", color="w",
                   markerfacecolor=self.NODE, markersize=10, label="Normal"),
        ]
        ax.legend(
            handles=legend_handles, loc="lower right", fontsize=9,
            facecolor=self.LEGEND_BG, edgecolor=self.LEGEND_BD, labelcolor=self.FG,
        )
        fig.tight_layout(pad=1.5)

        canvas = FigureCanvasTkAgg(fig, master=self.canvas_frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

        toolbar = NavigationToolbar2Tk(canvas, self.canvas_frame)
        toolbar.update()
        toolbar.pack(fill=tk.X)

        n_suspicious = len([n for n in graph.nodes() if graph.nodes[n].get("type") == "suspicious"])
        status = f"Showing {len(graph.nodes())} nodes, {len(graph.edges())} edges, {n_suspicious} suspicious"
        if self.report_info.get("risk_score") is not None:
            status += (f"  │  Risk Score: {self.report_info['risk_score']}"
                       f"  │  Threat Level: {self.report_info.get('threat_level', '?')}")
        self.status_var.set(status)
        plt.close(fig)


def launch(data: dict = None, report_info: dict | None = None) -> None:
    root = tk.Tk()
    GraphVisualizerApp(root, data=data, report_info=report_info)
    root.mainloop()


if __name__ == "__main__":
    launch()
