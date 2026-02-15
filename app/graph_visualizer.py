import os
import ctypes
import tkinter as tk
from tkinter import ttk

# matplotlib.use("TkAgg")  <-- Removed global side-effect

import matplotlib.pyplot as plt
from matplotlib.lines import Line2D
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg, NavigationToolbar2Tk
import networkx as nx

import config


def get_radare2_data():
    nodes_info = {
         1: ("Program Start",         "entry"),
         2: ("Detect Virtual Machine", "suspicious"),
         3: ("Validate Input",        "normal"),
         4: ("Decode Hidden Text",    "suspicious"),
         5: ("Log Error",             "normal"),
         6: ("Load Settings",         "normal"),
         7: ("Receive Instructions",  "normal"),
         8: ("Retry Connection",      "suspicious"),
         9: ("Use Backup Config",     "suspicious"),
        10: ("Setup Network",         "normal"),
        11: ("Clean Up & Exit",       "normal"),
        12: ("Run Malicious Code",    "suspicious"),
        13: ("Find Remote Server",    "suspicious"),
        14: ("Connect to Server",     "suspicious"),
    }

    nodes = list(nodes_info)
    edges = [
        (1, 2), (1, 3), (2, 4), (2, 5), (3, 5), (3, 6),
        (4, 7), (4, 12), (5, 7), (5, 9), (6, 9), (6, 10),
        (7, 11), (7, 12), (8, 5), (8, 12), (9, 13), (9, 10),
        (10, 13), (10, 14), (12, 11), (13, 14), (13, 8), (14, 11),
    ]
    labels = {}
    types = {}
    for k, v in nodes_info.items():
        labels[k] = v[0]
        types[k] = v[1]

    return {"nodes": nodes, "edges": edges, "labels": labels, "types": types}


def build_dynamic_graph_data(result):
    nodes = []
    edges = []
    labels = {}
    types = {}
    nid = 1

    def add_node(label, ntype, parent=None):
        nonlocal nid
        nodes.append(nid)
        labels[nid] = label
        types[nid] = ntype
        if parent is not None:
            edges.append((parent, nid))
        current = nid
        nid += 1
        return current

    target_name = result.get("target_location") or "Target"
    if len(target_name) > 30:
        target_name = "..." + target_name[-27:]
    root = add_node(target_name, "entry")

    if result.get("cpu_spike"):
        add_node("CPU Spike", "suspicious", root)

    net = result.get("network_activity", [])
    if net:
        hub = add_node("Network Activity", "suspicious", root)
        for endpoint in net:
            add_node(endpoint, "suspicious", hub)

    files = result.get("file_activity", [])
    if files:
        hub = add_node("File Activity", "suspicious", root)
        seen = set()
        for ev in files:
            fname = ev.get("file", "?")
            if fname not in seen:
                seen.add(fname)
                _, ext = os.path.splitext(fname)
                if ext.lower() in config.SUSPICIOUS_EXTENSIONS:
                    ntype = "suspicious"
                else:
                    ntype = "normal"
                add_node(f"{ev['action']}: {fname}", ntype, hub)

    flagged = result.get("flagged_functions", [])
    if flagged:
        hub = add_node("Flagged Functions", "suspicious", root)
        for fn in flagged:
            add_node(fn, "suspicious", hub)

    return {"nodes": nodes, "edges": edges, "labels": labels, "types": types}


def build_graph(data):
    graph = nx.DiGraph()
    graph.add_nodes_from(data["nodes"])
    graph.add_edges_from(data["edges"])
    if "labels" in data:
        nx.set_node_attributes(graph, data["labels"], "label")
    if "types" in data:
        nx.set_node_attributes(graph, data["types"], "type")
    return graph


class GraphVisualizerApp:

    BG = "#1e1e2e"
    FG = "#cdd6f4"
    NODE = "#89b4fa"
    ENTRY = "#f38ba8"
    SUSPICIOUS = "#fab387"
    EDGE = "#a6adc8"
    ACCENT = "#a6e3a1"
    STATUS_BG = "#181825"
    LEGEND_BG = "#313244"
    LEGEND_BD = "#45475a"

    THREAT_COLORS = {"HIGH": "#f38ba8", "MEDIUM": "#fab387", "LOW": "#a6e3a1"}

    def __init__(self, root, data=None, report_info=None):
        self.root = root
        self.data = data
        if report_info is not None:
            self.report_info = report_info
        else:
            self.report_info = {}

        self.root.title("SpectreFlow - Graph Visualizer")
        self.root.configure(bg=self.BG)
        self.root.state("zoomed")
        self.root.minsize(800, 600)

        self._build_ui()
        self._render_graph()

    def _build_ui(self):
        header = tk.Frame(self.root, bg=self.BG)
        header.pack(fill=tk.X, padx=12, pady=(10, 0))

        tk.Label(header, text="SpectreFlow",
                 font=("Segoe UI", 16, "bold"), fg=self.NODE,
                 bg=self.BG).pack(side=tk.LEFT)

        threat = self.report_info.get("threat_level")
        score = self.report_info.get("risk_score")
        if threat and score is not None:
            badge_color = self.THREAT_COLORS.get(threat, self.FG)
            tk.Label(header, text=f"  Risk: {score}  ─  {threat}  ",
                     font=("Segoe UI", 12, "bold"), fg=self.BG,
                     bg=badge_color).pack(side=tk.LEFT, padx=12)

        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Accent.TButton", background=self.ACCENT,
                        foreground=self.BG,
                        font=("Segoe UI", 10, "bold"), padding=6)
        style.map("Accent.TButton", background=[("active", "#74c78b")])

        ttk.Button(header, text="Reload Graph", style="Accent.TButton",
                   command=self._render_graph).pack(side=tk.RIGHT)

        ttk.Separator(self.root, orient=tk.HORIZONTAL).pack(
            fill=tk.X, padx=12, pady=6)

        self.canvas_frame = tk.Frame(self.root, bg=self.BG)
        self.canvas_frame.pack(fill=tk.BOTH, expand=True, padx=12, pady=(0, 6))

        self.status_var = tk.StringVar(value="Ready")
        tk.Label(self.root, textvariable=self.status_var,
                 font=("Segoe UI", 9), fg=self.FG, bg=self.STATUS_BG,
                 anchor=tk.W, padx=10, pady=4).pack(fill=tk.X, side=tk.BOTTOM)

    def _layout_hierarchical(self, graph):
        if not graph.nodes():
            return {}

        entry_nodes = []
        for n in graph.nodes():
            if graph.in_degree(n) == 0:
                entry_nodes.append(n)
        if not entry_nodes:
            entry_nodes = [list(graph.nodes())[0]]

        layers = {}
        bfs_queue = []
        visited = set()
        for node in entry_nodes:
            bfs_queue.append((node, 0))
            visited.add(node)
            layers[node] = 0

        while bfs_queue:
            current, level = bfs_queue.pop(0)
            layers[current] = level
            for neighbour in sorted(graph.successors(current), key=str):
                if neighbour not in visited:
                    visited.add(neighbour)
                    bfs_queue.append((neighbour, level + 1))

        max_level = max(layers.values()) if layers else 0
        for node in graph.nodes():
            if node not in layers:
                layers[node] = max_level + 1

        nx.set_node_attributes(graph, layers, "subset")
        pos = nx.multipartite_layout(graph, subset_key="subset", align="vertical")

        result = {}
        for node, (x, y) in pos.items():
            result[node] = (y, -x)
        return result

    def _render_graph(self):
        for widget in self.canvas_frame.winfo_children():
            widget.destroy()

        data = self.data or get_radare2_data()
        graph = build_graph(data)

        type_color = {"entry": self.ENTRY, "suspicious": self.SUSPICIOUS}
        node_colors = []
        for n in graph.nodes():
            ntype = graph.nodes[n].get("type", "normal")
            color = type_color.get(ntype, self.NODE)
            node_colors.append(color)

        fig, ax = plt.subplots(figsize=(14, 9))
        fig.patch.set_facecolor(self.BG)
        ax.set_facecolor(self.BG)
        ax.axis("off")

        threat = self.report_info.get("threat_level", "")
        title = "SpectreFlow — Analysis Graph"
        if threat:
            title += f"   [{threat} RISK]"
        ax.set_title(title, fontsize=16, fontweight="bold",
                     color=self.FG, pad=15)

        try:
            pos = self._layout_hierarchical(graph)
        except Exception:
            pos = nx.spring_layout(graph, seed=42, k=2.0)

        label_offset = 0.08
        if pos:
            ys = [p[1] for p in pos.values()]
            y_range = max(ys) - min(ys) if len(ys) > 1 else 1
            if y_range > 0:
                pad = y_range * 0.15
                label_offset = y_range * 0.06
            else:
                pad = 0.2
                label_offset = 0.08
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
                    for sp in (mid + offset, mid - offset):
                        if 0 < sp < len(raw) and raw[sp] in " :\\/_ -":
                            best = sp + 1
                            break
                    else:
                        continue
                    break
                labels[n] = raw[:best].rstrip() + "\n" + raw[best:].lstrip()
            else:
                labels[n] = raw

        label_pos = {}
        for k, v in pos.items():
            label_pos[k] = (v[0], v[1] - label_offset)

        nx.draw_networkx_labels(
            graph, label_pos, ax=ax, labels=labels,
            font_size=7, font_weight="bold", font_color=self.FG,
            bbox={"facecolor": self.BG, "edgecolor": "none",
                  "alpha": 0.8, "pad": 2},
            verticalalignment="top",
        )

        nx.draw_networkx_edges(
            graph, pos, ax=ax, edge_color=self.EDGE,
            width=1.5, arrows=True, arrowsize=15,
            arrowstyle="-|>", connectionstyle="arc3,rad=0.1",
        )

        legend_handles = [
            Line2D([0], [0], marker="o", color="w",
                   markerfacecolor=self.ENTRY, markersize=10,
                   label="Entry / Target"),
            Line2D([0], [0], marker="o", color="w",
                   markerfacecolor=self.SUSPICIOUS, markersize=10,
                   label="Suspicious"),
            Line2D([0], [0], marker="o", color="w",
                   markerfacecolor=self.NODE, markersize=10,
                   label="Normal"),
        ]
        ax.legend(handles=legend_handles, loc="lower right", fontsize=9,
                  facecolor=self.LEGEND_BG, edgecolor=self.LEGEND_BD,
                  labelcolor=self.FG)
        fig.tight_layout(pad=1.5)

        canvas = FigureCanvasTkAgg(fig, master=self.canvas_frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

        toolbar = NavigationToolbar2Tk(canvas, self.canvas_frame)
        toolbar.update()
        toolbar.pack(fill=tk.X)

        n_suspicious = 0
        for n in graph.nodes():
            if graph.nodes[n].get("type") == "suspicious":
                n_suspicious += 1

        status = (f"Showing {len(graph.nodes())} nodes, "
                  f"{len(graph.edges())} edges, "
                  f"{n_suspicious} suspicious")
        if self.report_info.get("risk_score") is not None:
            status += (f"  │  Risk Score: {self.report_info['risk_score']}"
                       f"  │  Threat Level: "
                       f"{self.report_info.get('threat_level', '?')}")
        self.status_var.set(status)
        plt.close(fig)



def launch(data=None, report_info=None, master=None):
    import matplotlib
    # Ensure backend is TkAgg before creating figures
    try:
        matplotlib.use("TkAgg")
    except:
        pass
    
    # Lazy import to avoid early backend binding if possible
    global plt, FigureCanvasTkAgg, NavigationToolbar2Tk, nx
    import matplotlib.pyplot as plt
    import networkx as nx
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg, NavigationToolbar2Tk

    if master:
        root = tk.Toplevel(master)
        # Toplevel doesn't support 'zoomed' state directly on all platforms/versions in same way,
        # but we can try setting geometry or state.
        try:
            root.state("zoomed")
        except:
            root.geometry("1000x700")
    else:
        root = tk.Tk()
        root.state("zoomed")
        root.minsize(800, 600)

    try:
        # Apply dark title bar if on Windows
        import ctypes
        hwnd = ctypes.windll.user32.GetParent(root.winfo_id())
        ctypes.windll.dwmapi.DwmSetWindowAttribute(
            hwnd, 20, ctypes.byref(ctypes.c_int(1)), ctypes.sizeof(ctypes.c_int),
        )
    except Exception:
        pass

    app = GraphVisualizerApp(root, data=data, report_info=report_info)
    
    # Only run mainloop if we own the root Tk instance
    if master is None:
        root.mainloop()


if __name__ == "__main__":
    launch()
