"""
SpectreFlow Graph Visualizer
Receives radare2-style control-flow graph data (nodes + edges),
builds a NetworkX DiGraph, and renders it inside a tkinter GUI
using matplotlib.
"""

import tkinter as tk
from tkinter import ttk

import matplotlib
matplotlib.use("TkAgg")

import matplotlib.pyplot as plt
from matplotlib.lines import Line2D
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg, NavigationToolbar2Tk
import networkx as nx


def get_radare2_data() -> dict:
    """
    Dummy function simulating data from a radare2 analysis backend.
    Returns a dict with 'nodes' (list of IDs), 'edges' (list of tuples),
    'labels' (dict of ID->Name), and 'types' (dict of ID->type).
    """
    # Mapping of ID -> (Label, Type)
    # Types: 'entry', 'suspicious', 'normal'
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
    
    # Extract derived lists for the API
    nodes = list(nodes_info.keys())
    labels = {k: v[0] for k, v in nodes_info.items()}
    types = {k: v[1] for k, v in nodes_info.items()}

    edges = [
        (1, 2), (1, 3),          # Start -> Detect VM, Validate
        (2, 4), (2, 5),          # Detect VM -> Decode, Log
        (3, 5), (3, 6),          # Validate -> Log, Load
        (4, 7), (4, 12),         # Decode -> Receive, Run Malicious
        (5, 7), (5, 9),          # Log -> Receive, Backup
        (6, 9), (6, 10),         # Load -> Backup, Setup
        (7, 11), (7, 12),        # Receive -> Clean, Run
        (8, 5), (8, 12),         # Retry -> Log, Run
        (9, 13), (9, 10),        # Backup -> Find Server, Setup
        (10, 13), (10, 14),      # Setup -> Find, Connect
        (12, 11),                # Run -> Clean
        (13, 14), (13, 8),       # Find -> Connect, Retry
        (14, 11),                # Connect -> Clean
    ]

    return {
        "nodes": nodes,
        "edges": edges,
        "labels": labels,
        "types": types,
    }


def build_graph(data: dict) -> nx.DiGraph:
    """Build a NetworkX directed graph from a radare2 dictionary."""
    graph = nx.DiGraph()
    graph.add_nodes_from(data["nodes"])
    graph.add_edges_from(data["edges"])
    
    # Add attributes if present
    if "labels" in data:
        nx.set_node_attributes(graph, data["labels"], "label")
    
    if "types" in data:
        nx.set_node_attributes(graph, data["types"], "type")
        
    return graph


class GraphVisualizerApp:
    """Tkinter window that embeds a matplotlib-rendered NetworkX graph."""

    # Catppuccin-inspired colour palette
    BG        = "#1e1e2e"
    FG        = "#cdd6f4"
    NODE      = "#89b4fa"  # Normal (Blue)
    ENTRY     = "#f38ba8"  # Entry (Pink)
    SUSPICIOUS= "#fab387"  # Suspicious (Orange)
    EDGE      = "#a6adc8"
    NODE_FONT = "#1e1e2e"
    ACCENT    = "#a6e3a1"
    STATUS_BG = "#181825"
    LEGEND_BG = "#313244"
    LEGEND_BD = "#45475a"

    def __init__(self, root: tk.Tk, data: dict = None) -> None:
        self.root = root
        self.data = data
        self.root.title("SpectreFlow - Graph Visualizer")
        self.root.configure(bg=self.BG)
        self.root.state('zoomed')  # Launch in full screen (maximized)
        self.root.minsize(800, 600)

        self._build_ui()
        self._render_graph()

    def _build_ui(self) -> None:
        """Construct header, canvas frame, and status bar."""
        # Header bar
        header = tk.Frame(self.root, bg=self.BG)
        header.pack(fill=tk.X, padx=12, pady=(10, 0))

        tk.Label(
            header, text="SpectreFlow",
            font=("Segoe UI", 16, "bold"), fg=self.NODE, bg=self.BG,
        ).pack(side=tk.LEFT)

        # Styled reload button
        style = ttk.Style()
        style.theme_use("clam")
        style.configure(
            "Accent.TButton",
            background=self.ACCENT, foreground=self.BG,
            font=("Segoe UI", 10, "bold"), padding=6,
        )
        style.map("Accent.TButton", background=[("active", "#74c78b")])

        ttk.Button(
            header, text="Reload Graph",
            style="Accent.TButton", command=self._render_graph,
        ).pack(side=tk.RIGHT)

        ttk.Separator(self.root, orient=tk.HORIZONTAL).pack(fill=tk.X, padx=12, pady=6)

        # Canvas container for matplotlib
        self.canvas_frame = tk.Frame(self.root, bg=self.BG)
        self.canvas_frame.pack(fill=tk.BOTH, expand=True, padx=12, pady=(0, 6))

        # Status bar
        self.status_var = tk.StringVar(value="Ready")
        tk.Label(
            self.root, textvariable=self.status_var,
            font=("Segoe UI", 9), fg=self.FG, bg=self.STATUS_BG,
            anchor=tk.W, padx=10, pady=4,
        ).pack(fill=tk.X, side=tk.BOTTOM)

    def _layout_graph_hierarchical(self, graph: nx.DiGraph) -> dict:
        """
        Compute positions for a top-down hierarchical layout.
        Uses BFS levels from entry node(s) to determine vertical layers.
        """
        if not graph.nodes():
            return {}

        # 1. Identify Entry Nodes (in-degree 0) to start BFS
        entry_nodes = [n for n in graph.nodes() if graph.in_degree(n) == 0]
        if not entry_nodes:
             # Fallback: Pick node with smallest ID or just first node
             entry_nodes = [list(graph.nodes())[0]]

        # 2. Assign layers using BFS
        layers = {}
        queue = [(node, 0) for node in entry_nodes]
        visited = set(entry_nodes)
        
        # Initialize layers with entry nodes
        for node in entry_nodes:
            layers[node] = 0

        while queue:
            current, level = queue.pop(0)
            layers[current] = level
            
            # Sort neighbors for deterministic layout if possible
            neighbors = sorted(list(graph.successors(current)), key=lambda x: str(x))
            for neighbor in neighbors:
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append((neighbor, level + 1))
        
        # Assign remaining nodes to max_level + 1 (orphans/cycles)
        max_level = max(layers.values()) if layers else 0
        for node in graph.nodes():
            if node not in layers:
                layers[node] = max_level + 1

        # 3. Use multipartite_layout to place nodes in layers (horizontal by default)
        nx.set_node_attributes(graph, layers, "subset")
        # subset_key="subset" makes x-coordinate based on subset. 
        # aligns nodes vertically inside subsets.
        # This creates Left-to-Right flow.
        pos = nx.multipartite_layout(graph, subset_key="subset", align="vertical")

        # 4. Rotate to Top-Down: Swap (x, y) and invert y
        # Original: x increases with depth (left -> right). y spreads nodes.
        # Target: y decreases with depth (top -> down). x spreads nodes.
        final_pos = {}
        for node, (x, y) in pos.items():
            final_pos[node] = (y, -x) # Rotate 90 degrees clockwise-ish

        return final_pos

    def _render_graph(self) -> None:
        """Fetch data, build the graph, and draw it on the canvas."""
        for widget in self.canvas_frame.winfo_children():
            widget.destroy()

        # Use provided data if available, else load dummy data
        data = self.data if self.data else get_radare2_data()
        graph = build_graph(data)

        # Determine node colors
        node_colors = []
        for n in graph.nodes():
            n_type = graph.nodes[n].get("type", "normal")
            if n_type == "entry":
                node_colors.append(self.ENTRY)
            elif n_type == "suspicious":
                node_colors.append(self.SUSPICIOUS)
            else:
                node_colors.append(self.NODE)

        # Create figure
        fig, ax = plt.subplots(figsize=(9, 6))
        fig.patch.set_facecolor(self.BG)
        ax.set_facecolor(self.BG)
        ax.axis("off")
        ax.set_title(
            "Malware Execution Flow", fontsize=16,
            fontweight="bold", color=self.FG, pad=15,
        )

        # Use custom hierarchical layout
        try:
            pos = self._layout_graph_hierarchical(graph)
        except Exception as e:
            print(f"Layout error: {e}, falling back to spring")
            pos = nx.spring_layout(graph, seed=42, k=2.0)

        # Draw nodes (smaller size)
        nx.draw_networkx_nodes(
            graph, pos, ax=ax, node_size=600,
            node_color=node_colors, edgecolors=self.FG, linewidths=2,
        )
        
        # Draw labels (offset below nodes) - adjusted for new layout
        # In Top-Down layout, y is negative. Subtracting more moves label down.
        # But scale of multipartite might be different. usually in [-1, 1].
        # Let's adjust offset carefully.
        labels = {
            n: graph.nodes[n].get("label", f"0x{n:x}")
            for n in graph.nodes()
        }
        
        # Calculate offset position for labels
        # Standard offset
        label_pos = {k: (v[0], v[1] - 0.1) for k, v in pos.items()}
        
        nx.draw_networkx_labels(
            graph, label_pos, ax=ax,
            labels=labels,
            font_size=8, font_weight="bold", font_color=self.FG,
            bbox={"facecolor": self.BG, "edgecolor": 'none', "alpha": 0.7, "pad": 1}
        )
        
        # Draw edges with curves
        nx.draw_networkx_edges(
            graph, pos, ax=ax, edge_color=self.EDGE,
            width=1.5, arrows=True, arrowsize=15,
            arrowstyle="-|>", connectionstyle="arc3,rad=0.1",
        )

        # Legend
        legend_handles = [
            Line2D([0], [0], marker="o", color="w",
                   markerfacecolor=self.ENTRY, markersize=10, label="Entry Point"),
            Line2D([0], [0], marker="o", color="w",
                   markerfacecolor=self.SUSPICIOUS, markersize=10, label="Suspicious Step"),
            Line2D([0], [0], marker="o", color="w",
                   markerfacecolor=self.NODE, markersize=10, label="Normal Step"),
        ]
        ax.legend(
            handles=legend_handles, loc="lower right", fontsize=9,
            facecolor=self.LEGEND_BG, edgecolor=self.LEGEND_BD, labelcolor=self.FG,
        )
        fig.tight_layout()

        # Embed in tkinter
        canvas = FigureCanvasTkAgg(fig, master=self.canvas_frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

        toolbar = NavigationToolbar2Tk(canvas, self.canvas_frame)
        toolbar.update()
        toolbar.pack(fill=tk.X)
        
        # Count stats
        n_suspicious = len([n for n in graph.nodes() if graph.nodes[n].get("type") == "suspicious"])
        self.status_var.set(f"Showing {len(graph.nodes())} steps, {len(graph.edges())} connections, {n_suspicious} suspicious")
        plt.close(fig)


def launch(data: dict = None) -> None:
    """Create the Tk root and start the app."""
    root = tk.Tk()
    GraphVisualizerApp(root, data=data)
    root.mainloop()


if __name__ == "__main__":
    launch()
