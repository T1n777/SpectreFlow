try:
    import r2pipe
    _HAS_R2PIPE = True
except ImportError:
    _HAS_R2PIPE = False


def extract_cfg(binary_path: str):
    if not _HAS_R2PIPE:
        print("[!] r2pipe not installed — skipping static analysis.")
        return {"nodes": [], "edges": []}

    r2 = r2pipe.open(binary_path)
    r2.cmd("aaa")
    functions = r2.cmdj("aflj")

    main_addr = None
    for f in functions:
        if f["name"] == "main":
            main_addr = f["offset"]
            break
    if not main_addr:
        main_addr = functions[0]["offset"]

    cfg = r2.cmdj(f"agfj @ {main_addr}")
    r2.quit()

    nodes, edges = [], []
    if cfg:
        blocks = cfg[0].get("blocks", [])
        for block in blocks:
            nodes.append(block["offset"])
            if "jump" in block:
                edges.append((block["offset"], block["jump"]))
            if "fail" in block:
                edges.append((block["offset"], block["fail"]))

    return {"nodes": nodes, "edges": edges}


def compute_static_metrics(cfg):
    nodes = cfg["nodes"]
    edges = cfg["edges"]
    node_count = len(nodes)
    edge_count = len(edges)

    complexity = edge_count - node_count + 2
    branch_factor = edge_count / node_count if node_count else 0
    loop_count = len([e for e in edges if e[0] == e[1]])

    return {
        "complexity": complexity,
        "branch_factor": branch_factor,
        "loop_count": loop_count,
        "suspicious_density": 0.0,
    }
