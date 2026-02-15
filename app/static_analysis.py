import r2pipe


def extract_cfg(binary_path):
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

    nodes = []
    edges = []
    if cfg:
        for block in cfg[0].get("blocks", []):
            nodes.append(block["offset"])
            if "jump" in block:
                edges.append((block["offset"], block["jump"]))
            if "fail" in block:
                edges.append((block["offset"], block["fail"]))

    return {"nodes": nodes, "edges": edges}


def compute_static_metrics(cfg):
    node_count = len(cfg["nodes"])
    edge_count = len(cfg["edges"])

    complexity = edge_count - node_count + 2

    if node_count > 0:
        branch_factor = edge_count / node_count
    else:
        branch_factor = 0

    loop_count = 0
    for src, dst in cfg["edges"]:
        if src == dst:
            loop_count += 1

    return {
        "complexity": complexity,
        "branch_factor": branch_factor,
        "loop_count": loop_count,
        "suspicious_density": 0.0,
    }
