import r2pipe


def extract_cfg(binary_path: str):

    r2 = r2pipe.open(binary_path)
    r2.cmd("aaa")
    functions = r2.cmdj("aflj")
# runs aaa to analyse everything followed by listing all functions
    main_addr = None
    for f in functions:
        if f["name"] == "main":
            main_addr = f["offset"]
            break
    if not main_addr:
        main_addr = functions[0]["offset"]

    cfg = r2.cmdj(f"agfj @ {main_addr}")
    r2.quit()
# make the cfg - control flow graph
    nodes, edges = [], []
    if cfg:
        blocks = cfg[0].get("blocks", [])
        for block in blocks:
            nodes.append(block["offset"])
            if "jump" in block:
                edges.append((block["offset"], block["jump"]))
            if "fail" in block:
                edges.append((block["offset"], block["fail"]))
# get all blocks from cfg, find all nodes(the simple blocks) and edges(the jumps and fails b/w blocks)
    return {"nodes": nodes, "edges": edges}

#providing additional data required for risk engine
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
