import r2pipe


<<<<<<< HEAD
def extract_cfg(binary_path):
    # open the binary in radare2 and analyze it
    r2 = r2pipe.open(binary_path)
    r2.cmd("aaa")
    functions = r2.cmdj("aflj")

    # find the main function address
=======
def extract_cfg(binary_path: str):

    r2 = r2pipe.open(binary_path)
    r2.cmd("aaa")
    functions = r2.cmdj("aflj")
# runs aaa to analyse everything followed by listing all functions
>>>>>>> 09c3d52367c2e9d3defc12b8090c83963e82f317
    main_addr = None
    for f in functions:
        if f["name"] == "main":
            main_addr = f["offset"]
            break

    # if no main found, just use the first function
    if not main_addr:
        main_addr = functions[0]["offset"]

    # extract the control flow graph
    cfg = r2.cmdj(f"agfj @ {main_addr}")
    r2.quit()
<<<<<<< HEAD

    # build lists of nodes and edges from the cfg blocks
    nodes = []
    edges = []
=======
# make the cfg - control flow graph
    nodes, edges = [], []
>>>>>>> 09c3d52367c2e9d3defc12b8090c83963e82f317
    if cfg:
        for block in cfg[0].get("blocks", []):
            nodes.append(block["offset"])
            if "jump" in block:
                edges.append((block["offset"], block["jump"]))
            if "fail" in block:
                edges.append((block["offset"], block["fail"]))
# get all blocks from cfg, find all nodes(the simple blocks) and edges(the jumps and fails b/w blocks)
    return {"nodes": nodes, "edges": edges}

#providing additional data required for risk engine
def compute_static_metrics(cfg):
    # count nodes and edges
    node_count = len(cfg["nodes"])
    edge_count = len(cfg["edges"])

    # cyclomatic complexity = edges - nodes + 2
    complexity = edge_count - node_count + 2

    # average edges per node
    if node_count > 0:
        branch_factor = edge_count / node_count
    else:
        branch_factor = 0

    # count self-loops (a block that jumps to itself)
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
