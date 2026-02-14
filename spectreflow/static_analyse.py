import r2pipe
import json
import sys

def extract_cfg(binary_path):
    
    print(f"Opening binary: {binary_path}")
    
    r2 = r2pipe.open(binary_path)
    
    
    r2.cmd('aaa')
    
    functions = r2.cmdj('aflj')
    
    if not functions:
        print("No functions found. Exiting.")
        r2.quit()
        return None
    
    else:
        print(f"Found {len(functions)} functions.")
    
    
    main_addr = None

    for f in functions:
        if f.get("name") == "main":
            main_addr = f.get("offset") or f.get("addr")
            break

    if main_addr is None:
        print("Main function not found.")
        r2.quit()
        return None

    print(f"[+] Main address: {hex(main_addr)}")

    cfg_json = r2.cmdj(f"agfj @ {main_addr}")
    r2.quit()

    if not cfg_json:
        print("CFG extraction failed.")
        return None
    function_info = cfg_json[0]
    blocks = function_info.get("blocks", [])
    nodes = []
    edges = []

    for block in blocks:
        addr = block.get("addr") or block.get("offset")

        if addr is None:
            continue

        nodes.append(hex(addr))

        jump = block.get("jump")
        fail = block.get("fail")

        if jump is not None:
            edges.append((hex(addr), hex(jump)))

        if fail is not None:
            edges.append((hex(addr), hex(fail)))
    return {
        "nodes": nodes, 
        "edges": edges
        }

if __name__ == "__main__":
    
    if len(sys.argv) != 2:
        print("Usage: python test.py <binary_path>")
        sys.exit(1)
    
    binary_path = sys.argv[1]
    
    result = extract_cfg(binary_path)
    
    if result:
        print("\n---------cfg extracted data----------")
        print(result)

    
    else:
        print("Static Analysis failed")