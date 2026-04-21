"""Time the analysis with dataflow enabled"""
import time
import subprocess
import sys

projects = [
    ("../flask_test_project", "flask_test_project"),
    ("../fastapi_test_project", "fastapi_test_project"),
    ("../nextjs_test_project", "nextjs_test_project"),
]

results = []

for project, name in projects:
    print(f"\nTiming: {name}")
    
    start = time.perf_counter()
    result = subprocess.run(
        ["venv/Scripts/code-sentinel.exe", "analyze", project, "--no-llm", "--dataflow", f"--graph-out output/{name}_graph.json"],
        capture_output=True,
        text=True,
        cwd="."
    )
    elapsed = time.perf_counter() - start
    
    # Combine stdout and stderr  
    output = result.stdout + result.stderr
    
    # Find "Analysis Complete: XX issues found"
    findings = 0
    for line in output.split('\n'):
        if "Analysis Complete:" in line and "issues found" in line:
            parts = line.split(':')
            if len(parts) >= 2:
                num = parts[1].strip().split()[0]
                findings = int(num)
                break
    
    # Extract graph info
    nodes = edges = 0
    for line in output.split('\n'):
        if "[DataFlow] nodes=" in line:
            for p in line.split():
                if "nodes=" in p:
                    nodes = int(p.split('=')[1])
                if "edges=" in p:
                    edges = int(p.split('=')[1])
    
    # Count severity
    critical = output.count("[CRITICAL]")
    high = output.count("[HIGH]")
    medium = output.count("[MEDIUM]")
    low = output.count("[LOW]")
    
    print(f"  Time: {elapsed*1000:.1f}ms, Findings: {findings}, Graph: {nodes}nodes/{edges}edges, C={critical} H={high} M={medium} L={low}")
    
    results.append({
        'name': name,
        'time_ms': elapsed * 1000,
        'findings': findings,
        'nodes': nodes,
        'edges': edges,
        'critical': critical,
        'high': high,
        'medium': medium,
        'low': low,
    })

print(f"\n{'='*75}")
print(f"{'Project':<25} {'Time(ms)':<10} {'Findings':<10} {'Nodes':<8} {'Edges':<6} {'C':<3} {'H':<3} {'M':<3} {'L':<3}")
print('-'*75)
for r in results:
    print(f"{r['name']:<25} {r['time_ms']:<10.1f} {r['findings']:<10} {r['nodes']:<8} {r['edges']:<6} {r['critical']:<3} {r['high']:<3} {r['medium']:<3} {r['low']:<3}")