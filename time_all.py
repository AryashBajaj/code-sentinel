"""Time all 3 configurations for 3 projects"""
import time
import subprocess

projects = [
    ("../flask_test_project", "flask_test_project"),
    ("../fastapi_test_project", "fastapi_test_project"),
    ("../nextjs_test_project", "nextjs_test_project"),
]

configs = [
    (["--no-llm"], "no-dataflow"),
    (["--no-llm", "--dataflow", "--graph-out", "output/t.json"], "dataflow"),
    (["--no-llm", "--dataflow", "--graph-out", "output/t.json", "--visualise"], "visualise"),
]

for proj_path, proj_name in projects:
    print(f"\n=== {proj_name} ===")
    for extra_args, config_name in configs:
        cmd = ["venv/Scripts/code-sentinel.exe", "analyze", proj_path] + extra_args
        start = time.perf_counter()
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=".")
        elapsed = time.perf_counter() - start
        
        output = result.stdout + result.stderr
        findings = 0
        nodes = edges = 0
        for line in output.split('\n'):
            if "Analysis Complete:" in line and "issues found" in line:
                for p in line.split():
                    if p.isdigit():
                        findings = int(p)
                        break
            if "[DataFlow] nodes=" in line or "[JS-DataFlow] nodes=" in line:
                for p in line.split():
                    if "nodes=" in p:
                        nodes = int(p.split('=')[1])
                    if "edges=" in p:
                        edges = int(p.split('=')[1])
        
        print(f"  {config_name:15} Time: {elapsed*1000:6.1f}ms  Findings: {findings:3}  Graph: {nodes}nodes/{edges}edges")