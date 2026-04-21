"""Measure CPU and memory during analysis - track child process"""
import subprocess
import psutil
import os
import time
import threading

peak_mem = 0
peak_cpu = 0
monitoring = True

def monitor_process(proc):
    global peak_mem, peak_cpu, monitoring
    try:
        ps_proc = psutil.Process(proc.pid)
        while monitoring and proc.poll() is None:
            try:
                mem = ps_proc.memory_info().rss / 1024 / 1024
                cpu = ps_proc.cpu_percent(interval=0.1)
                global peak_mem, peak_cpu
                peak_mem = max(peak_mem, mem)
                peak_cpu = max(peak_cpu, cpu)
            except:
                break
    except:
        pass

def measure_project(project_path, name):
    global peak_mem, peak_cpu, monitoring
    
    # Run analysis as subprocess
    proc = subprocess.Popen(
        ["venv/Scripts/code-sentinel.exe", "analyze", project_path, "--no-llm", "--dataflow", "--graph-out", "o.json"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    
    # Monitor it
    monitoring = True
    peak_mem = 0
    peak_cpu = 0
    monitor_thread = threading.Thread(target=monitor_process, args=(proc,))
    monitor_thread.start()
    
    # Wait for completion
    stdout, stderr = proc.communicate()
    elapsed = time.perf_counter() - start if 'start' in locals() else 0
    
    monitoring = False
    monitor_thread.join(timeout=1)
    
    print(f"{name}:")
    print(f"  Peak Memory: {peak_mem:.1f} MB")
    print(f"  Peak CPU%: {peak_cpu:.1f}%")

start = time.perf_counter()
measure_project("../flask_test_project", "Flask")

start = time.perf_counter()
measure_project("../fastapi_test_project", "FastAPI")

start = time.perf_counter()
measure_project("../nextjs_test_project", "Next.js")