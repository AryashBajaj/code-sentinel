"""
Benchmark script to measure CodeSentinel performance on sample projects.
"""
import time
import sys
from pathlib import Path
import io
import contextlib

# Add src to path
BASE = Path(__file__).parent / 'src'
sys.path.insert(0, str(BASE))

from scanner.project_scanner import ProjectScanner
from scanner.framework_detector import FrameworkDetector
from analyzer.static_analyzer import StaticAnalyzer


def benchmark_project(project_path, name):
    """Run benchmark on a project."""
    # Suppress taint output
    devnull = io.StringIO()
    
    print(f"\n{'='*60}")
    print(f"Benchmarking: {name}")
    print(f"Path: {project_path}")
    print('='*60)
    
    # Scan project
    start = time.perf_counter()
    scanner = ProjectScanner(project_path)
    project_info = scanner.scan()
    scan_time = time.perf_counter() - start
    
    files = project_info.get('files', [])
    print(f"Files found: {len(files)}")
    print(f"Scan time: {scan_time*1000:.2f}ms")
    
    # Detect framework
    det = FrameworkDetector(project_path)
    framework = det.detect()
    print(f"Framework detected: {framework}")
    
    # Static analysis (includes taint tracking)
    start = time.perf_counter()
    static_analyzer = StaticAnalyzer(project_path, project_info)
    static_result = static_analyzer.analyze()
    static_time = time.perf_counter() - start
    static_findings = static_result.get('findings', [])
    
    print(f"Static analysis time: {static_time*1000:.2f}ms")
    print(f"Static findings: {len(static_findings)}")
    
    # Severity breakdown
    critical = sum(1 for f in static_findings if f.get('severity') == 'critical')
    high = sum(1 for f in static_findings if f.get('severity') == 'high')
    medium = sum(1 for f in static_findings if f.get('severity') == 'medium')
    low = sum(1 for f in static_findings if f.get('severity') == 'low')
    
    print(f"\nTotal findings: {len(static_findings)}")
    print(f"  - Critical: {critical}")
    print(f"  - High: {high}")
    print(f"  - Medium: {medium}")
    print(f"  - Low: {low}")
    
    total_time = scan_time + static_time
    print(f"\nTotal time: {total_time*1000:.2f}ms")
    print(f"Time per file: {(total_time/len(files))*1000:.2f}ms" if files else "N/A")
    
    # Show sample findings
    print(f"\n--- Sample Findings ---")
    unique_ids = {}
    for f in static_findings:
        fid = f.get('id', '?')
        if fid not in unique_ids:
            unique_ids[fid] = f
    for fid, f in list(unique_ids.items())[:8]:
        print(f"  [{f.get('severity', '?').upper()}] {fid}: {f.get('message', '?')[:50]}")
    
    return {
        'name': name,
        'files': len(files),
        'framework': framework,
        'scan_time_ms': scan_time * 1000,
        'static_time_ms': static_time * 1000,
        'total_time_ms': total_time * 1000,
        'findings': len(static_findings),
        'critical': critical,
        'high': high,
        'medium': medium,
        'low': low,
    }


if __name__ == '__main__':
    projects = [
        (Path(__file__).parent.parent / 'flask_test_project', 'flask_test_project'),
        (Path(__file__).parent.parent / 'fastapi_test_project', 'fastapi_test_project'),
        (Path(__file__).parent.parent / 'nextjs_test_project', 'nextjs_test_project'),
    ]
    
    results = []
    for project_path, name in projects:
        if project_path.exists():
            result = benchmark_project(project_path, name)
            results.append(result)
        else:
            print(f"Project not found: {project_path}")
    
    print(f"\n{'='*60}")
    print("SUMMARY")
    print('='*60)
    print(f"{'Project':<25} {'Files':<6} {'Framework':<10} {'Time(ms)':<10} {'Findings':<10} {'C':<3} {'H':<3} {'M':<3} {'L':<3}")
    print('-'*75)
    for r in results:
        print(f"{r['name']:<25} {r['files']:<6} {r['framework']:<10} {r['total_time_ms']:<10.2f} {r['findings']:<10} {r['critical']:<3} {r['high']:<3} {r['medium']:<3} {r['low']:<3}")