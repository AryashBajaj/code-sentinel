#!/usr/bin/env python3
"""CLI for building and exporting a Python call graph (production-grade)."""
import argparse
import json
from pathlib import Path

from . import __dict__ as _cg  # dummy to hint package import
from .callgraph import CallGraphBuilder
from .export import graph_to_json, graph_to_dot

def main():
    parser = argparse.ArgumentParser(description="CallGraph CLI: end-to-end Python call graph builder")
    sub = parser.add_subparsers(dest="command", required=True)

    analyze = sub.add_parser("analyze", help="Analyze a root path and build a call graph")
    analyze.add_argument("path", help="Root path to analyze")
    analyze.add_argument("--out", help="Output file path (optional)")
    analyze.add_argument("--format", choices=["json", "dot"], default="json", help="Export format (default json)")

    args = parser.parse_args()
    if args.command == "analyze":
        root = args.path
        cg = CallGraphBuilder(root)
        graph = cg.build_graph()
        if args.out:
            Path(args.out).parent.mkdir(parents=True, exist_ok=True)
            with open(args.out, "w", encoding="utf-8") as f:
                if args.format == "json":
                    f.write(graph_to_json(graph))
                else:
                    f.write(graph.to_dot())
        else:
            if args.format == "json":
                print(graph_to_json(graph))
            else:
                print(graph.to_dot())

if __name__ == "__main__":
    main()
