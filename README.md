# CodeSentinel

AI-powered code security and optimization analyzer with multi-language support, framework-specific analyzers, and interprocedural taint tracking.

## Features

### Multi-Language Support
- **Python**: Django, Flask, FastAPI
- **JavaScript/TypeScript**: Next.js, Express.js

### Security Analysis
- **Pattern-based detection**: SQL injection, XSS, command injection, hardcoded secrets
- **Framework-specific rules**: 30+ security rules tailored to each framework
- **Taint tracking**: Interprocedural data flow analysis to trace user input to dangerous sinks

### Analysis Types
| Type | Description |
|------|-------------|
| Static Analysis | AST-based pattern matching |
| Framework Analysis | Framework-specific security rules |
| Taint Tracking | Data flow from sources to sinks |

## Installation

### Prerequisites
- Python 3.11+
- pip

### Setup

```bash
# Clone the repository
cd code-sentinel

# Install in development mode
pip install -e .

# Verify installation
code-sentinel --version
```

### Dependencies

Core dependencies are installed automatically:
- `tree-sitter` (0.21.3) - AST parsing
- `tree-sitter-languages` (1.9.1) - Language support
- `click` - CLI framework
- `rich` - Terminal output formatting

## Quick Start

```bash
# Analyze a project (full analysis with LLM)
code-sentinel analyze ./myproject

# Static analysis only (no LLM)
code-sentinel analyze ./myproject --no-llm

# With taint tracking enabled
code-sentinel analyze ./myproject --dataflow

# With taint tracking and visualization
code-sentinel analyze ./myproject --dataflow --graph-out graph.json --visualise

# Export call graph
code-sentinel analyze ./myproject --dataflow --graph-out output.json
```

## Usage

### Analyze Command

```bash
code-sentinel analyze <path> [options]
```

| Option | Description |
|--------|-------------|
| `--llm {gemini\|openai\|anthropic}` | LLM provider (default: gemini) |
| `--api-key <key>` | API key for LLM provider |
| `--no-llm` | Skip LLM analysis (static only) |
| `--dataflow` | Enable taint tracking analysis |
| `--graph-out <path>` | Export call graph to file |
| `--graph-format {json\|dot}` | Graph export format |
| `--visualise` | Generate interactive HTML visualization (requires --dataflow and --graph-out) |

### Detect Command

```bash
code-sentinel detect <path>
```

Quick project type detection without full analysis.

### Environment Variables

Set your LLM API key as an environment variable:

```bash
# Gemini (default)
export GEMINI_API_KEY=your-key-here

# OpenAI
export OPENAI_API_KEY=your-key-here

# Anthropic
export ANTHROPIC_API_KEY=your-key-here
```

Or pass it directly:

```bash
code-sentinel analyze ./myproject --api-key your-key-here
```

## Framework-Specific Analysis

### Flask
```bash
code-sentinel analyze ./flask-app --no-llm
```
**Detects**: SQL injection, XSS via `render_template_string`, command injection, hardcoded secrets, eval/exec usage

### Django
```bash
code-sentinel analyze ./django-app --no-llm
```
**Detects**: Raw SQL queries, template injection via `mark_safe`, mass assignment, missing CSRF protection

### FastAPI
```bash
code-sentinel analyze ./fastapi-app --no-llm
```
**Detects**: CORSMiddleware misconfiguration, missing Pydantic models, NoSQL injection patterns

### Next.js
```bash
code-sentinel analyze ./nextjs-app --no-llm
```
**Detects**: SSRF vulnerabilities, XSS via `dangerouslySetInnerHTML`, `NEXT_PUBLIC_` secret exposure

### Express.js
```bash
code-sentinel analyze ./express-app --no-llm
```
**Detects**: SQL injection, CORS wildcard origins, unsafe cookies, hardcoded secrets

## Taint Tracking

Enable taint tracking with `--dataflow`:

```bash
code-sentinel analyze ./myproject --dataflow
```

This performs interprocedural analysis to trace how user input flows through your code:

```
Sources (user input)          Sinks (dangerous operations)
─────────────────             ──────────────────────────
req.query         ─────┐
req.body          ──┐  │
req.params        ──┐  │      eval()
searchParams      ──┐  ├─────► exec()
process.env       ──┐  │      innerHTML
                   │  │      pickle.loads
```

### Example Output

```
=== Analysis Complete: 8 issues found ===

[CRITICAL] routes/api.py:45 - Use of eval() is dangerous
  => Use ast.literal_eval()

[HIGH] routes/user.py:23 - SQL injection via string concatenation
  => Use parameterized queries

[HIGH] utils/auth.py:67 - Taint flow: user input reaches dangerous sink exec
  => Sanitize input or use safer alternative
```

## Call Graph Visualization

Generate interactive HTML visualizations of the call graph with D3.js:

```bash
code-sentinel analyze ./myproject --dataflow --graph-out graph.json --visualise
```

This generates an interactive HTML file (`graph.html`) that you can open in a browser.

### Features

- **Force-directed graph**: Nodes and edges arranged automatically using D3.js physics simulation
- **Topological sorting**: Entry points (routes, handlers, main functions) appear first
- **Hover details**: See file path, line number, callers, and callees
- **Filter**: Toggle visibility by node type
- **Search**: Filter nodes by name

## Rule Categories

### Security Rules

| ID Prefix | Framework | Examples |
|----------|-----------|----------|
| FLxxx | Flask | FL011: eval/exec, FL006: SQL injection |
| DJxxx | Django | DJ001: raw SQL, DJ002: XSS |
| FAxxx | FastAPI | FA001: CORS, FA002: NoSQL injection |
| NEXTxxx | Next.js | NEXT001: SSRF, NEXT003: XSS |
| EXPRxxx | Express | EXPR003: CORS, EXPR006: SQL injection |

### Taint Rules

| ID | Language | Description |
|----|----------|-------------|
| TAINT001 | Python | Taint flow to dangerous sink |
| JS-TAINT001 | JavaScript | Taint flow to dangerous sink |

### Severity Levels

| Level | Description |
|-------|-------------|
| CRITICAL | Immediate security risk (e.g., eval with user input) |
| HIGH | Significant vulnerability (e.g., SQL injection) |
| MEDIUM | Potential issue (e.g., weak crypto) |
| LOW | Code quality suggestion |

## Project Structure

```
code-sentinel/
├── src/
│   ├── cli.py              # CLI interface
│   ├── scanner/            # Project scanning
│   ├── analyzer/           # Static analysis
│   │   ├── framework/      # Framework-specific analyzers
│   │   └── tree_sitter/    # AST parsing
│   └── callgraph/          # Taint tracking
├── tests/                  # Test suite
└── docs/                   # Documentation
```
