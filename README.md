# CodeSentinel

AI-powered code security and optimization analyzer.

## Installation

```bash
pip install -e .
```

## Usage

```bash
# Analyze a project
code-sentinel analyze ./myproject

# Static analysis only (no LLM)
code-sentinel analyze ./myproject --no-llm

# Detect project type
code-sentinel detect ./myproject
```

## LLM Providers

Set your API key:
- Gemini: `GEMINI_API_KEY`
- OpenAI: `OPENAI_API_KEY`
- Anthropic: `ANTHROPIC_API_KEY`

Or pass via `--api-key` flag.
