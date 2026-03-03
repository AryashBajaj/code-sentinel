"""Configuration settings for CodeSentinel."""
import os
from pathlib import Path
from typing import Optional


class Settings:
    """Application settings loaded from environment and config."""
    
    def __init__(self):
        self.openai_api_key = os.getenv("OPENAI_API_KEY")
        self.anthropic_api_key = os.getenv("ANTHROPIC_API_KEY")
        self.default_llm = os.getenv("DEFAULT_LLM", "anthropic")
        self.max_file_size = int(os.getenv("MAX_FILE_SIZE", "100000"))
        self.max_files_to_analyze = int(os.getenv("MAX_FILES_TO_ANALYZE", "20"))
        self.enable_semgrep = os.getenv("ENABLE_SEMGREP", "true").lower() == "true"
    
    @property
    def has_openai_key(self) -> bool:
        return bool(self.openai_api_key)
    
    @property
    def has_anthropic_key(self) -> bool:
        return bool(self.anthropic_api_key)
    
    @property
    def has_any_llm_key(self) -> bool:
        return self.has_openai_key or self.has_anthropic_key
