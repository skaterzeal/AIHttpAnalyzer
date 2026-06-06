from __future__ import annotations

import yaml
from pydantic import BaseModel
from pathlib import Path


class AnalysisConfig(BaseModel):
    extract_endpoints: bool = True
    extract_stack_traces: bool = True
    extract_versions: bool = True
    extract_secrets: bool = True
    extract_errors: bool = True
    fingerprint_technology: bool = True


class AIConfig(BaseModel):
    enabled: bool = False
    provider: str = "ollama"
    model: str = "llama3.2"
    temperature: float = 0.2
    max_tokens: int = 2000
    batch_size: int = 10
    confidence_threshold: float = 0.6
    api_key: str | None = None



class OutputConfig(BaseModel):
    format: str = "json"
    min_severity: str = "low"
    include_evidence: bool = True
    max_evidence_length: int = 500


class ProxyConfig(BaseModel):
    port: int = 8082
    intercept_responses: bool = True
    filter_content_types: list[str] = [
        "application/json",
        "text/html",
        "text/plain",
        "application/xml",
    ]


class CacheConfig(BaseModel):
    enabled: bool = True
    ttl_hours: int = 48


class Config(BaseModel):
    analysis: AnalysisConfig = AnalysisConfig()
    ai: AIConfig = AIConfig()
    output: OutputConfig = OutputConfig()
    proxy: ProxyConfig = ProxyConfig()
    cache: CacheConfig = CacheConfig()

    @classmethod
    def from_yaml(cls, path: str | Path) -> Config:
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        return cls(**data)
