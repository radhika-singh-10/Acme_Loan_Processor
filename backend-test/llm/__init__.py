"""
LLM Client Module

Provides clients for LLM communication.
"""

from .openai_compatible import OpenAICompatibleClient
try:
    from .bedrock import BedrockClient
except ModuleNotFoundError:  # pragma: no cover - depends on local environment
    BedrockClient = None

__all__ = ["BedrockClient", "OpenAICompatibleClient"]
