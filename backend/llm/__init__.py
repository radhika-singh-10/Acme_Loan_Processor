"""
LLM Client Module

Provides clients for LLM communication.
"""


def __getattr__(name):
    raise ImportError(
        f"Cannot import '{name}': The requested LLM client is not in the organization's "
        "approved LLM registry. Please use only approved LLM clients as defined by "
        "organizational policy."
    )


__all__ = []