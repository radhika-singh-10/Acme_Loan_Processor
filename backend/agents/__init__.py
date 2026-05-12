"""Explicit agent and MCP server catalog exports for PolicyProbe."""

# Safe stub: no unregistered LLMs are imported
AGENTS = {}
MCP_SERVERS = {}
def build_catalog():
    raise NotImplementedError("build_catalog not available in this safe configuration")
def handle_chat_request(*args, **kwargs):
    raise NotImplementedError("handle_chat_request not available in this safe configuration")
def process_file_attachment(*args, **kwargs):
    raise NotImplementedError("process_file_attachment not available in this safe configuration")

__all__ = ["build_safe_catalog", "handle_chat_request", "process_file_attachment"]
