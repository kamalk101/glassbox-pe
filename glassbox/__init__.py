"""GlassBox PE — offline, evidence-first triage for Windows PE executables."""

from .schema import SCHEMA_VERSION, TOOL_VERSION

__version__ = TOOL_VERSION

__all__ = ["SCHEMA_VERSION", "TOOL_VERSION", "__version__"]
