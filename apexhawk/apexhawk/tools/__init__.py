"""Tool wrappers package.

Importing this package registers every wrapper into the shared REGISTRY.
"""

from __future__ import annotations

from .registry import REGISTRY, ToolRegistry
from .base import BaseTool

# Importing each module has the side effect of registering its tools.
from . import network  # noqa: F401,E402
from . import web  # noqa: F401,E402
from . import recon  # noqa: F401,E402
from . import auth  # noqa: F401,E402
from . import binary  # noqa: F401,E402
from . import cloud  # noqa: F401,E402

__all__ = ["REGISTRY", "ToolRegistry", "BaseTool"]
