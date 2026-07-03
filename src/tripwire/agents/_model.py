"""Single source of the Gemini model id used by every ADK agent.

The id must exist on the endpoint the operator's credential talks to
(AI Studio `v1beta` for `GOOGLE_API_KEY`, Vertex for
`GOOGLE_GENAI_USE_VERTEXAI=True`) — a bad id fails at chat time with
`404 NOT_FOUND: models/<id> is not found for API version v1beta`.
Override per-deployment with `TRIPWIRE_AGENT_MODEL`; when unset, the
default below is used.
"""

from __future__ import annotations

import os

# Available on the plain AI Studio (v1beta) endpoint — the lowest-friction
# credential route (GOOGLE_API_KEY) — as well as on Vertex.
DEFAULT_AGENT_MODEL = "gemini-3-pro-preview"


def agent_model() -> str:
    """Model id for the ADK agents. `TRIPWIRE_AGENT_MODEL` overrides the default."""
    return os.environ.get("TRIPWIRE_AGENT_MODEL") or DEFAULT_AGENT_MODEL
