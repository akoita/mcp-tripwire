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

# Rolling alias, deliberately not a pinned id: pinned previews retire and then
# 404 at chat time (gemini-3-pro-preview did exactly that). The alias always
# resolves on the AI Studio (v1beta) endpoint; pin a specific id per-deployment
# via TRIPWIRE_AGENT_MODEL when reproducibility matters more than availability.
DEFAULT_AGENT_MODEL = "gemini-pro-latest"


def agent_model() -> str:
    """Model id for the ADK agents. `TRIPWIRE_AGENT_MODEL` overrides the default."""
    return os.environ.get("TRIPWIRE_AGENT_MODEL") or DEFAULT_AGENT_MODEL
