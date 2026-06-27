"""ADK application entry — composes the Scanner / Red-team / Attestor agents.

`agents-cli` discovers `root_agent` at module load time. Importing this module
without the `[agent]` extra installed will fail at the `google.adk` import in
the sub-agent factories — `tripwire.agents.adk_available()` lets callers (e.g.
`make demo-adk`) test for that condition without taking the exception.

App name MUST equal the agent directory name ("app") or evals fail with
"Session not found" errors — see the ADK code cheatsheet §App Name.
"""

from __future__ import annotations

from google.adk.agents import Agent
from google.adk.apps import App

from app.app_utils.telemetry import setup_telemetry
from tripwire.agents import (
    create_attestor_agent,
    create_redteam_agent,
    create_scanner_agent,
)

setup_telemetry()


COORDINATOR_INSTRUCTION = """
You are the MCP-Tripwire coordinator. The operator is a security engineer who
wants to vet, attest, or stress-test MCP tools.

Route the request to the correct specialist:
- Scanner — when the operator pastes a tool descriptor and wants findings,
  drift analysis, or an OWASP MCP categorisation.
- Attestor — when the operator wants a signed trust badge issued for a tool.
  The Attestor's tool requires explicit user confirmation; this is by design.
- Red-team — when the operator wants adversarial probes to test the gateway
  against (seeded from the canonical corpus).

Never invent verdicts. The specialists' tools return deterministic results;
your job is to pick the right specialist and present the result faithfully.
"""

COORDINATOR_DESCRIPTION = (
    "Routes operator requests to the Scanner / Attestor / Red-team specialists "
    "and presents their deterministic verdicts in natural language."
)


root_agent = Agent(
    name="root_agent",
    model="gemini-3-pro",
    description=COORDINATOR_DESCRIPTION,
    instruction=COORDINATOR_INSTRUCTION,
    sub_agents=[
        create_scanner_agent(),
        create_attestor_agent(),
        create_redteam_agent(),
    ],
)

# App.name MUST equal the agent directory name ("app") — see agents-cli docs.
app = App(name="app", root_agent=root_agent)
