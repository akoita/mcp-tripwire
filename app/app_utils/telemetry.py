"""Observability setup (course Day-5 pattern): OpenTelemetry → Cloud Trace + GenAI logging.

No-op locally; configured from env when deployed. Called at the top of `fast_api_app.py`.
A security tool must NEVER persist raw payloads, so message-content capture is forced to
NO_CONTENT unless explicitly disabled.
"""

from __future__ import annotations

import os


def setup_telemetry() -> None:
    capture = os.environ.get("OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT", "false")
    if capture.lower() != "false":
        os.environ["OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT"] = "NO_CONTENT"
    # STUB(P1): initialise the OTel SDK + Cloud Trace exporter (otel_to_cloud=True),
    # honouring LOGS_BUCKET_NAME / OTEL_RESOURCE_ATTRIBUTES when present.
