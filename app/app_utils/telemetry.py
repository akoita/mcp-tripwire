"""Observability setup (course Day-5 pattern): OpenTelemetry → Cloud Trace + GenAI logging.

Called at the top of `fast_api_app.py`. A security tool must NEVER persist raw payloads,
so message-content capture is forced off before any optional telemetry SDK can start.
"""

from __future__ import annotations

import os


def setup_telemetry() -> None:
    """Configure safe telemetry when optional OpenTelemetry packages are installed.

    The served gateway can run without any telemetry dependencies. When the operator
    includes OpenTelemetry packages in the deployment image, this function wires a
    tracer provider and exports to Cloud Trace if that exporter is available.
    """
    capture = os.environ.get("OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT", "false")
    if capture.lower() != "false":
        os.environ["OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT"] = "NO_CONTENT"

    try:
        from opentelemetry import trace  # type: ignore[import-not-found]  # noqa: PLC0415
        from opentelemetry.sdk.resources import (
            Resource,  # type: ignore[import-not-found]  # noqa: PLC0415
        )
        from opentelemetry.sdk.trace import (
            TracerProvider,  # type: ignore[import-not-found]  # noqa: PLC0415
        )
        from opentelemetry.sdk.trace.export import (  # type: ignore[import-not-found]  # noqa: PLC0415
            BatchSpanProcessor,
        )
    except ImportError:
        return

    try:
        from opentelemetry.exporter.cloud_trace import (  # type: ignore[import-not-found]  # noqa: PLC0415
            CloudTraceSpanExporter,
        )
    except ImportError:
        return

    provider = TracerProvider(
        resource=Resource.create(
            {
                "service.name": "mcp-tripwire",
                "service.version": os.environ.get("K_REVISION", "local"),
            }
        )
    )
    provider.add_span_processor(BatchSpanProcessor(CloudTraceSpanExporter()))
    trace.set_tracer_provider(provider)
